// End-to-end ACME (TLS-ALPN-01) test against Pebble, Let's Encrypt's test ACME
// server. It exercises the full path: a site's `zeroserve.init.acme_config`
// section declares a domain, zeroserve registers an account, places an order,
// answers the TLS-ALPN-01 challenge on its TLS listener, downloads the issued
// certificate, persists it under --acme-dir, and serves it for the domain.
//
// Requires `pebble` and `pebble-challtestsrv` (and `openssl`). In CI they are
// installed via `go install` and exposed through PEBBLE_BIN /
// PEBBLE_CHALLTESTSRV_BIN; locally the test is skipped if they are absent.

import { assertStringIncludes } from "@std/assert";
import { join } from "@std/path";
import {
  delay,
  getFreePort,
  getZeroservePath,
  packSite,
  repoRoot,
} from "./test_utils.ts";

const decoder = new TextDecoder();

async function resolveBin(
  envVar: string,
  name: string,
): Promise<string | null> {
  const fromEnv = Deno.env.get(envVar);
  if (fromEnv) {
    try {
      await Deno.stat(fromEnv);
      return fromEnv;
    } catch { /* fall through to PATH lookup */ }
  }
  try {
    const out = await new Deno.Command("bash", {
      args: ["-c", `command -v ${name}`],
      stdout: "piped",
      stderr: "null",
    }).output();
    if (out.success) {
      const path = decoder.decode(out.stdout).trim();
      if (path) return path;
    }
  } catch { /* ignore */ }
  return null;
}

async function hasOpenssl(): Promise<boolean> {
  try {
    const out = await new Deno.Command("openssl", {
      args: ["version"],
      stdout: "null",
      stderr: "null",
    }).output();
    return out.success;
  } catch {
    return false;
  }
}

async function openssl(args: string[]): Promise<void> {
  const out = await new Deno.Command("openssl", {
    args,
    stdout: "null",
    stderr: "piped",
  }).output();
  if (!out.success) {
    throw new Error(
      `openssl ${args.join(" ")} failed: ${decoder.decode(out.stderr)}`,
    );
  }
}

const pebbleBin = await resolveBin("PEBBLE_BIN", "pebble");
const challtestsrvBin = await resolveBin(
  "PEBBLE_CHALLTESTSRV_BIN",
  "pebble-challtestsrv",
);
const available = pebbleBin !== null && challtestsrvBin !== null &&
  await hasOpenssl();

Deno.test({
  name: "e2e: ACME TLS-ALPN-01 issuance against Pebble",
  ignore: !available,
}, async () => {
  const domain = "zs.test";
  const work = await Deno.makeTempDir({ prefix: "zs-acme-" });
  const children: Deno.ChildProcess[] = [];
  const kill = (c: Deno.ChildProcess) => {
    try {
      c.kill("SIGKILL");
    } catch { /* already gone */ }
  };

  // Drain a child's stderr into a growing buffer for diagnostics on failure.
  const logs = new Map<Deno.ChildProcess, () => string>();
  const drain = (c: Deno.ChildProcess, label: string) => {
    let buf = "";
    (async () => {
      for await (const chunk of c.stderr) buf += decoder.decode(chunk);
    })().catch(() => {});
    logs.set(c, () => `--- ${label} ---\n${buf}`);
  };

  try {
    const zsTlsPort = await getFreePort();
    const dirPort = await getFreePort();
    const mgmtPort = await getFreePort();
    const dnsPort = await getFreePort();
    const pebbleHttpPort = await getFreePort();

    // 1. A throwaway CA and a leaf for Pebble's ACME directory endpoint, whose
    //    SAN covers 127.0.0.1 (zeroserve verifies the directory by IP).
    const caCrt = join(work, "ca.crt");
    const caKey = join(work, "ca.key");
    const dirCrt = join(work, "dir.crt");
    const dirKey = join(work, "dir.key");
    const dirCsr = join(work, "dir.csr");
    await openssl([
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      caKey,
      "-out",
      caCrt,
      "-days",
      "2",
      "-subj",
      "/CN=Test ACME Directory CA",
      "-addext",
      "basicConstraints=critical,CA:TRUE",
    ]);
    await openssl([
      "req",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      dirKey,
      "-out",
      dirCsr,
      "-subj",
      "/CN=localhost",
      "-addext",
      "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]);
    await openssl([
      "x509",
      "-req",
      "-in",
      dirCsr,
      "-CA",
      caCrt,
      "-CAkey",
      caKey,
      "-CAcreateserial",
      "-copy_extensions",
      "copyall",
      "-out",
      dirCrt,
      "-days",
      "2",
    ]);

    // 2. Pebble config: serve the directory with our leaf; validate TLS-ALPN-01
    //    against zeroserve's TLS port.
    const pebbleConfig = join(work, "pebble.json");
    await Deno.writeTextFile(
      pebbleConfig,
      JSON.stringify({
        pebble: {
          listenAddress: `127.0.0.1:${dirPort}`,
          managementListenAddress: `127.0.0.1:${mgmtPort}`,
          certificate: dirCrt,
          privateKey: dirKey,
          httpPort: pebbleHttpPort,
          tlsPort: zsTlsPort,
          ocspResponderURL: "",
          externalAccountBindingRequired: false,
        },
      }),
    );

    // 3. challtestsrv: DNS only, every A query -> 127.0.0.1, no AAAA (Pebble
    //    must reach zeroserve's IPv4 listener).
    const chall = new Deno.Command(challtestsrvBin!, {
      args: [
        "-dnsserver",
        `:${dnsPort}`,
        "-defaultIPv4",
        "127.0.0.1",
        "-defaultIPv6",
        "",
        "-http01",
        "",
        "-https01",
        "",
        "-tlsalpn01",
        "",
        "-doh",
        "",
        "-management",
        `:${await getFreePort()}`,
      ],
      stdout: "null",
      stderr: "piped",
    }).spawn();
    children.push(chall);
    drain(chall, "challtestsrv");

    // 4. Pebble (no validation sleeps, never reject good nonces).
    const pebble = new Deno.Command(pebbleBin!, {
      args: ["-config", pebbleConfig, "-dnsserver", `127.0.0.1:${dnsPort}`],
      env: { PEBBLE_VA_NOSLEEP: "1", PEBBLE_WFE_NONCEREJECT: "0" },
      stdout: "null",
      stderr: "piped",
    }).spawn();
    children.push(pebble);
    drain(pebble, "pebble");

    // Trust the directory CA from Deno when polling Pebble's HTTPS endpoints.
    const caClient = Deno.createHttpClient({
      caCerts: [await Deno.readTextFile(caCrt)],
    });
    const directoryUrl = `https://127.0.0.1:${dirPort}/dir`;
    await waitFor(
      async () => {
        try {
          const res = await fetch(directoryUrl, { client: caClient });
          await res.body?.cancel();
          return res.ok;
        } catch {
          return false;
        }
      },
      15_000,
      "pebble directory",
    );

    // 5. A site whose acme_config requests `domain` from our Pebble directory.
    const siteRoot = join(work, "site");
    await Deno.mkdir(join(siteRoot, ".zeroserve", "scripts"), {
      recursive: true,
    });
    await Deno.writeTextFile(join(siteRoot, "index.html"), "<h1>acme</h1>\n");
    await Deno.writeTextFile(
      join(siteRoot, ".zeroserve", "scripts", "00-acme.c"),
      `#include <zeroserve.h>
ZS_INIT_ENTRY(acme_config) {
  zs_s64 cfg = zs_json_new_object();
  zs_s64 domains = zs_json_new_array();
  zs_s64 d = zs_json_new_object();
  zs_json_set_string(d, ZS_STR("${domain}"));
  zs_json_array_push(domains, d);
  zs_object_free(d);
  zs_json_set(cfg, ZS_STR("domains"), domains);
  zs_object_free(domains);
  zs_s64 u = zs_json_new_object();
  zs_json_set_string(u, ZS_STR("${directoryUrl}"));
  zs_json_set(cfg, ZS_STR("directory_url"), u);
  zs_object_free(u);
  return cfg;
}
`,
    );
    const tarPath = await packSite(siteRoot);

    // 6. Run zeroserve, trusting our directory CA via SSL_CERT_FILE.
    const acmeDir = join(work, "acme-store");
    const zeroserve = new Deno.Command(await getZeroservePath(), {
      args: [
        "--addr",
        "127.0.0.1:0",
        "--tls-addr",
        `127.0.0.1:${zsTlsPort}`,
        "--acme-dir",
        acmeDir,
        "--disable-ns-isolation",
        "--disable-request-logging",
        tarPath,
      ],
      cwd: repoRoot,
      env: { SSL_CERT_FILE: caCrt },
      stdin: "null",
      stdout: "null",
      stderr: "piped",
    }).spawn();
    children.push(zeroserve);
    drain(zeroserve, "zeroserve");

    // 7. Wait for the issued certificate to be persisted.
    const certPath = join(acmeDir, "certs", domain, "cert.pem");
    await waitFor(
      async () => {
        try {
          await Deno.stat(certPath);
          return true;
        } catch {
          return false;
        }
      },
      40_000,
      "issued certificate",
    );

    // The persisted leaf is issued by Pebble and covers the domain.
    const certText = await runOpensslText([
      "x509",
      "-in",
      certPath,
      "-noout",
      "-issuer",
      "-ext",
      "subjectAltName",
    ]);
    assertStringIncludes(certText, "Pebble");
    assertStringIncludes(certText, domain);

    // 8. The certificate is actually served on the TLS port for SNI=domain and
    //    chains to Pebble's root.
    const trust = join(work, "pebble-trust.pem");
    const root = await (await fetch(`https://127.0.0.1:${mgmtPort}/roots/0`, {
      client: caClient,
    })).text();
    const intermediate =
      await (await fetch(`https://127.0.0.1:${mgmtPort}/intermediates/0`, {
        client: caClient,
      })).text();
    await Deno.writeTextFile(trust, `${root}\n${intermediate}\n`);
    caClient.close();

    const handshake = await runOpensslText([
      "s_client",
      "-connect",
      `127.0.0.1:${zsTlsPort}`,
      "-servername",
      domain,
      "-CAfile",
      trust,
      "-verify_return_error",
    ], "Q\n");
    assertStringIncludes(handshake, "Verify return code: 0 (ok)");
  } catch (err) {
    for (const get of logs.values()) {
      console.error(get());
    }
    throw err;
  } finally {
    for (const c of children) kill(c);
    // Let the children settle so their stderr readers finish before cleanup.
    await delay(100);
    for (const c of children) await c.status.catch(() => {});
    await Deno.remove(work, { recursive: true }).catch(() => {});
  }
});

async function waitFor(
  cond: () => Promise<boolean>,
  timeoutMs: number,
  what: string,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await cond()) return;
    await delay(250);
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function runOpensslText(args: string[], stdin?: string): Promise<string> {
  const cmd = new Deno.Command("openssl", {
    args,
    stdin: stdin ? "piped" : "null",
    stdout: "piped",
    stderr: "piped",
  });
  const child = cmd.spawn();
  if (stdin) {
    const w = child.stdin.getWriter();
    await w.write(new TextEncoder().encode(stdin));
    await w.close();
  }
  const out = await child.output();
  return decoder.decode(out.stdout) + decoder.decode(out.stderr);
}
