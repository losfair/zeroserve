// End-to-end ACME (TLS-ALPN-01) test against Pebble, Let's Encrypt's test ACME
// server. It exercises the full path: a site's `zeroserve.init.acme_config`
// section declares a domain, zeroserve registers an account, places an order,
// answers the TLS-ALPN-01 challenge on its TLS listener, downloads the issued
// certificate, persists it under --acme-dir, and serves it for the domain.
//
// Requires `pebble` and `pebble-challtestsrv` (and `openssl`). In CI they are
// installed via `go install` and exposed through PEBBLE_BIN /
// PEBBLE_CHALLTESTSRV_BIN; locally the test is skipped if they are absent.

import { assert, assertStringIncludes } from "@std/assert";
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

const DOMAIN = "zs.test";

interface PebbleEnv {
  work: string;
  caCrt: string;
  directoryUrl: string;
  zsTlsPort: number;
  mgmtPort: number;
  caClient: Deno.HttpClient;
  children: Deno.ChildProcess[];
  /** Spawn a child and drain its stderr for failure diagnostics. */
  spawn: (cmd: Deno.Command, label: string) => Deno.ChildProcess;
  dumpLogs: () => void;
}

/** Stand up a throwaway CA, Pebble, and pebble-challtestsrv; run `fn`; clean up. */
async function withPebble(
  fn: (env: PebbleEnv) => Promise<void>,
): Promise<void> {
  const work = await Deno.makeTempDir({ prefix: "zs-acme-" });
  const children: Deno.ChildProcess[] = [];
  const logs = new Map<Deno.ChildProcess, () => string>();
  const spawn = (cmd: Deno.Command, label: string): Deno.ChildProcess => {
    const child = cmd.spawn();
    children.push(child);
    let buf = "";
    (async () => {
      for await (const chunk of child.stderr) buf += decoder.decode(chunk);
    })().catch(() => {});
    logs.set(child, () => `--- ${label} ---\n${buf}`);
    return child;
  };
  const dumpLogs = () => {
    for (const get of logs.values()) console.error(get());
  };

  let caClient: Deno.HttpClient | undefined;
  try {
    const zsTlsPort = await getFreePort();
    const dirPort = await getFreePort();
    const mgmtPort = await getFreePort();
    const dnsPort = await getFreePort();
    const pebbleHttpPort = await getFreePort();

    // A throwaway CA and a leaf for Pebble's ACME directory endpoint, whose SAN
    // covers 127.0.0.1 (zeroserve verifies the directory by IP).
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

    // Pebble: serve the directory with our leaf; validate TLS-ALPN-01 against
    // zeroserve's TLS port.
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

    // challtestsrv: DNS only, every A query -> 127.0.0.1, no AAAA (Pebble must
    // reach zeroserve's IPv4 listener).
    spawn(
      new Deno.Command(challtestsrvBin!, {
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
      }),
      "challtestsrv",
    );
    spawn(
      new Deno.Command(pebbleBin!, {
        args: ["-config", pebbleConfig, "-dnsserver", `127.0.0.1:${dnsPort}`],
        env: { PEBBLE_VA_NOSLEEP: "1", PEBBLE_WFE_NONCEREJECT: "0" },
        stdout: "null",
        stderr: "piped",
      }),
      "pebble",
    );

    caClient = Deno.createHttpClient({
      caCerts: [await Deno.readTextFile(caCrt)],
    });
    const directoryUrl = `https://127.0.0.1:${dirPort}/dir`;
    const client = caClient;
    await waitFor(
      async () => {
        try {
          const res = await fetch(directoryUrl, { client });
          await res.body?.cancel();
          return res.ok;
        } catch {
          return false;
        }
      },
      15_000,
      "pebble directory",
    );

    await fn({
      work,
      caCrt,
      directoryUrl,
      zsTlsPort,
      mgmtPort,
      caClient,
      children,
      spawn,
      dumpLogs,
    });
  } catch (err) {
    dumpLogs();
    throw err;
  } finally {
    caClient?.close();
    for (const c of children) {
      try {
        c.kill("SIGKILL");
      } catch { /* already gone */ }
    }
    await delay(100);
    for (const c of children) await c.status.catch(() => {});
    await Deno.remove(work, { recursive: true }).catch(() => {});
  }
}

/** Wait for the issued cert to be persisted, then confirm it's served on the
 *  TLS port for SNI=DOMAIN and chains to Pebble's issuing CA. */
async function verifyIssuedAndServed(
  env: PebbleEnv,
  acmeDir: string,
): Promise<void> {
  const certPath = join(acmeDir, "certs", DOMAIN, "cert.pem");
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
  assertStringIncludes(certText, DOMAIN);

  const trust = join(env.work, "pebble-trust.pem");
  const root = await (await fetch(`https://127.0.0.1:${env.mgmtPort}/roots/0`, {
    client: env.caClient,
  })).text();
  const intermediate = await (await fetch(
    `https://127.0.0.1:${env.mgmtPort}/intermediates/0`,
    { client: env.caClient },
  )).text();
  await Deno.writeTextFile(trust, `${root}\n${intermediate}\n`);

  const handshake = await runOpensslText([
    "s_client",
    "-connect",
    `127.0.0.1:${env.zsTlsPort}`,
    "-servername",
    DOMAIN,
    "-CAfile",
    trust,
    "-verify_return_error",
  ], "Q\n");
  assertStringIncludes(handshake, "Verify return code: 0 (ok)");
}

Deno.test({
  name: "e2e: ACME TLS-ALPN-01 issuance (script-driven acme_config)",
  ignore: !available,
}, async () => {
  await withPebble(async (env) => {
    // A site whose acme_config requests DOMAIN from our Pebble directory.
    const siteRoot = join(env.work, "site");
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
  zs_json_set_string(d, ZS_STR("${DOMAIN}"));
  zs_json_array_push(domains, d);
  zs_object_free(d);
  zs_json_set(cfg, ZS_STR("domains"), domains);
  zs_object_free(domains);
  zs_s64 u = zs_json_new_object();
  zs_json_set_string(u, ZS_STR("${env.directoryUrl}"));
  zs_json_set(cfg, ZS_STR("directory_url"), u);
  zs_object_free(u);
  return cfg;
}
`,
    );
    const tarPath = await packSite(siteRoot);

    const acmeDir = join(env.work, "acme-store");
    env.spawn(
      new Deno.Command(await getZeroservePath(), {
        args: [
          "--addr",
          "127.0.0.1:0",
          "--tls-addr",
          `127.0.0.1:${env.zsTlsPort}`,
          "--acme-dir",
          acmeDir,
          "--disable-ns-isolation",
          "--disable-request-logging",
          tarPath,
        ],
        cwd: repoRoot,
        env: { SSL_CERT_FILE: env.caCrt },
        stdin: "null",
        stdout: "null",
        stderr: "piped",
      }),
      "zeroserve",
    );
    await verifyIssuedAndServed(env, acmeDir);
  });
});

Deno.test({
  name: "e2e: ACME issuance via Caddyfile-generated acme_config",
  ignore: !available,
}, async () => {
  await withPebble(async (env) => {
    // A Caddyfile whose global email + acme_ca compile to a
    // zeroserve.init.acme_config covering the site's domain.
    const caddyfile = join(env.work, "site.caddy");
    await Deno.writeTextFile(
      caddyfile,
      `{
  email admin@${DOMAIN}
  acme_ca ${env.directoryUrl}
}
${DOMAIN} {
  respond "ok"
}
`,
    );

    const acmeDir = join(env.work, "acme-store");
    env.spawn(
      new Deno.Command(await getZeroservePath(), {
        args: [
          "--addr",
          "127.0.0.1:0",
          "--tls-addr",
          `127.0.0.1:${env.zsTlsPort}`,
          "--acme-dir",
          acmeDir,
          "--disable-ns-isolation",
          "--disable-request-logging",
          "--caddy",
          caddyfile,
        ],
        cwd: repoRoot,
        env: { SSL_CERT_FILE: env.caCrt },
        stdin: "null",
        stdout: "null",
        stderr: "piped",
      }),
      "zeroserve",
    );
    await verifyIssuedAndServed(env, acmeDir);
  });
});

Deno.test({
  name: "e2e: --cert-dir takes precedence over ACME for covered hostnames",
  ignore: !available,
}, async () => {
  await withPebble(async (env) => {
    const covered = "covered.test";

    // A --cert-dir holding a self-signed cert for `covered`.
    const certDir = join(env.work, "certdir");
    await Deno.mkdir(certDir);
    await openssl([
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      join(certDir, "covered.key"),
      "-out",
      join(certDir, "covered.crt"),
      "-days",
      "2",
      "-subj",
      `/CN=${covered}`,
      "-addext",
      "basicConstraints=critical,CA:FALSE",
      "-addext",
      `subjectAltName=DNS:${covered}`,
    ]);

    // A site whose acme_config requests BOTH the cert-dir domain and an
    // uncovered one; only the uncovered one should be acquired over ACME.
    const siteRoot = join(env.work, "site");
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
  zs_s64 a = zs_json_new_object();
  zs_json_set_string(a, ZS_STR("${covered}"));
  zs_json_array_push(domains, a);
  zs_object_free(a);
  zs_s64 b = zs_json_new_object();
  zs_json_set_string(b, ZS_STR("${DOMAIN}"));
  zs_json_array_push(domains, b);
  zs_object_free(b);
  zs_json_set(cfg, ZS_STR("domains"), domains);
  zs_object_free(domains);
  zs_s64 u = zs_json_new_object();
  zs_json_set_string(u, ZS_STR("${env.directoryUrl}"));
  zs_json_set(cfg, ZS_STR("directory_url"), u);
  zs_object_free(u);
  return cfg;
}
`,
    );
    const tarPath = await packSite(siteRoot);

    const acmeDir = join(env.work, "acme-store");
    env.spawn(
      new Deno.Command(await getZeroservePath(), {
        args: [
          "--addr",
          "127.0.0.1:0",
          "--tls-addr",
          `127.0.0.1:${env.zsTlsPort}`,
          "--cert-dir",
          certDir,
          "--acme-dir",
          acmeDir,
          "--disable-ns-isolation",
          "--disable-request-logging",
          tarPath,
        ],
        cwd: repoRoot,
        env: { SSL_CERT_FILE: env.caCrt },
        stdin: "null",
        stdout: "null",
        stderr: "piped",
      }),
      "zeroserve",
    );

    // The uncovered domain is issued by Pebble and served.
    await verifyIssuedAndServed(env, acmeDir);

    // The cert-dir domain is NEVER ordered over ACME.
    const orderedPath = join(acmeDir, "certs", covered, "cert.pem");
    let ordered = true;
    try {
      await Deno.stat(orderedPath);
    } catch {
      ordered = false;
    }
    assert(!ordered, `${covered} should not be acquired over ACME`);

    // ...and it is served from the cert-dir cert (self-signed; not Pebble).
    const served = await runOpensslText([
      "s_client",
      "-connect",
      `127.0.0.1:${env.zsTlsPort}`,
      "-servername",
      covered,
    ], "Q\n");
    assertStringIncludes(served, covered);
    assert(!served.includes("Pebble"), `${covered} should not be ACME-issued`);
  });
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
