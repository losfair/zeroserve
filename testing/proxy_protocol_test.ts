import { assertStringIncludes } from "@std/assert";
import { join } from "@std/path";
import {
  generateSelfSignedCert,
  packSite,
  spawnZeroserve,
} from "./test_utils.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

Deno.test("e2e: PROXY protocol can be enabled per listener", async () => {
  const siteDir = await Deno.makeTempDir();
  const cert = await generateSelfSignedCert();
  let tarPath: string | null = null;
  try {
    await Deno.writeTextFile(
      join(siteDir, "index.html"),
      "proxy protocol ok\n",
    );
    tarPath = await packSite(siteDir);

    await assertListenerModes(
      tarPath,
      cert,
      "--enable-http-proxy-protocol",
      { http: true, https: false },
    );
    await assertListenerModes(
      tarPath,
      cert,
      "--enable-https-proxy-protocol",
      { http: false, https: true },
    );
  } finally {
    if (tarPath) {
      await Deno.remove(tarPath).catch(() => {});
    }
    await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    await cert.cleanup();
  }
});

async function assertListenerModes(
  tarPath: string,
  cert: { certPath: string; keyPath: string },
  flag: string,
  proxyProtocol: { http: boolean; https: boolean },
): Promise<void> {
  const proc = await spawnZeroserve(
    [
      "--cert",
      cert.certPath,
      "--key",
      cert.keyPath,
      flag,
      tarPath,
    ],
    { tls: true },
  );
  try {
    const httpResponse = await request(
      proc.httpPort,
      false,
      proxyProtocol.http,
      cert.certPath,
    );
    assertStringIncludes(httpResponse, "HTTP/1.1 200 OK");
    assertStringIncludes(httpResponse, "proxy protocol ok\n");

    const httpsResponse = await request(
      proc.tlsPort!,
      true,
      proxyProtocol.https,
      cert.certPath,
    );
    assertStringIncludes(httpsResponse, "HTTP/1.1 200 OK");
    assertStringIncludes(httpsResponse, "proxy protocol ok\n");
  } finally {
    await proc.stop();
  }
}

async function request(
  port: number,
  tls: boolean,
  proxyProtocol: boolean,
  certPath: string,
): Promise<string> {
  const tcpConn = await Deno.connect({ hostname: "127.0.0.1", port });
  let conn: Deno.Conn = tcpConn;
  try {
    if (proxyProtocol) {
      await writeAll(conn, encoder.encode("PROXY UNKNOWN\r\n"));
    }
    if (tls) {
      conn = await Deno.startTls(tcpConn, {
        hostname: "localhost",
        caCerts: [await Deno.readTextFile(certPath)],
      });
    }

    await writeAll(
      conn,
      encoder.encode(
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
      ),
    );
    const chunks: Uint8Array[] = [];
    const buffer = new Uint8Array(4096);
    while (true) {
      const read = await conn.read(buffer);
      if (read === null) {
        break;
      }
      chunks.push(buffer.slice(0, read));
      const response = decoder.decode(concat(chunks));
      if (response.includes("proxy protocol ok\n")) {
        return response;
      }
    }
    return decoder.decode(concat(chunks));
  } finally {
    conn.close();
  }
}

async function writeAll(
  conn: { write(bytes: Uint8Array): Promise<number> },
  bytes: Uint8Array,
): Promise<void> {
  let written = 0;
  while (written < bytes.length) {
    written += await conn.write(bytes.subarray(written));
  }
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}
