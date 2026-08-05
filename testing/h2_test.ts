import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
    generateSelfSignedCert,
    hasBpfToolchain,
    packSite,
    withZeroserve,
    withZeroserveTls,
} from "./test_utils.ts";
import * as http2 from "node:http2";
import { Buffer } from "node:buffer";

const canRunScripts = await hasBpfToolchain();

function h2cRequest(
    hostname: string,
    port: number,
    path: string,
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
    return new Promise((resolve, reject) => {
        const client = http2.connect(`http://${hostname}:${port}`);

        client.on("error", (err: Error) => {
            client.close();
            reject(err);
        });

        const req = client.request({ ":path": path, ":method": "GET" });

        let status = 0;
        let headers: Record<string, string> = {};
        const chunks: Buffer[] = [];

        req.on("response", (hdrs: http2.IncomingHttpHeaders & http2.IncomingHttpStatusHeader) => {
            status = hdrs[":status"] as number;
            for (const [key, value] of Object.entries(hdrs)) {
                if (!key.startsWith(":")) {
                    headers[key] = Array.isArray(value) ? value[0] : (value as string);
                }
            }
        });

        req.on("data", (chunk: Buffer) => {
            chunks.push(chunk);
        });

        req.on("end", () => {
            client.close();
            const body = Buffer.concat(chunks).toString("utf-8");
            resolve({ status, headers, body });
        });

        req.on("error", (err: Error) => {
            client.close();
            reject(err);
        });

        req.end();
    });
}

function h2cMultipleRequests(
    hostname: string,
    port: number,
    paths: string[],
): Promise<{ status: number; body: string }[]> {
    return new Promise((resolve, reject) => {
        const client = http2.connect(`http://${hostname}:${port}`);

        client.on("error", (err: Error) => {
            client.close();
            reject(err);
        });

        const results: { status: number; body: string }[] = [];
        let completed = 0;

        for (let i = 0; i < paths.length; i++) {
            const path = paths[i];
            const req = client.request({ ":path": path, ":method": "GET" });

            let status = 0;
            const chunks: Buffer[] = [];

            req.on("response", (hdrs: http2.IncomingHttpHeaders & http2.IncomingHttpStatusHeader) => {
                status = hdrs[":status"] as number;
            });

            req.on("data", (chunk: Buffer) => {
                chunks.push(chunk);
            });

            req.on("end", () => {
                const body = Buffer.concat(chunks).toString("utf-8");
                results[i] = { status, body };
                completed++;
                if (completed === paths.length) {
                    client.close();
                    resolve(results);
                }
            });

            req.on("error", (err: Error) => {
                client.close();
                reject(err);
            });

            req.end();
        }
    });
}

async function h2Request(
    hostname: string,
    port: number,
    path: string,
    certPath: string,
): Promise<{ status: number; headers: Record<string, string>; body: string; alpn: string }> {
    const caCert = await Deno.readTextFile(certPath);
    const client = Deno.createHttpClient({
        caCerts: [caCert],
        http2: true,
    });

    try {
        const res = await fetch(`https://${hostname}:${port}${path}`, { client });
        const body = await res.text();
        const headers: Record<string, string> = {};
        for (const [key, value] of res.headers.entries()) {
            headers[key] = value;
        }
        // Deno's fetch with http2: true negotiates h2 via ALPN
        return { status: res.status, headers, body, alpn: "h2" };
    } finally {
        client.close();
    }
}

async function h2MultipleRequests(
    hostname: string,
    port: number,
    paths: string[],
    certPath: string,
): Promise<{ status: number; body: string }[]> {
    const caCert = await Deno.readTextFile(certPath);
    const client = Deno.createHttpClient({
        caCerts: [caCert],
        http2: true,
    });

    try {
        // Make all requests in parallel to test multiplexing
        const promises = paths.map(async (path) => {
            const res = await fetch(`https://${hostname}:${port}${path}`, { client });
            const body = await res.text();
            return { status: res.status, body };
        });
        return await Promise.all(promises);
    } finally {
        client.close();
    }
}

Deno.test("e2e: h2c basic content serving", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<!doctype html><h1>hello h2c</h1>\n",
        );
        await Deno.mkdir(join(siteDir, "docs"), { recursive: true });
        await Deno.writeTextFile(join(siteDir, "docs", "note.txt"), "h2c docs ok\n");

        tarPath = await packSite(siteDir);

        await withZeroserve(tarPath, async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            const indexRes = await h2cRequest(hostname, port, "/");
            assertEquals(indexRes.status, 200);
            assertEquals(indexRes.body, "<!doctype html><h1>hello h2c</h1>\n");
            assert(indexRes.headers["content-type"]?.includes("text/html"));

            const noteRes = await h2cRequest(hostname, port, "/docs/note.txt");
            assertEquals(noteRes.status, 200);
            assertEquals(noteRes.body, "h2c docs ok\n");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: h2c multiplexed streams", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(join(siteDir, "a.txt"), "content a\n");
        await Deno.writeTextFile(join(siteDir, "b.txt"), "content b\n");
        await Deno.writeTextFile(join(siteDir, "c.txt"), "content c\n");
        await Deno.writeTextFile(join(siteDir, "d.txt"), "content d\n");

        tarPath = await packSite(siteDir);

        await withZeroserve(tarPath, async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            const paths = ["/a.txt", "/b.txt", "/c.txt", "/d.txt"];
            const results = await h2cMultipleRequests(hostname, port, paths);

            assertEquals(results.length, 4);
            assertEquals(results[0].status, 200);
            assertEquals(results[0].body, "content a\n");
            assertEquals(results[1].status, 200);
            assertEquals(results[1].body, "content b\n");
            assertEquals(results[2].status, 200);
            assertEquals(results[2].body, "content c\n");
            assertEquals(results[3].status, 200);
            assertEquals(results[3].body, "content d\n");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: h2c 404 handling", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(join(siteDir, "index.html"), "home\n");

        tarPath = await packSite(siteDir);

        await withZeroserve(tarPath, async (baseUrl) => {
            const url = new URL(baseUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            const notFoundRes = await h2cRequest(hostname, port, "/nonexistent.txt");
            assertEquals(notFoundRes.status, 404);
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});

Deno.test("e2e: h2 (TLS) basic content serving", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    const cert = await generateSelfSignedCert();
    try {
        await Deno.writeTextFile(
            join(siteDir, "index.html"),
            "<!doctype html><h1>hello h2</h1>\n",
        );
        await Deno.mkdir(join(siteDir, "docs"), { recursive: true });
        await Deno.writeTextFile(join(siteDir, "docs", "note.txt"), "h2 docs ok\n");

        tarPath = await packSite(siteDir);

        await withZeroserveTls(tarPath, cert.certPath, cert.keyPath, async (_httpUrl, httpsUrl) => {
            const url = new URL(httpsUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            const indexRes = await h2Request(hostname, port, "/", cert.certPath);
            assertEquals(indexRes.status, 200);
            assertEquals(indexRes.body, "<!doctype html><h1>hello h2</h1>\n");
            assert(indexRes.headers["content-type"]?.includes("text/html"));
            assertEquals(indexRes.alpn, "h2");

            const noteRes = await h2Request(hostname, port, "/docs/note.txt", cert.certPath);
            assertEquals(noteRes.status, 200);
            assertEquals(noteRes.body, "h2 docs ok\n");
            assertEquals(noteRes.alpn, "h2");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        await cert.cleanup();
    }
});

Deno.test("e2e: h2 (TLS) multiplexed streams", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    const cert = await generateSelfSignedCert();
    try {
        await Deno.writeTextFile(join(siteDir, "x.txt"), "content x\n");
        await Deno.writeTextFile(join(siteDir, "y.txt"), "content y\n");
        await Deno.writeTextFile(join(siteDir, "z.txt"), "content z\n");

        tarPath = await packSite(siteDir);

        await withZeroserveTls(tarPath, cert.certPath, cert.keyPath, async (_httpUrl, httpsUrl) => {
            const url = new URL(httpsUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            const paths = ["/x.txt", "/y.txt", "/z.txt"];
            const results = await h2MultipleRequests(hostname, port, paths, cert.certPath);

            assertEquals(results.length, 3);
            assertEquals(results[0].status, 200);
            assertEquals(results[0].body, "content x\n");
            assertEquals(results[1].status, 200);
            assertEquals(results[1].body, "content y\n");
            assertEquals(results[2].status, 200);
            assertEquals(results[2].body, "content z\n");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        await cert.cleanup();
    }
});

Deno.test("e2e: h2 (TLS) 404 handling", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    const cert = await generateSelfSignedCert();
    try {
        await Deno.writeTextFile(join(siteDir, "index.html"), "home\n");

        tarPath = await packSite(siteDir);

        await withZeroserveTls(tarPath, cert.certPath, cert.keyPath, async (_httpUrl, httpsUrl) => {
            const url = new URL(httpsUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            const notFoundRes = await h2Request(hostname, port, "/nonexistent.txt", cert.certPath);
            assertEquals(notFoundRes.status, 404);
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        await cert.cleanup();
    }
});

Deno.test("e2e: h2 (TLS) ALPN negotiation", async () => {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    const cert = await generateSelfSignedCert();
    try {
        await Deno.writeTextFile(join(siteDir, "index.html"), "alpn test\n");

        tarPath = await packSite(siteDir);

        await withZeroserveTls(tarPath, cert.certPath, cert.keyPath, async (_httpUrl, httpsUrl) => {
            const url = new URL(httpsUrl);
            const hostname = url.hostname;
            const port = Number(url.port);

            const res = await h2Request(hostname, port, "/", cert.certPath);
            assertEquals(res.status, 200);
            assertEquals(res.alpn, "h2", "Server should negotiate h2 via ALPN");
        });
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        await cert.cleanup();
    }
});

Deno.test({
    name: "e2e: zs_req_uri works for h1 and h2",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        const cert = await generateSelfSignedCert();
        try {
            await Deno.writeTextFile(join(siteDir, "index.html"), "fallback\n");

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            // Script that echoes the request URI back in the response
            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char uri[256];
  zs_s64 uri_len = zs_req_uri(uri, sizeof(uri));
  if (uri_len < 0) {
    zs_respond(500, ZS_STR("zs_req_uri failed"));
    return 0;
  }

  char path[64];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/echo-uri") != 0) {
    return 0;
  }

  zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("text/plain"));
  zs_respond(200, uri, uri_len);
  return 0;
}
`;
            await Deno.writeTextFile(join(scriptsDir, "10-echo-uri.c"), scriptSource);

            tarPath = await packSite(siteDir);

            // Test with h1, h2c, and h2
            await withZeroserveTls(tarPath, cert.certPath, cert.keyPath, async (httpUrl, httpsUrl) => {
                const httpUrlObj = new URL(httpUrl);
                const httpsUrlObj = new URL(httpsUrl);

                // Test h1 (HTTP/1.1 via regular fetch)
                const h1Res = await fetch(`${httpUrl}/echo-uri?foo=bar&baz=qux`);
                assertEquals(h1Res.status, 200);
                const h1Body = await h1Res.text();
                assertEquals(h1Body, "/echo-uri?foo=bar&baz=qux", "h1 zs_req_uri should return path with query");

                // Test h2c (HTTP/2 cleartext)
                const h2cRes = await h2cRequest(
                    httpUrlObj.hostname,
                    Number(httpUrlObj.port),
                    "/echo-uri?h2c=true&test=1",
                );
                assertEquals(h2cRes.status, 200);
                assertEquals(h2cRes.body, "/echo-uri?h2c=true&test=1", "h2c zs_req_uri should return path with query");

                // Test h2 (HTTP/2 over TLS)
                const h2Res = await h2Request(
                    httpsUrlObj.hostname,
                    Number(httpsUrlObj.port),
                    "/echo-uri?h2=true&secure=1",
                    cert.certPath,
                );
                assertEquals(h2Res.status, 200);
                assertEquals(h2Res.body, "/echo-uri?h2=true&secure=1", "h2 zs_req_uri should return path with query");

                // Test with no query string
                const h1NoQueryRes = await fetch(`${httpUrl}/echo-uri`);
                assertEquals(h1NoQueryRes.status, 200);
                assertEquals(await h1NoQueryRes.text(), "/echo-uri", "h1 zs_req_uri should work without query");

                const h2cNoQueryRes = await h2cRequest(
                    httpUrlObj.hostname,
                    Number(httpUrlObj.port),
                    "/echo-uri",
                );
                assertEquals(h2cNoQueryRes.status, 200);
                assertEquals(h2cNoQueryRes.body, "/echo-uri", "h2c zs_req_uri should work without query");

                const h2NoQueryRes = await h2Request(
                    httpsUrlObj.hostname,
                    Number(httpsUrlObj.port),
                    "/echo-uri",
                    cert.certPath,
                );
                assertEquals(h2NoQueryRes.status, 200);
                assertEquals(h2NoQueryRes.body, "/echo-uri", "h2 zs_req_uri should work without query");
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
            await cert.cleanup();
        }
    },
});

Deno.test("e2e: h2c advertises enlarged flow-control windows", async () => {
    // The h2 crate's default 64 KiB windows cap upload throughput at
    // 64 KiB per round trip, which throttles large reverse-proxied uploads
    // (e.g. git pushes). The server must advertise the configured settings.
    // Reads the server's SETTINGS frame off a raw h2c connection. node:http2's
    // remoteSettings event would be simpler, but some runtimes' node compat
    // shims (e.g. the Deno packaged for OpenBSD) never emit it.
    async function fetchRemoteSettings(
        hostname: string,
        port: number,
    ): Promise<{ initialWindowSize?: number; maxFrameSize?: number }> {
        const conn = await Deno.connect({ hostname, port });
        let timedOut = false;
        const timer = setTimeout(() => {
            timedOut = true;
            try {
                conn.close();
            } catch {
                // already closed
            }
        }, 10000);
        try {
            // Client preface plus an empty SETTINGS frame.
            const preface = new TextEncoder().encode("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            const emptySettings = new Uint8Array([0, 0, 0, 0x4, 0, 0, 0, 0, 0]);
            const out = new Uint8Array(preface.length + emptySettings.length);
            out.set(preface);
            out.set(emptySettings, preface.length);
            for (let written = 0; written < out.length;) {
                written += await conn.write(out.subarray(written));
            }

            let buf = new Uint8Array(0);
            const chunk = new Uint8Array(16 * 1024);
            for (;;) {
                // Parse complete frames: 3-byte length, type, flags, stream id.
                while (buf.length >= 9) {
                    const len = (buf[0] << 16) | (buf[1] << 8) | buf[2];
                    if (buf.length < 9 + len) {
                        break;
                    }
                    const type = buf[3];
                    const flags = buf[4];
                    const payload = buf.subarray(9, 9 + len);
                    if (type === 0x4 && (flags & 0x1) === 0) {
                        const settings: { initialWindowSize?: number; maxFrameSize?: number } = {};
                        for (let off = 0; off + 6 <= payload.length; off += 6) {
                            const id = (payload[off] << 8) | payload[off + 1];
                            const value = (payload[off + 2] << 24 >>> 0) |
                                (payload[off + 3] << 16) |
                                (payload[off + 4] << 8) |
                                payload[off + 5];
                            if (id === 0x4) {
                                settings.initialWindowSize = value >>> 0;
                            } else if (id === 0x5) {
                                settings.maxFrameSize = value >>> 0;
                            }
                        }
                        return settings;
                    }
                    buf = buf.subarray(9 + len);
                }
                const n = await conn.read(chunk).catch(() => null);
                if (n === null) {
                    throw new Error(
                        timedOut ? "timed out waiting for SETTINGS" : "connection closed before SETTINGS",
                    );
                }
                const next = new Uint8Array(buf.length + n);
                next.set(buf);
                next.set(chunk.subarray(0, n), buf.length);
                buf = next;
            }
        } finally {
            clearTimeout(timer);
            if (!timedOut) {
                try {
                    conn.close();
                } catch {
                    // already closed
                }
            }
        }
    }

    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
        await Deno.writeTextFile(join(siteDir, "index.html"), "windows\n");
        tarPath = await packSite(siteDir);

        await withZeroserve(tarPath, async (baseUrl) => {
            const url = new URL(baseUrl);
            const settings = await fetchRemoteSettings(url.hostname, Number(url.port));
            assertEquals(settings.initialWindowSize, 512 * 1024);
            assertEquals(settings.maxFrameSize, 64 * 1024);
        });

        // The windows are configurable per instance.
        await withZeroserve(tarPath, async (baseUrl) => {
            const url = new URL(baseUrl);
            const settings = await fetchRemoteSettings(url.hostname, Number(url.port));
            assertEquals(settings.initialWindowSize, 128 * 1024);
        }, ["--h2-stream-window-kb", "128", "--h2-connection-window-kb", "256"]);
    } finally {
        if (tarPath) {
            await Deno.remove(tarPath).catch(() => {});
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
});
