import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
    generateSelfSignedCert,
    hasBpfToolchain,
    packSite,
    repoRoot,
    withZeroserve,
    withZeroserveTls,
} from "./test_utils.ts";

const canRunScripts = await hasBpfToolchain();
const encoder = new TextEncoder();
const decoder = new TextDecoder();
type ByteArray = Uint8Array<ArrayBufferLike>;

function bytesToBase64(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}

function base64ToBase64Url(base64: string): string {
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function bytesToBase64Url(bytes: Uint8Array): string {
    return base64ToBase64Url(bytesToBase64(bytes));
}

function pemToDerBytes(pem: string): Uint8Array {
    const base64 = pem
        .split(/\r?\n/)
        .filter((line) => !line.startsWith("-----") && line.length > 0)
        .join("");
    return Uint8Array.from(atob(base64), (ch) => ch.charCodeAt(0));
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
    const input = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(input).set(bytes);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
    return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0"))
        .join("");
}

async function startBackend(
    handler: (req: Request) => Response | Promise<Response>,
): Promise<{ url: string; close: () => Promise<void> }> {
    const controller = new AbortController();
    let port = 0;
    const server = Deno.serve(
        {
            hostname: "127.0.0.1",
            port: 0,
            signal: controller.signal,
            onListen: ({ port: listenPort }) => {
                port = listenPort;
            },
        },
        handler,
    );

    if (port === 0) {
        await new Promise((resolve) => setTimeout(resolve, 0));
    }

    if (port === 0) {
        controller.abort();
        await server.finished;
        throw new Error("failed to start backend server");
    }

    return {
        url: `http://127.0.0.1:${port}`,
        close: async () => {
            controller.abort();
            await server.finished;
        },
    };
}

async function startWebsocketBackend(): Promise<{
    httpUrl: string;
    close: () => Promise<void>;
}> {
    const controller = new AbortController();
    let port = 0;
    const sockets = new Set<WebSocket>();
    const server = Deno.serve(
        {
            hostname: "127.0.0.1",
            port: 0,
            signal: controller.signal,
            onListen: ({ port: listenPort }) => {
                port = listenPort;
            },
        },
        (req) => {
            const upgrade = req.headers.get("upgrade") ?? "";
            if (!upgrade.toLowerCase().includes("websocket")) {
                return new Response("upgrade required", { status: 426 });
            }
            const { socket, response } = Deno.upgradeWebSocket(req);
            sockets.add(socket);
            socket.addEventListener("message", (event) => {
                socket.send(`echo:${event.data}`);
            });
            socket.addEventListener("close", () => {
                sockets.delete(socket);
            });
            return response;
        },
    );

    if (port === 0) {
        await new Promise((resolve) => setTimeout(resolve, 0));
    }

    if (port === 0) {
        controller.abort();
        await server.finished;
        throw new Error("failed to start websocket backend");
    }

    return {
        httpUrl: `http://127.0.0.1:${port}`,
        close: async () => {
            const pending = Array.from(sockets, (socket) =>
                new Promise<void>((resolve) => {
                    if (socket.readyState === WebSocket.CLOSED) {
                        resolve();
                        return;
                    }
                    socket.addEventListener("close", () => resolve(), {
                        once: true,
                    });
                    try {
                        socket.close();
                    } catch {
                        resolve();
                    }
                })
            );
            await Promise.all(pending);
            controller.abort();
            await server.finished;
        },
    };
}

async function assertWebsocketEcho(url: string, payload: string): Promise<void> {
    await new Promise<void>((resolve, reject) => {
        const ws = new WebSocket(url);
        let done = false;
        let timer: ReturnType<typeof setTimeout> | null = null;
        const closePromise = new Promise<void>((resolveClose) => {
            ws.onclose = () => resolveClose();
        });
        const finish = (err?: Error) => {
            if (done) {
                return;
            }
            done = true;
            if (timer !== null) {
                clearTimeout(timer);
            }
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        };
        const terminate = (err: Error) => {
            try {
                ws.close();
            } catch {
                // ignore close errors on error path
            }
            closePromise.then(() => finish(err));
        };
        timer = setTimeout(() => {
            terminate(new Error("websocket timeout"));
        }, 2000);

        ws.onopen = () => {
            ws.send(payload);
        };

        ws.onmessage = (event) => {
            if (event.data === `echo:${payload}`) {
                try {
                    ws.close();
                } catch {
                    // ignore close errors on shutdown path
                }
                closePromise.then(() => finish());
            }
        };

        ws.onerror = () => {
            terminate(new Error("websocket error"));
        };
    });
}

type RawHttpResponse = {
    status: number;
    headers: Headers;
    body: ByteArray;
};

async function writeAll(conn: Deno.Conn, data: Uint8Array): Promise<void> {
    let offset = 0;
    while (offset < data.length) {
        offset += await conn.write(data.subarray(offset));
    }
}

function concatBuffers(chunks: ByteArray[], total: number): ByteArray {
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }
    return out;
}

function appendBuffer(buffer: ByteArray, chunk: ByteArray): ByteArray {
    if (buffer.length === 0) {
        return chunk;
    }
    const out = new Uint8Array(buffer.length + chunk.length);
    out.set(buffer);
    out.set(chunk, buffer.length);
    return out;
}

function indexOfSequence(buffer: ByteArray, needle: ByteArray): number {
    if (needle.length === 0 || buffer.length < needle.length) {
        return -1;
    }
    outer:
    for (let i = 0; i <= buffer.length - needle.length; i++) {
        for (let j = 0; j < needle.length; j++) {
            if (buffer[i + j] !== needle[j]) {
                continue outer;
            }
        }
        return i;
    }
    return -1;
}

async function readUntil(
    conn: Deno.Conn,
    delimiter: ByteArray,
): Promise<{ head: ByteArray; rest: ByteArray }> {
    let buffer: ByteArray = new Uint8Array();
    while (true) {
        const index = indexOfSequence(buffer, delimiter);
        if (index >= 0) {
            const head = buffer.subarray(0, index);
            const rest = buffer.subarray(index + delimiter.length);
            return { head, rest };
        }
        const chunk: ByteArray = new Uint8Array(8192);
        const n = await conn.read(chunk);
        if (n === null || n === 0) {
            throw new Error("unexpected eof while reading headers");
        }
        buffer = appendBuffer(buffer, chunk.subarray(0, n));
    }
}

async function startRawHeaderCaptureBackend(): Promise<{
    url: string;
    requestHead: Promise<string>;
    close: () => Promise<void>;
}> {
    const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
    const port = (listener.addr as Deno.NetAddr).port;
    let closed = false;

    const requestHead = (async () => {
        const conn = await listener.accept();
        try {
            const delimiter = encoder.encode("\r\n\r\n");
            const { head } = await readUntil(conn, delimiter);
            await writeAll(
                conn,
                encoder.encode(
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                ),
            );
            return decoder.decode(head);
        } finally {
            conn.close();
            if (!closed) {
                closed = true;
                listener.close();
            }
        }
    })();

    return {
        url: `http://127.0.0.1:${port}`,
        requestHead,
        close: async () => {
            if (!closed) {
                closed = true;
                listener.close();
            }
            await requestHead.catch(() => {});
        },
    };
}

async function readChunkedBody(
    conn: Deno.Conn,
    initial: ByteArray,
): Promise<ByteArray> {
    const crlf = encoder.encode("\r\n");
    let buffer = initial;
    const chunks: ByteArray[] = [];
    let total = 0;

    const readMore = async () => {
        const chunk: ByteArray = new Uint8Array(8192);
        const n = await conn.read(chunk);
        if (n === null || n === 0) {
            throw new Error("unexpected eof while reading chunked body");
        }
        buffer = appendBuffer(buffer, chunk.subarray(0, n));
    };

    while (true) {
        let lineEnd = indexOfSequence(buffer, crlf);
        while (lineEnd === -1) {
            await readMore();
            lineEnd = indexOfSequence(buffer, crlf);
        }
        const line = decoder.decode(buffer.subarray(0, lineEnd));
        buffer = buffer.subarray(lineEnd + crlf.length);
        const sizePart = line.split(";")[0].trim();
        const size = Number.parseInt(sizePart, 16);
        if (!Number.isFinite(size)) {
            throw new Error(`invalid chunk size: ${line}`);
        }
        if (size === 0) {
            while (true) {
                let trailerEnd = indexOfSequence(buffer, crlf);
                while (trailerEnd === -1) {
                    await readMore();
                    trailerEnd = indexOfSequence(buffer, crlf);
                }
                const trailer = decoder.decode(buffer.subarray(0, trailerEnd));
                buffer = buffer.subarray(trailerEnd + crlf.length);
                if (trailer.length === 0) {
                    return concatBuffers(chunks, total);
                }
            }
        }
        while (buffer.length < size + crlf.length) {
            await readMore();
        }
        const chunk = buffer.subarray(0, size);
        const trailer = buffer.subarray(size, size + crlf.length);
        if (
            trailer.length !== crlf.length ||
            indexOfSequence(trailer, crlf) !== 0
        ) {
            throw new Error("missing chunk trailer");
        }
        chunks.push(chunk);
        total += chunk.length;
        buffer = buffer.subarray(size + crlf.length);
    }
}

async function readContentLengthBody(
    conn: Deno.Conn,
    initial: ByteArray,
    length: number,
): Promise<ByteArray> {
    let buffer = initial;
    while (buffer.length < length) {
        const chunk: ByteArray = new Uint8Array(8192);
        const n = await conn.read(chunk);
        if (n === null || n === 0) {
            throw new Error("unexpected eof while reading body");
        }
        buffer = appendBuffer(buffer, chunk.subarray(0, n));
    }
    return buffer.subarray(0, length);
}

async function readToEnd(conn: Deno.Conn, initial: ByteArray): Promise<ByteArray> {
    const chunks: ByteArray[] = [];
    let total = 0;
    if (initial.length > 0) {
        chunks.push(initial);
        total += initial.length;
    }
    while (true) {
        const chunk: ByteArray = new Uint8Array(8192);
        const n = await conn.read(chunk);
        if (n === null || n === 0) {
            break;
        }
        const slice = chunk.subarray(0, n);
        chunks.push(slice);
        total += slice.length;
    }
    return concatBuffers(chunks, total);
}

async function sendRawHttpRequest(
    hostname: string,
    port: number,
    path: string,
    body: string,
    chunked: boolean,
): Promise<RawHttpResponse> {
    const conn = await Deno.connect({ hostname, port });
    try {
        const bodyBytes = encoder.encode(body);
        const headers = [
            `Host: ${hostname}:${port}`,
            "User-Agent: deno-test",
            "Accept: */*",
            "Accept-Encoding: identity",
            "Content-Type: text/plain",
        ];
        if (chunked) {
            headers.push("Transfer-Encoding: chunked");
        } else {
            headers.push(`Content-Length: ${bodyBytes.length}`);
        }
        const headerText = `POST ${path} HTTP/1.1\r\n${headers.join("\r\n")}\r\n\r\n`;
        await writeAll(conn, encoder.encode(headerText));
        if (chunked) {
            const mid = Math.max(1, Math.floor(body.length / 2));
            const parts = [body.slice(0, mid), body.slice(mid)];
            for (const part of parts) {
                if (part.length === 0) {
                    continue;
                }
                const chunk = encoder.encode(part);
                const prefix = `${chunk.length.toString(16)}\r\n`;
                await writeAll(conn, encoder.encode(prefix));
                await writeAll(conn, chunk);
                await writeAll(conn, encoder.encode("\r\n"));
            }
            await writeAll(conn, encoder.encode("0\r\n\r\n"));
        } else if (bodyBytes.length > 0) {
            await writeAll(conn, bodyBytes);
        }

        const delimiter = encoder.encode("\r\n\r\n");
        const { head, rest } = await readUntil(conn, delimiter);
        const headerTextResp = decoder.decode(head);
        const lines = headerTextResp.split("\r\n").filter((line) => line.length > 0);
        if (lines.length === 0) {
            throw new Error("missing response status line");
        }
        const [_, statusCode] = lines[0].split(" ");
        const status = Number.parseInt(statusCode ?? "", 10);
        if (!Number.isFinite(status)) {
            throw new Error(`invalid response status: ${lines[0]}`);
        }
        const headersOut = new Headers();
        for (const line of lines.slice(1)) {
            const idx = line.indexOf(":");
            if (idx === -1) {
                continue;
            }
            const name = line.slice(0, idx).trim();
            const value = line.slice(idx + 1).trim();
            headersOut.append(name, value);
        }

        const transferEncoding = headersOut.get("transfer-encoding");
        const contentLength = headersOut.get("content-length");
        let bodyBytesOut: Uint8Array;
        if (transferEncoding && transferEncoding.toLowerCase().includes("chunked")) {
            bodyBytesOut = await readChunkedBody(conn, rest);
        } else if (contentLength) {
            const length = Number.parseInt(contentLength, 10);
            bodyBytesOut = await readContentLengthBody(conn, rest, length);
        } else {
            bodyBytesOut = await readToEnd(conn, rest);
        }

        return {
            status,
            headers: headersOut,
            body: bodyBytesOut,
        };
    } finally {
        conn.close();
    }
}

Deno.test({
    name: "e2e: scripting APIs",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "Hello <zs-meta>name</zs-meta> via <zs-meta>method</zs-meta> at <zs-meta>now_ms</zs-meta>\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.copyFile(
                join(repoRoot, "examples", "template.c"),
                join(scriptsDir, "template.c"),
            );
            await Deno.copyFile(
                join(repoRoot, "examples", "health_response.c"),
                join(scriptsDir, "health_response.c"),
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const healthRes = await fetch(`${baseUrl}/health`);
                assertEquals(healthRes.status, 200);
                const healthJson = (await healthRes.json()) as {
                    status: string;
                    year: string;
                };
                assertEquals(healthJson.status, "ok");
                const year = Number.parseInt(healthJson.year, 10);
                assert(!Number.isNaN(year));
                assert(year >= 1970 && year <= 3000);

                const templatedRes = await fetch(
                    `${baseUrl}/index.html?name=user`,
                );
                assertEquals(templatedRes.status, 200);
                const templatedBody = await templatedRes.text();
                assert(templatedBody.includes("Hello user via GET"));
                assert(!templatedBody.includes("<zs-meta>name</zs-meta>"));
                assert(!templatedBody.includes("<zs-meta>method</zs-meta>"));
                assert(!templatedBody.includes("<zs-meta>now_ms</zs-meta>"));
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: cstring helpers cap returned length to output buffer",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[8];

  zs_s64 zero_len = zs_req_path(path, 0);
  if (zero_len != 0) {
    zs_respond(500, ZS_STR("zero-length output returned nonzero\\n"));
    return 0;
  }

  zs_s64 path_len = zs_req_path(path, sizeof(path));
  if (path_len != (zs_s64)sizeof(path)) {
    zs_respond(500, ZS_STR("truncated output length was not capped\\n"));
    return 0;
  }

  if (zs_memcmp(path, "/abcdef", 7) != 0 || path[7] != 0) {
    zs_respond(500, ZS_STR("truncated output contents mismatch\\n"));
    return 0;
  }

  zs_respond(204, ZS_STR(""));
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-cstr-return.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/abcdefghijklmnopqrstuvwxyz`);
                assertEquals(res.status, 204);
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: zs_connection_info reports tls/alpn/ech",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(join(siteDir, "index.html"), "hello\n");
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.copyFile(
                join(repoRoot, "examples", "connection_info.c"),
                join(scriptsDir, "connection_info.c"),
            );
            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/conn`);
                assertEquals(res.status, 200);
                const body = (await res.json()) as {
                    tls: boolean;
                    alpn: string | null;
                    sni: { inner: string | null; outer: string | null };
                    ech: unknown;
                    fingerprint: { ja4: string | null };
                    tls_client: {
                        certificate: unknown;
                        chain_fingerprints_sha256: string[];
                    };
                };
                assertEquals(body.tls, false);
                assertEquals(body.alpn, null);
                assertEquals(body.sni.inner, null);
                assertEquals(body.sni.outer, null);
                assertEquals(body.ech, null);
                assertEquals(body.fingerprint.ja4, null);
                assertEquals(body.tls_client.certificate, null);
                assertEquals(body.tls_client.chain_fingerprints_sha256, []);
            });

            const cert = await generateSelfSignedCert();
            try {
                await withZeroserveTls(
                    tarPath,
                    cert.certPath,
                    cert.keyPath,
                    async (_httpUrl, httpsUrl) => {
                        const caCert = await Deno.readTextFile(cert.certPath);
                        const client = Deno.createHttpClient({ caCerts: [caCert] });
                        try {
                            const res = await fetch(`${httpsUrl}/conn`, { client });
                            assertEquals(res.status, 200);
                            const body = (await res.json()) as {
                                tls: boolean;
                                ech: unknown;
                                fingerprint: { ja4: string | null };
                                tls_client: {
                                    certificate: unknown;
                                    chain_fingerprints_sha256: string[];
                                };
                            };
                            assertEquals(body.tls, true);
                            assertEquals(body.ech, null);
                            assert(body.fingerprint.ja4 !== null);
                            assert(
                                /^t[0-9sd]{2}[di][0-9]{4}[A-Za-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/
                                    .test(body.fingerprint.ja4),
                            );
                            assertEquals(body.tls_client.certificate, null);
                        } finally {
                            client.close();
                        }
                    },
                );
                await withZeroserveTls(
                    tarPath,
                    cert.certPath,
                    cert.keyPath,
                    async (_httpUrl, httpsUrl) => {
                        const caCert = await Deno.readTextFile(cert.certPath);
                        const key = await Deno.readTextFile(cert.keyPath);
                        const expectedFingerprint = await sha256Hex(pemToDerBytes(caCert));
                        const client = Deno.createHttpClient({
                            caCerts: [caCert],
                            cert: caCert,
                            key,
                        });
                        try {
                            const res = await fetch(`${httpsUrl}/conn`, { client });
                            assertEquals(res.status, 200);
                            const body = (await res.json()) as {
                                tls_client: {
                                    certificate: {
                                        fingerprint_sha256: string;
                                        subject: string;
                                        issuer: string;
                                        serial: string;
                                    } | null;
                                    chain_fingerprints_sha256: string[];
                                };
                            };
                            assertEquals(body.tls_client.certificate?.subject, "CN=localhost");
                            assertEquals(body.tls_client.certificate?.issuer, "CN=localhost");
                            assertEquals(
                                body.tls_client.certificate?.fingerprint_sha256,
                                expectedFingerprint,
                            );
                            assertEquals(
                                body.tls_client.chain_fingerprints_sha256,
                                [],
                            );
                        } finally {
                            client.close();
                        }
                    },
                );
            } finally {
                await cert.cleanup();
            }
        } finally {
            if (tarPath) await Deno.remove(tarPath).catch(() => {});
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: websocket reverse proxy",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startWebsocketBackend();
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "websocket proxy\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/socket") == 0) {
    zs_reverse_proxy(ZS_STR("${backend.httpUrl}"));
  }
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "15-ws-proxy.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const wsUrl = `${baseUrl.replace("http://", "ws://")}/socket`;
                await assertWebsocketEcho(wsUrl, "ping");
            });
        } finally {
            await backend.close().catch(() => {});
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name:
        "e2e: reverse proxy combines cookies and preserves absent Accept-Encoding",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startRawHeaderCaptureBackend();
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  zs_reverse_proxy(ZS_STR("${backend.url}"));
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "18-cookie-proxy.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                const hostname = url.hostname;
                const port = Number(url.port);
                const conn = await Deno.connect({ hostname, port });
                try {
                    const request = [
                        "GET /cookies HTTP/1.1",
                        `Host: ${hostname}:${port}`,
                        "Cookie: theme=light",
                        "Cookie: session=abc",
                        "Accept: text/plain",
                        "Connection: close",
                        "",
                        "",
                    ].join("\r\n");
                    await writeAll(conn, encoder.encode(request));
                    const { head, rest } = await readUntil(
                        conn,
                        encoder.encode("\r\n\r\n"),
                    );
                    const responseHead = decoder.decode(head);
                    assert(responseHead.startsWith("HTTP/1.1 200 "));
                    const responseBody = await readContentLengthBody(
                        conn,
                        rest,
                        2,
                    );
                    assertEquals(decoder.decode(responseBody), "ok");
                } finally {
                    conn.close();
                }

                const upstreamHead = await backend.requestHead;
                const cookieLines = upstreamHead
                    .split("\r\n")
                    .filter((line) => line.toLowerCase().startsWith("cookie:"));
                assertEquals(cookieLines, ["cookie: theme=light; session=abc"]);
                assert(
                    !upstreamHead.split("\r\n").some((line) =>
                        line.toLowerCase().startsWith("accept-encoding:")
                    ),
                    upstreamHead,
                );
            });
        } finally {
            await backend.close().catch(() => {});
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: reverse proxy chunked and fixed bodies",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startBackend(async (req) => {
            const url = new URL(req.url);
            const body = await req.text();
            const payload = JSON.stringify({
                body,
                contentLength: req.headers.get("content-length"),
                transferEncoding: req.headers.get("transfer-encoding"),
            });

            if (url.pathname === "/chunked") {
                const stream = new ReadableStream<Uint8Array>({
                    start(controller) {
                        const bytes = encoder.encode(payload);
                        const mid = Math.max(1, Math.floor(bytes.length / 2));
                        controller.enqueue(bytes.subarray(0, mid));
                        controller.enqueue(bytes.subarray(mid));
                        controller.close();
                    },
                });
                return new Response(stream, {
                    headers: { "content-type": "application/json" },
                });
            }

            return new Response(payload, {
                headers: { "content-type": "application/json" },
            });
        });

        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  zs_reverse_proxy(ZS_STR("${backend.url}"));
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "20-proxy-bodies.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                const hostname = url.hostname;
                const port = Number(url.port);

                const fixedFixed = await sendRawHttpRequest(
                    hostname,
                    port,
                    "/fixed",
                    "fixed-body",
                    false,
                );
                assertEquals(fixedFixed.status, 200);
                const fixedFixedPayload = JSON.parse(
                    decoder.decode(fixedFixed.body),
                ) as {
                    body: string;
                    contentLength: string | null;
                    transferEncoding: string | null;
                };
                assertEquals(fixedFixedPayload.body, "fixed-body");
                assertEquals(fixedFixedPayload.transferEncoding, null);
                assertEquals(fixedFixedPayload.contentLength, "10");
                assertEquals(
                    fixedFixed.headers.get("transfer-encoding"),
                    null,
                );
                assert(fixedFixed.headers.get("content-length") !== null);

                const chunkedFixed = await sendRawHttpRequest(
                    hostname,
                    port,
                    "/fixed",
                    "chunked-body",
                    true,
                );
                const chunkedFixedPayload = JSON.parse(
                    decoder.decode(chunkedFixed.body),
                ) as {
                    body: string;
                    contentLength: string | null;
                    transferEncoding: string | null;
                };
                assertEquals(chunkedFixedPayload.body, "chunked-body");
                assertEquals(chunkedFixedPayload.contentLength, null);
                assert(
                    chunkedFixedPayload.transferEncoding?.toLowerCase().includes(
                        "chunked",
                    ),
                );
                assertEquals(
                    chunkedFixed.headers.get("transfer-encoding"),
                    null,
                );
                assert(chunkedFixed.headers.get("content-length") !== null);

                const fixedChunked = await sendRawHttpRequest(
                    hostname,
                    port,
                    "/chunked",
                    "fixed-to-chunked",
                    false,
                );
                const fixedChunkedPayload = JSON.parse(
                    decoder.decode(fixedChunked.body),
                ) as {
                    body: string;
                    contentLength: string | null;
                    transferEncoding: string | null;
                };
                assertEquals(fixedChunkedPayload.body, "fixed-to-chunked");
                assertEquals(fixedChunkedPayload.transferEncoding, null);
                assertEquals(fixedChunkedPayload.contentLength, "16");
                assert(
                    fixedChunked.headers.get("transfer-encoding")?.toLowerCase()
                        .includes("chunked"),
                );
                assertEquals(fixedChunked.headers.get("content-length"), null);

                const chunkedChunked = await sendRawHttpRequest(
                    hostname,
                    port,
                    "/chunked",
                    "chunked-to-chunked",
                    true,
                );
                const chunkedChunkedPayload = JSON.parse(
                    decoder.decode(chunkedChunked.body),
                ) as {
                    body: string;
                    contentLength: string | null;
                    transferEncoding: string | null;
                };
                assertEquals(chunkedChunkedPayload.body, "chunked-to-chunked");
                assertEquals(chunkedChunkedPayload.contentLength, null);
                assert(
                    chunkedChunkedPayload.transferEncoding?.toLowerCase().includes(
                        "chunked",
                    ),
                );
                assert(
                    chunkedChunked.headers.get("transfer-encoding")?.toLowerCase()
                        .includes("chunked"),
                );
                assertEquals(chunkedChunked.headers.get("content-length"), null);
            });
        } finally {
            await backend.close().catch(() => {});
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: request mutations (set_uri, set_header)",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startBackend((req) => {
            const url = new URL(req.url);
            const payload = {
                path: url.pathname,
                query: url.search.slice(1),
                headers: {
                    "x-original": req.headers.get("x-original"),
                    "x-remove": req.headers.get("x-remove"),
                    "x-script-set": req.headers.get("x-script-set"),
                },
            };
            return new Response(JSON.stringify(payload), {
                headers: { "content-type": "application/json" },
            });
        });

        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "proxy target\n",
            );
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const backendUrl = backend.url;
            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  zs_req_set_uri(ZS_STR("/proxy/rewritten?name=changed&flag=1"));
  zs_req_set_header(ZS_STR("x-script-set"), ZS_STR("from-script"));
  zs_req_set_header(ZS_STR("x-remove"), ZS_STR(""));
  zs_reverse_proxy(ZS_STR("${backendUrl}"));
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-rewrite_proxy.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/original/path?name=orig`, {
                    headers: {
                        "x-original": "keep",
                        "x-remove": "drop",
                    },
                });
                assertEquals(res.status, 200);
                const payload = (await res.json()) as {
                    path: string;
                    query: string;
                    headers: Record<string, string | null>;
                };
                assertEquals(payload.path, "/proxy/rewritten");
                assertEquals(payload.query, "name=changed&flag=1");
                assertEquals(payload.headers["x-original"], "keep");
                assertEquals(payload.headers["x-script-set"], "from-script");
                assertEquals(payload.headers["x-remove"], null);
            });
        } finally {
            await backend.close().catch(() => {});
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: metadata response headers",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startBackend(() => {
            return new Response("proxied", {
                headers: { "content-type": "text/plain" },
            });
        });

        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "static.txt"),
                "static ok\n",
            );
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const backendUrl = backend.url;
            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  const char *header_key = "zs.response.header.x-test";
  const char *header_value = "meta";
  zs_meta_set(
    ZS_STR(header_key),
    ZS_STR(header_value)
  );

  char path[64];
  zs_req_path(path, sizeof(path));

  if (zs_strcmp(path, "/respond") == 0) {
    zs_respond(201, ZS_STR("script response"));
    return 0;
  }

  if (zs_strcmp(path, "/proxy") == 0) {
    zs_reverse_proxy(ZS_STR("${backendUrl}"));
    return 0;
  }

  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-response-headers.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const staticRes = await fetch(`${baseUrl}/static.txt`);
                assertEquals(staticRes.status, 200);
                assertEquals(staticRes.headers.get("x-test"), "meta");
                assertEquals(await staticRes.text(), "static ok\n");

                const scriptRes = await fetch(`${baseUrl}/respond`);
                assertEquals(scriptRes.status, 201);
                assertEquals(scriptRes.headers.get("x-test"), "meta");
                assertEquals(await scriptRes.text(), "script response");

                const proxyRes = await fetch(`${baseUrl}/proxy`);
                assertEquals(proxyRes.status, 200);
                assertEquals(proxyRes.headers.get("x-test"), "meta");
                assertEquals(await proxyRes.text(), "proxied");
            });
        } finally {
            await backend.close().catch(() => {});
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: crypto helpers",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "crypto helpers\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = String.raw`#include <zeroserve.h>

static int base64_roundtrip(const char *input, zs_u64 input_len, zs_u64 encoding) {
  char buf[64];
  zs_s64 enc_len = zs_base64_encode(input, input_len, buf, sizeof(buf), encoding);
  if (enc_len <= 0) return 0;
  zs_s64 dec_len = zs_base64_decode_in_place(buf, enc_len, encoding);
  if (dec_len != (zs_s64)input_len) return 0;
  if (zs_memcmp(buf, input, input_len) != 0) return 0;
  return 1;
}

static int base64_expected(void) {
  zs_u8 bytes[3] = {0xff, 0xff, 0xff};
  char buf[8];
  zs_s64 len = zs_base64_encode(bytes, sizeof(bytes), buf, sizeof(buf), ZS_BASE64_STANDARD);
  if (len != 4 || zs_memcmp(buf, "////", 4) != 0) return 0;
  len = zs_base64_encode(bytes, sizeof(bytes), buf, sizeof(buf), ZS_BASE64_URL);
  if (len != 4 || zs_memcmp(buf, "____", 4) != 0) return 0;

  const char hi[] = "hi";
  len = zs_base64_encode(hi, sizeof(hi) - 1, buf, sizeof(buf), ZS_BASE64_STANDARD);
  if (len != 4 || zs_memcmp(buf, "aGk=", 4) != 0) return 0;
  len = zs_base64_encode(hi, sizeof(hi) - 1, buf, sizeof(buf), ZS_BASE64_STANDARD_NO_PAD);
  if (len != 3 || zs_memcmp(buf, "aGk", 3) != 0) return 0;
  len = zs_base64_encode(hi, sizeof(hi) - 1, buf, sizeof(buf), ZS_BASE64_URL_NO_PAD);
  if (len != 3 || zs_memcmp(buf, "aGk", 3) != 0) return 0;

  return 1;
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/crypto") != 0) {
    return 0;
  }

  zs_u8 digest[32];
  zs_hmac_sha256(ZS_STR("supersecret"), ZS_STR("hello"), digest);

  char hmac_b64[64];
  zs_s64 hmac_len = zs_base64_encode(digest, sizeof(digest), hmac_b64, sizeof(hmac_b64), ZS_BASE64_STANDARD);

  zs_u8 rand_bytes[32];
  zs_s64 rand_len = zs_getrandom(rand_bytes, sizeof(rand_bytes));
  char rand_b64[64];
  zs_s64 rand_b64_len = zs_base64_encode(rand_bytes, rand_len, rand_b64, sizeof(rand_b64), ZS_BASE64_STANDARD);

  int ok = 1;
  if (hmac_len <= 0 || rand_len != (zs_s64)sizeof(rand_bytes) || rand_b64_len <= 0) ok = 0;
  if (!base64_roundtrip("hello", sizeof("hello") - 1, ZS_BASE64_STANDARD)) ok = 0;
  if (!base64_roundtrip("hello", sizeof("hello") - 1, ZS_BASE64_STANDARD_NO_PAD)) ok = 0;
  if (!base64_roundtrip("hello", sizeof("hello") - 1, ZS_BASE64_URL)) ok = 0;
  if (!base64_roundtrip("hello", sizeof("hello") - 1, ZS_BASE64_URL_NO_PAD)) ok = 0;
  if (!base64_expected()) ok = 0;

  char body[256];
  char *bp = zs_stpcpy(body, "{\"hmac_b64\":\"");
  zs_memcpy(bp, hmac_b64, hmac_len);
  bp += hmac_len;
  bp = zs_stpcpy(bp, "\",\"rand_b64\":\"");
  zs_memcpy(bp, rand_b64, rand_b64_len);
  bp += rand_b64_len;
  bp = zs_stpcpy(bp, "\",\"base64_ok\":");
  bp += zs_utoa10(ok, bp, 8);
  bp = zs_stpcpy(bp, "}\n");

  zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("application/json"));
  zs_respond(200, body, bp - body);
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "10-crypto-helpers.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/crypto`);
                assertEquals(res.status, 200);
                const payload = (await res.json()) as {
                    hmac_b64: string;
                    rand_b64: string;
                    base64_ok: number;
                };

                const key = await crypto.subtle.importKey(
                    "raw",
                    new TextEncoder().encode("supersecret"),
                    { name: "HMAC", hash: "SHA-256" },
                    false,
                    ["sign"],
                );
                const signature = new Uint8Array(
                    await crypto.subtle.sign(
                        "HMAC",
                        key,
                        new TextEncoder().encode("hello"),
                    ),
                );
                const expectedHmac = bytesToBase64(signature);
                assertEquals(payload.hmac_b64, expectedHmac);
                assertEquals(payload.base64_ok, 1);
                assertEquals(payload.rand_b64.length, 44);
                assert(payload.rand_b64.endsWith("="));
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: json helpers",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "json helpers\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = String.raw`#include <zeroserve.h>

static int check_json(zs_u64 root) {
  zs_s64 name_h = zs_json_get(root, ZS_STR("name"));
  if (name_h == -1) return 0;

  char name[16];
  zs_s64 zero_len = zs_json_read_string(name_h, name, 0);
  if (zero_len != 0) return 0;
  zs_s64 name_len = zs_json_read_string(name_h, name, sizeof(name));
  if (name_len != 3) return 0;
  if (zs_memcmp(name, "Ada", 3) != 0) return 0;

  zs_s64 active_h = zs_json_get(root, ZS_STR("active"));
  if (active_h == -1) return 0;
  zs_u8 active = 0;
  zs_s64 active_len = zs_json_read_bool(active_h, &active, sizeof(active));
  if (active_len != 1 || active != 1) return 0;

  zs_s64 count_h = zs_json_get(root, ZS_STR("count"));
  if (count_h == -1) return 0;
  zs_s64 count = 0;
  zs_s64 count_len = zs_json_read_i64(count_h, &count, sizeof(count));
  if (count_len != (zs_s64)sizeof(count) || count != 42) return 0;

  zs_s64 delta_h = zs_json_get(root, ZS_STR("delta"));
  if (delta_h == -1) return 0;
  zs_s64 delta = 0;
  zs_s64 delta_len = zs_json_read_i64(delta_h, &delta, sizeof(delta));
  if (delta_len != (zs_s64)sizeof(delta) || delta != -7) return 0;

  zs_s64 nested_h = zs_json_get(root, ZS_STR("nested"));
  if (nested_h == -1) return 0;
  zs_s64 flag_h = zs_json_get(nested_h, ZS_STR("flag"));
  if (flag_h == -1) return 0;
  zs_u8 flag = 1;
  zs_s64 flag_len = zs_json_read_bool(flag_h, &flag, sizeof(flag));
  if (flag_len != 1 || flag != 0) return 0;

  zs_s64 tag_h = zs_json_get(nested_h, ZS_STR("tag"));
  if (tag_h == -1) return 0;
  char tag[16];
  zs_s64 tag_len = zs_json_read_string(tag_h, tag, sizeof(tag));
  if (tag_len != 5 || zs_memcmp(tag, "hello", 5) != 0) return 0;

  if (zs_json_reset(nested_h) != 0) return 0;
  zs_s64 reset_name_h = zs_json_get(nested_h, ZS_STR("name"));
  if (reset_name_h == -1) return 0;
  char name2[16];
  zs_s64 name2_len = zs_json_read_string(reset_name_h, name2, sizeof(name2));
  if (name2_len != 3 || zs_memcmp(name2, "Ada", 3) != 0) return 0;

  if (zs_json_get(root, ZS_STR("missing")) != -1) return 0;

  int ok = 1;
  zs_object_free(name_h);
  zs_object_free(active_h);
  zs_object_free(count_h);
  zs_object_free(delta_h);
  zs_object_free(flag_h);
  zs_object_free(tag_h);
  zs_object_free(reset_name_h);
  zs_object_free(nested_h);
  zs_object_free(root);
  return ok;
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/json") != 0) {
    return 0;
  }

  char payload[256];
  zs_req_header(ZS_STR("x-json"), payload, sizeof(payload));
  zs_u64 payload_len = zs_strlen(payload);
  if (payload_len == 0) {
    zs_respond(400, ZS_STR("missing json\n"));
    return 0;
  }

  zs_s64 root = zs_json_parse(payload, payload_len);
  if (root == -1) {
    zs_respond(400, ZS_STR("parse failed\n"));
    return 0;
  }

  if (!check_json(root)) {
    zs_respond(500, ZS_STR("json helpers failed\n"));
    return 0;
  }

  zs_respond(200, ZS_STR("ok\n"));
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "12-json-helpers.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const payload =
                    '{"name":"Ada","active":true,"count":42,"delta":-7,"nested":{"flag":false,"tag":"hello"}}';

                const okRes = await fetch(`${baseUrl}/json`, {
                    headers: { "x-json": payload },
                });
                assertEquals(okRes.status, 200);
                assertEquals(await okRes.text(), "ok\n");

                const badRes = await fetch(`${baseUrl}/json`, {
                    headers: { "x-json": "{not-json}" },
                });
                assertEquals(badRes.status, 400);
                assertEquals(await badRes.text(), "parse failed\n");
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: load static json helper",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "static json helper\n",
            );

            const dataDir = join(siteDir, "data");
            await Deno.mkdir(dataDir, { recursive: true });
            const configJson = '{"name":"Ada","enabled":true,"count":3}';
            const configPath = join(dataDir, "config.json");
            await Deno.writeTextFile(configPath, configJson);
            const expectedMtime = 1_700_000_000;
            const expectedMtimeDate = new Date(expectedMtime * 1000);
            await Deno.utime(configPath, expectedMtimeDate, expectedMtimeDate);
            const expectedSize = encoder.encode(configJson).length;

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = String.raw`#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/static-json") != 0) {
    return 0;
  }

  zs_s64 bad_meta = zs_load_file_metadata(ZS_STR("/data/config.json"));
  if (bad_meta != -1) {
    zs_object_free(bad_meta);
    zs_respond(500, ZS_STR("meta path normalization\n"));
    return 0;
  }

  zs_s64 meta = zs_load_file_metadata(ZS_STR("data/config.json"));
  if (meta == -1) {
    zs_respond(500, ZS_STR("meta load failed\n"));
    return 0;
  }

  zs_s64 size_h = zs_json_get(meta, ZS_STR("size"));
  if (size_h == -1) {
    zs_respond(500, ZS_STR("missing size\n"));
    return 0;
  }
  zs_s64 size = 0;
  zs_s64 size_len = zs_json_read_i64(size_h, &size, sizeof(size));
  if (size_len != (zs_s64)sizeof(size) || size != ${expectedSize}) {
    zs_respond(500, ZS_STR("bad size\n"));
    return 0;
  }

  zs_s64 mtime_h = zs_json_get(meta, ZS_STR("mtime"));
  if (mtime_h == -1) {
    zs_respond(500, ZS_STR("missing mtime\n"));
    return 0;
  }
  zs_s64 mtime = 0;
  zs_s64 mtime_len = zs_json_read_i64(mtime_h, &mtime, sizeof(mtime));
  if (mtime_len != (zs_s64)sizeof(mtime) || mtime != ${expectedMtime}) {
    zs_respond(500, ZS_STR("bad mtime\n"));
    return 0;
  }

  zs_s64 etag_h = zs_json_get(meta, ZS_STR("etag"));
  if (etag_h == -1) {
    zs_respond(500, ZS_STR("missing etag\n"));
    return 0;
  }
  char etag[64];
  zs_s64 etag_len = zs_json_read_string(etag_h, etag, sizeof(etag));
  if (etag_len != 32) {
    zs_respond(500, ZS_STR("bad etag length\n"));
    return 0;
  }
  for (int i = 0; i < 32; i++) {
    char c = etag[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      zs_respond(500, ZS_STR("bad etag chars\n"));
      return 0;
    }
  }

  zs_s64 bad = zs_load_static_json(ZS_STR("/data/config.json"));
  if (bad != -1) {
    zs_object_free(bad);
    zs_respond(500, ZS_STR("path normalization\n"));
    return 0;
  }

  zs_s64 root = zs_load_static_json(ZS_STR("data/config.json"));
  if (root == -1) {
    zs_respond(500, ZS_STR("load failed\n"));
    return 0;
  }

  zs_s64 name_h = zs_json_get(root, ZS_STR("name"));
  if (name_h == -1) {
    zs_respond(500, ZS_STR("missing name\n"));
    return 0;
  }
  char name[8];
  zs_s64 name_len = zs_json_read_string(name_h, name, sizeof(name));
  if (name_len != 3 || zs_memcmp(name, "Ada", 3) != 0) {
    zs_respond(500, ZS_STR("bad name\n"));
    return 0;
  }

  zs_s64 enabled_h = zs_json_get(root, ZS_STR("enabled"));
  if (enabled_h == -1) {
    zs_respond(500, ZS_STR("missing enabled\n"));
    return 0;
  }
  zs_u8 enabled = 0;
  zs_s64 enabled_len = zs_json_read_bool(enabled_h, &enabled, sizeof(enabled));
  if (enabled_len != 1 || enabled != 1) {
    zs_respond(500, ZS_STR("bad enabled\n"));
    return 0;
  }

  zs_s64 count_h = zs_json_get(root, ZS_STR("count"));
  if (count_h == -1) {
    zs_respond(500, ZS_STR("missing count\n"));
    return 0;
  }
  zs_s64 count = 0;
  zs_s64 count_len = zs_json_read_i64(count_h, &count, sizeof(count));
  if (count_len != (zs_s64)sizeof(count) || count != 3) {
    zs_respond(500, ZS_STR("bad count\n"));
    return 0;
  }

  zs_object_free(name_h);
  zs_object_free(enabled_h);
  zs_object_free(count_h);
  zs_object_free(root);
  zs_object_free(size_h);
  zs_object_free(mtime_h);
  zs_object_free(etag_h);
  zs_object_free(meta);

  zs_respond(200, ZS_STR("ok\n"));
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "13-load-static-json.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/static-json`);
                assertEquals(res.status, 200);
                assertEquals(await res.text(), "ok\n");
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: jwt helpers",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "jwt helpers\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = String.raw`#include <zeroserve.h>

static int verify_jwt(const char *token, const char *secret, const char *expected_payload, zs_u64 expected_len, char *out, zs_u64 out_len, zs_u64 *decoded_len) {
  zs_u64 header_len = 0;
  zs_u64 payload_len = 0;
  zs_u64 sig_len = 0;

  while (token[header_len] != '\0' && token[header_len] != '.') header_len++;
  if (token[header_len] != '.') return 0;
  const char *payload = token + header_len + 1;
  while (payload[payload_len] != '\0' && payload[payload_len] != '.') payload_len++;
  if (payload[payload_len] != '.') return 0;
  const char *sig = payload + payload_len + 1;
  while (sig[sig_len] != '\0') sig_len++;
  if (sig_len == 0) return 0;

  zs_u8 digest[32];
  zs_u64 msg_len = header_len + 1 + payload_len;
  zs_hmac_sha256(secret, zs_strlen(secret), token, msg_len, digest);

  char sig_b64[64];
  zs_s64 sig_b64_len = zs_base64_encode(digest, sizeof(digest), sig_b64, sizeof(sig_b64), ZS_BASE64_URL_NO_PAD);
  if (sig_b64_len <= 0 || (zs_u64)sig_b64_len != sig_len) return 0;
  if (zs_memcmp(sig_b64, sig, sig_len) != 0) return 0;

  if (payload_len >= out_len) return 0;
  zs_memcpy(out, payload, payload_len);
  zs_s64 decoded = zs_base64_decode_in_place(out, payload_len, ZS_BASE64_URL_NO_PAD);
  if (decoded <= 0) return 0;
  if ((zs_u64)decoded != expected_len) return 0;
  if (zs_memcmp(out, expected_payload, expected_len) != 0) return 0;
  *decoded_len = (zs_u64)decoded;
  return 1;
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/jwt") != 0) {
    return 0;
  }

  char auth[512];
  zs_req_header(ZS_STR("authorization"), auth, sizeof(auth));
  if (zs_strncmp(auth, "Bearer ", 7) != 0) {
    zs_respond(401, ZS_STR("missing bearer token\n"));
    return 0;
  }

  const char *token = auth + 7;
  const char expected_payload[] = "{\"sub\":\"1234567890\",\"name\":\"Ada Lovelace\",\"admin\":true}";
  char payload_buf[256];
  zs_u64 decoded_len = 0;
  int ok = verify_jwt(token, "jwtsecret", expected_payload, sizeof(expected_payload) - 1, payload_buf, sizeof(payload_buf), &decoded_len);
  if (!ok) {
    zs_respond(401, ZS_STR("invalid token\n"));
    return 0;
  }

  zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("application/json"));
  zs_respond(200, payload_buf, decoded_len);
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "11-jwt-helpers.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const headerJson = '{"alg":"HS256","typ":"JWT"}';
                const payloadJson =
                    '{"sub":"1234567890","name":"Ada Lovelace","admin":true}';
                const headerB64 = bytesToBase64Url(encoder.encode(headerJson));
                const payloadB64 = bytesToBase64Url(
                    encoder.encode(payloadJson),
                );
                const signingInput = `${headerB64}.${payloadB64}`;

                const key = await crypto.subtle.importKey(
                    "raw",
                    encoder.encode("jwtsecret"),
                    { name: "HMAC", hash: "SHA-256" },
                    false,
                    ["sign"],
                );
                const signature = new Uint8Array(
                    await crypto.subtle.sign(
                        "HMAC",
                        key,
                        encoder.encode(signingInput),
                    ),
                );

                {
                    const token = `${signingInput}.${bytesToBase64Url(signature)}`;
                    const res = await fetch(`${baseUrl}/jwt`, {
                        headers: {
                            authorization: `Bearer ${token}`,
                        },
                    });
                    assertEquals(res.status, 200);
                    assertEquals(await res.text(), payloadJson);
                }

                {
                    signature[0] ^= 0xff;
                    const token = `${signingInput}.${bytesToBase64Url(signature)}`;
                    const res = await fetch(`${baseUrl}/jwt`, {
                        headers: {
                            authorization: `Bearer ${token}`,
                        },
                    });
                    assertEquals(res.status, 401);
                    assertEquals(await res.text(), "invalid token\n");
                }
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: sha256 helper",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "sha256 helper\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = String.raw`#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/sha256") != 0) {
    return 0;
  }

  const char *input = "hello world";
  zs_u8 digest[32];
  zs_s64 ret = zs_sha256(input, zs_strlen(input), digest, sizeof(digest));
  if (ret != 32) {
    zs_respond(500, ZS_STR("sha256 failed\n"));
    return 0;
  }

  char digest_b64[64];
  zs_s64 b64_len = zs_base64_encode(digest, sizeof(digest), digest_b64, sizeof(digest_b64), ZS_BASE64_STANDARD);

  char body[128];
  char *bp = zs_stpcpy(body, "{\"sha256_b64\":\"");
  zs_memcpy(bp, digest_b64, b64_len);
  bp += b64_len;
  bp = zs_stpcpy(bp, "\"}\n");

  zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("application/json"));
  zs_respond(200, body, bp - body);
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "10-sha256-helper.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/sha256`);
                assertEquals(res.status, 200);
                const payload = (await res.json()) as {
                    sha256_b64: string;
                };

                const expectedDigest = new Uint8Array(
                    await crypto.subtle.digest(
                        "SHA-256",
                        new TextEncoder().encode("hello world"),
                    ),
                );
                const expectedB64 = bytesToBase64(expectedDigest);
                assertEquals(payload.sha256_b64, expectedB64);
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: json creation and modification helpers",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "json modification helpers\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = String.raw`#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));

  if (zs_strcmp(path, "/json/new-object") == 0) {
    zs_s64 obj = zs_json_new_object();
    if (obj < 0) {
      zs_respond(500, ZS_STR("new_object failed\n"));
      return 0;
    }
    zs_s64 type = zs_json_type(obj);
    zs_s64 len = zs_json_len(obj);
    if (type != 5 || len != 0) {
      zs_respond(500, ZS_STR("wrong type/len\n"));
      return 0;
    }
    zs_object_free(obj);
    zs_respond(200, ZS_STR("ok\n"));
    return 0;
  }

  if (zs_strcmp(path, "/json/new-array") == 0) {
    zs_s64 arr = zs_json_new_array();
    if (arr < 0) {
      zs_respond(500, ZS_STR("new_array failed\n"));
      return 0;
    }
    zs_s64 type = zs_json_type(arr);
    zs_s64 len = zs_json_len(arr);
    if (type != 4 || len != 0) {
      zs_respond(500, ZS_STR("wrong type/len\n"));
      return 0;
    }
    zs_object_free(arr);
    zs_respond(200, ZS_STR("ok\n"));
    return 0;
  }

  if (zs_strcmp(path, "/json/set-fields") == 0) {
    zs_s64 obj = zs_json_new_object();
    if (obj < 0) {
      zs_respond(500, ZS_STR("new_object failed\n"));
      return 0;
    }

    // Create and set a string value
    zs_s64 str_val = zs_json_parse(ZS_STR("\"hello\""));
    if (str_val < 0) {
      zs_respond(500, ZS_STR("parse string failed\n"));
      return 0;
    }
    if (zs_json_set(obj, ZS_STR("greeting"), str_val) != 0) {
      zs_respond(500, ZS_STR("set greeting failed\n"));
      return 0;
    }
    zs_object_free(str_val);

    // Create and set a number value
    zs_s64 num_val = zs_json_parse(ZS_STR("42"));
    if (num_val < 0) {
      zs_respond(500, ZS_STR("parse number failed\n"));
      return 0;
    }
    if (zs_json_set(obj, ZS_STR("count"), num_val) != 0) {
      zs_respond(500, ZS_STR("set count failed\n"));
      return 0;
    }
    zs_object_free(num_val);

    // Verify length is now 2
    if (zs_json_len(obj) != 2) {
      zs_respond(500, ZS_STR("wrong len after set\n"));
      return 0;
    }

    // Verify we can read the values back
    zs_s64 greeting_h = zs_json_get(obj, ZS_STR("greeting"));
    if (greeting_h < 0) {
      zs_respond(500, ZS_STR("get greeting failed\n"));
      return 0;
    }
    char greeting[16];
    if (zs_json_read_string(greeting_h, greeting, sizeof(greeting)) != 5) {
      zs_respond(500, ZS_STR("read greeting failed\n"));
      return 0;
    }
    if (zs_memcmp(greeting, "hello", 5) != 0) {
      zs_respond(500, ZS_STR("greeting mismatch\n"));
      return 0;
    }
    zs_object_free(greeting_h);
    zs_object_free(obj);
    zs_respond(200, ZS_STR("ok\n"));
    return 0;
  }

  if (zs_strcmp(path, "/json/remove-field") == 0) {
    zs_s64 obj = zs_json_parse(ZS_STR("{\"a\":1,\"b\":2,\"c\":3}"));
    if (obj < 0) {
      zs_respond(500, ZS_STR("parse failed\n"));
      return 0;
    }
    if (zs_json_len(obj) != 3) {
      zs_respond(500, ZS_STR("initial len wrong\n"));
      return 0;
    }
    if (zs_json_remove(obj, ZS_STR("b")) != 0) {
      zs_respond(500, ZS_STR("remove failed\n"));
      return 0;
    }
    if (zs_json_len(obj) != 2) {
      zs_respond(500, ZS_STR("len after remove wrong\n"));
      return 0;
    }
    // Verify b is gone
    if (zs_json_get(obj, ZS_STR("b")) != -1) {
      zs_respond(500, ZS_STR("b still exists\n"));
      return 0;
    }
    // Verify a and c still exist
    zs_s64 a_h = zs_json_get(obj, ZS_STR("a"));
    zs_s64 c_h = zs_json_get(obj, ZS_STR("c"));
    if (a_h < 0 || c_h < 0) {
      zs_respond(500, ZS_STR("a or c missing\n"));
      return 0;
    }
    zs_object_free(a_h);
    zs_object_free(c_h);
    // Remove non-existent key should return -1
    if (zs_json_remove(obj, ZS_STR("missing")) != -1) {
      zs_respond(500, ZS_STR("remove missing should fail\n"));
      return 0;
    }
    zs_object_free(obj);
    zs_respond(200, ZS_STR("ok\n"));
    return 0;
  }

  if (zs_strcmp(path, "/json/array-push") == 0) {
    zs_s64 arr = zs_json_new_array();
    if (arr < 0) {
      zs_respond(500, ZS_STR("new_array failed\n"));
      return 0;
    }

    zs_s64 val1 = zs_json_parse(ZS_STR("\"first\""));
    zs_s64 val2 = zs_json_parse(ZS_STR("\"second\""));
    zs_s64 val3 = zs_json_parse(ZS_STR("\"third\""));

    zs_s64 len1 = zs_json_array_push(arr, val1);
    zs_s64 len2 = zs_json_array_push(arr, val2);
    zs_s64 len3 = zs_json_array_push(arr, val3);

    if (len1 != 1 || len2 != 2 || len3 != 3) {
      zs_respond(500, ZS_STR("push lengths wrong\n"));
      return 0;
    }

    zs_object_free(val1);
    zs_object_free(val2);
    zs_object_free(val3);

    // Verify array contents
    zs_s64 elem0 = zs_json_array_get(arr, 0);
    zs_s64 elem2 = zs_json_array_get(arr, 2);
    char buf[16];
    if (zs_json_read_string(elem0, buf, sizeof(buf)) != 5 || zs_memcmp(buf, "first", 5) != 0) {
      zs_respond(500, ZS_STR("elem0 wrong\n"));
      return 0;
    }
    if (zs_json_read_string(elem2, buf, sizeof(buf)) != 5 || zs_memcmp(buf, "third", 5) != 0) {
      zs_respond(500, ZS_STR("elem2 wrong\n"));
      return 0;
    }
    zs_object_free(elem0);
    zs_object_free(elem2);
    zs_object_free(arr);
    zs_respond(200, ZS_STR("ok\n"));
    return 0;
  }

  if (zs_strcmp(path, "/json/array-set") == 0) {
    zs_s64 arr = zs_json_parse(ZS_STR("[\"a\",\"b\",\"c\"]"));
    if (arr < 0) {
      zs_respond(500, ZS_STR("parse failed\n"));
      return 0;
    }

    zs_s64 new_val = zs_json_parse(ZS_STR("\"replaced\""));
    if (zs_json_array_set(arr, 1, new_val) != 0) {
      zs_respond(500, ZS_STR("array_set failed\n"));
      return 0;
    }
    zs_object_free(new_val);

    // Verify element was replaced
    zs_s64 elem1 = zs_json_array_get(arr, 1);
    char buf[16];
    if (zs_json_read_string(elem1, buf, sizeof(buf)) != 8 || zs_memcmp(buf, "replaced", 8) != 0) {
      zs_respond(500, ZS_STR("replacement wrong\n"));
      return 0;
    }
    zs_object_free(elem1);

    // Out of bounds should fail
    zs_s64 oob_val = zs_json_parse(ZS_STR("\"oob\""));
    if (zs_json_array_set(arr, 10, oob_val) != -1) {
      zs_respond(500, ZS_STR("oob should fail\n"));
      return 0;
    }
    zs_object_free(oob_val);
    zs_object_free(arr);
    zs_respond(200, ZS_STR("ok\n"));
    return 0;
  }

  if (zs_strcmp(path, "/json/set-primitives") == 0) {
    zs_s64 obj = zs_json_new_object();

    // Set string
    zs_s64 s = zs_json_parse(ZS_STR("null"));
    zs_json_set_string(s, ZS_STR("hello world"));
    if (zs_json_type(s) != 3) {
      zs_respond(500, ZS_STR("set_string type wrong\n"));
      return 0;
    }
    zs_json_set(obj, ZS_STR("str"), s);
    zs_object_free(s);

    // Set i64
    zs_s64 n = zs_json_parse(ZS_STR("null"));
    zs_json_set_i64(n, -12345);
    if (zs_json_type(n) != 2) {
      zs_respond(500, ZS_STR("set_i64 type wrong\n"));
      return 0;
    }
    zs_json_set(obj, ZS_STR("num"), n);
    zs_object_free(n);

    // Set bool true
    zs_s64 bt = zs_json_parse(ZS_STR("null"));
    zs_json_set_bool(bt, 1);
    if (zs_json_type(bt) != 1) {
      zs_respond(500, ZS_STR("set_bool type wrong\n"));
      return 0;
    }
    zs_json_set(obj, ZS_STR("flag_true"), bt);
    zs_object_free(bt);

    // Set bool false
    zs_s64 bf = zs_json_parse(ZS_STR("null"));
    zs_json_set_bool(bf, 0);
    zs_json_set(obj, ZS_STR("flag_false"), bf);
    zs_object_free(bf);

    // Set null
    zs_s64 nl = zs_json_parse(ZS_STR("123"));
    zs_json_set_null(nl);
    if (zs_json_type(nl) != 0) {
      zs_respond(500, ZS_STR("set_null type wrong\n"));
      return 0;
    }
    zs_json_set(obj, ZS_STR("nothing"), nl);
    zs_object_free(nl);

    // Verify values
    zs_s64 str_h = zs_json_get(obj, ZS_STR("str"));
    char str_buf[32];
    if (zs_json_read_string(str_h, str_buf, sizeof(str_buf)) != 11) {
      zs_respond(500, ZS_STR("str len wrong\n"));
      return 0;
    }
    zs_object_free(str_h);

    zs_s64 num_h = zs_json_get(obj, ZS_STR("num"));
    zs_s64 num_val = 0;
    zs_json_read_i64(num_h, &num_val, sizeof(num_val));
    if (num_val != -12345) {
      zs_respond(500, ZS_STR("num val wrong\n"));
      return 0;
    }
    zs_object_free(num_h);

    zs_s64 ft_h = zs_json_get(obj, ZS_STR("flag_true"));
    zs_u8 ft_val = 0;
    zs_json_read_bool(ft_h, &ft_val, 1);
    if (ft_val != 1) {
      zs_respond(500, ZS_STR("flag_true wrong\n"));
      return 0;
    }
    zs_object_free(ft_h);

    zs_s64 ff_h = zs_json_get(obj, ZS_STR("flag_false"));
    zs_u8 ff_val = 1;
    zs_json_read_bool(ff_h, &ff_val, 1);
    if (ff_val != 0) {
      zs_respond(500, ZS_STR("flag_false wrong\n"));
      return 0;
    }
    zs_object_free(ff_h);

    zs_s64 null_h = zs_json_get(obj, ZS_STR("nothing"));
    if (zs_json_type(null_h) != 0) {
      zs_respond(500, ZS_STR("nothing type wrong\n"));
      return 0;
    }
    zs_object_free(null_h);

    zs_object_free(obj);
    zs_respond(200, ZS_STR("ok\n"));
    return 0;
  }

  if (zs_strcmp(path, "/json/clone") == 0) {
    zs_s64 orig = zs_json_parse(ZS_STR("{\"x\":1,\"y\":2}"));
    if (orig < 0) {
      zs_respond(500, ZS_STR("parse failed\n"));
      return 0;
    }

    zs_s64 clone = zs_json_clone(orig);
    if (clone < 0) {
      zs_respond(500, ZS_STR("clone failed\n"));
      return 0;
    }

    // Modify the clone
    zs_s64 new_val = zs_json_parse(ZS_STR("999"));
    zs_json_set(clone, ZS_STR("x"), new_val);
    zs_object_free(new_val);

    // Original should be unchanged
    zs_s64 orig_x = zs_json_get(orig, ZS_STR("x"));
    zs_s64 orig_x_val = 0;
    zs_json_read_i64(orig_x, &orig_x_val, sizeof(orig_x_val));
    if (orig_x_val != 1) {
      zs_respond(500, ZS_STR("original modified\n"));
      return 0;
    }
    zs_object_free(orig_x);

    // Clone should have new value
    zs_s64 clone_x = zs_json_get(clone, ZS_STR("x"));
    zs_s64 clone_x_val = 0;
    zs_json_read_i64(clone_x, &clone_x_val, sizeof(clone_x_val));
    if (clone_x_val != 999) {
      zs_respond(500, ZS_STR("clone not modified\n"));
      return 0;
    }
    zs_object_free(clone_x);

    zs_object_free(orig);
    zs_object_free(clone);
    zs_respond(200, ZS_STR("ok\n"));
    return 0;
  }

  if (zs_strcmp(path, "/json/type-and-len") == 0) {
    // Test all types
    zs_s64 null_j = zs_json_parse(ZS_STR("null"));
    zs_s64 bool_j = zs_json_parse(ZS_STR("true"));
    zs_s64 num_j = zs_json_parse(ZS_STR("42"));
    zs_s64 str_j = zs_json_parse(ZS_STR("\"hello\""));
    zs_s64 arr_j = zs_json_parse(ZS_STR("[1,2,3]"));
    zs_s64 obj_j = zs_json_parse(ZS_STR("{\"a\":1}"));

    if (zs_json_type(null_j) != 0) { zs_respond(500, ZS_STR("null type\n")); return 0; }
    if (zs_json_type(bool_j) != 1) { zs_respond(500, ZS_STR("bool type\n")); return 0; }
    if (zs_json_type(num_j) != 2) { zs_respond(500, ZS_STR("num type\n")); return 0; }
    if (zs_json_type(str_j) != 3) { zs_respond(500, ZS_STR("str type\n")); return 0; }
    if (zs_json_type(arr_j) != 4) { zs_respond(500, ZS_STR("arr type\n")); return 0; }
    if (zs_json_type(obj_j) != 5) { zs_respond(500, ZS_STR("obj type\n")); return 0; }

    // Test lengths
    if (zs_json_len(str_j) != 5) { zs_respond(500, ZS_STR("str len\n")); return 0; }
    if (zs_json_len(arr_j) != 3) { zs_respond(500, ZS_STR("arr len\n")); return 0; }
    if (zs_json_len(obj_j) != 1) { zs_respond(500, ZS_STR("obj len\n")); return 0; }
    // Null, bool, number should return -1 for len
    if (zs_json_len(null_j) != (zs_s64)-1) { zs_respond(500, ZS_STR("null len\n")); return 0; }
    if (zs_json_len(bool_j) != (zs_s64)-1) { zs_respond(500, ZS_STR("bool len\n")); return 0; }
    if (zs_json_len(num_j) != (zs_s64)-1) { zs_respond(500, ZS_STR("num len\n")); return 0; }

    zs_object_free(null_j);
    zs_object_free(bool_j);
    zs_object_free(num_j);
    zs_object_free(str_j);
    zs_object_free(arr_j);
    zs_object_free(obj_j);
    zs_respond(200, ZS_STR("ok\n"));
    return 0;
  }

  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "15-json-modification.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const endpoints = [
                    "/json/new-object",
                    "/json/new-array",
                    "/json/set-fields",
                    "/json/remove-field",
                    "/json/array-push",
                    "/json/array-set",
                    "/json/set-primitives",
                    "/json/clone",
                    "/json/type-and-len",
                ];

                for (const endpoint of endpoints) {
                    const res = await fetch(`${baseUrl}${endpoint}`);
                    const text = await res.text();
                    assertEquals(
                        res.status,
                        200,
                        `${endpoint} failed: ${text}`,
                    );
                    assertEquals(text, "ok\n");
                }
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: json respond helper",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "json respond helper\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = String.raw`#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));

  if (zs_strcmp(path, "/json/respond-simple") == 0) {
    zs_s64 obj = zs_json_new_object();

    zs_s64 status = zs_json_parse(ZS_STR("\"ok\""));
    zs_json_set(obj, ZS_STR("status"), status);
    zs_object_free(status);

    zs_s64 code = zs_json_parse(ZS_STR("0"));
    zs_json_set_i64(code, 200);
    zs_json_set(obj, ZS_STR("code"), code);
    zs_object_free(code);

    zs_json_respond(200, obj);
    zs_object_free(obj);
    return 0;
  }

  if (zs_strcmp(path, "/json/respond-nested") == 0) {
    zs_s64 root = zs_json_new_object();

    // Create nested object
    zs_s64 user = zs_json_new_object();
    zs_s64 name = zs_json_parse(ZS_STR("\"Alice\""));
    zs_json_set(user, ZS_STR("name"), name);
    zs_object_free(name);

    zs_s64 age = zs_json_parse(ZS_STR("0"));
    zs_json_set_i64(age, 30);
    zs_json_set(user, ZS_STR("age"), age);
    zs_object_free(age);

    zs_json_set(root, ZS_STR("user"), user);
    zs_object_free(user);

    // Create array of tags
    zs_s64 tags = zs_json_new_array();
    zs_s64 tag1 = zs_json_parse(ZS_STR("\"admin\""));
    zs_s64 tag2 = zs_json_parse(ZS_STR("\"verified\""));
    zs_json_array_push(tags, tag1);
    zs_json_array_push(tags, tag2);
    zs_object_free(tag1);
    zs_object_free(tag2);

    zs_json_set(root, ZS_STR("tags"), tags);
    zs_object_free(tags);

    zs_json_respond(200, root);
    zs_object_free(root);
    return 0;
  }

  if (zs_strcmp(path, "/json/respond-array") == 0) {
    zs_s64 arr = zs_json_new_array();

    for (int i = 0; i < 3; i++) {
      zs_s64 item = zs_json_new_object();
      zs_s64 id = zs_json_parse(ZS_STR("0"));
      zs_json_set_i64(id, i + 1);
      zs_json_set(item, ZS_STR("id"), id);
      zs_object_free(id);

      zs_json_array_push(arr, item);
      zs_object_free(item);
    }

    zs_json_respond(200, arr);
    zs_object_free(arr);
    return 0;
  }

  if (zs_strcmp(path, "/json/respond-error") == 0) {
    zs_s64 obj = zs_json_new_object();

    zs_s64 err = zs_json_parse(ZS_STR("\"Not Found\""));
    zs_json_set(obj, ZS_STR("error"), err);
    zs_object_free(err);

    zs_s64 code = zs_json_parse(ZS_STR("0"));
    zs_json_set_i64(code, 404);
    zs_json_set(obj, ZS_STR("code"), code);
    zs_object_free(code);

    zs_json_respond(404, obj);
    zs_object_free(obj);
    return 0;
  }

  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "16-json-respond.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                // Test simple object response
                {
                    const res = await fetch(`${baseUrl}/json/respond-simple`);
                    assertEquals(res.status, 200);
                    assertEquals(
                        res.headers.get("content-type"),
                        "application/json",
                    );
                    const body = await res.json();
                    assertEquals(body.status, "ok");
                    assertEquals(body.code, 200);
                }

                // Test nested object response
                {
                    const res = await fetch(`${baseUrl}/json/respond-nested`);
                    assertEquals(res.status, 200);
                    assertEquals(
                        res.headers.get("content-type"),
                        "application/json",
                    );
                    const body = await res.json();
                    assertEquals(body.user.name, "Alice");
                    assertEquals(body.user.age, 30);
                    assertEquals(body.tags, ["admin", "verified"]);
                }

                // Test array response
                {
                    const res = await fetch(`${baseUrl}/json/respond-array`);
                    assertEquals(res.status, 200);
                    assertEquals(
                        res.headers.get("content-type"),
                        "application/json",
                    );
                    const body = await res.json();
                    assertEquals(body.length, 3);
                    assertEquals(body[0].id, 1);
                    assertEquals(body[1].id, 2);
                    assertEquals(body[2].id, 3);
                }

                // Test error response with non-200 status
                {
                    const res = await fetch(`${baseUrl}/json/respond-error`);
                    assertEquals(res.status, 404);
                    assertEquals(
                        res.headers.get("content-type"),
                        "application/json",
                    );
                    const body = await res.json();
                    assertEquals(body.error, "Not Found");
                    assertEquals(body.code, 404);
                }
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: hex encoding helpers",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "hex helpers\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = String.raw`#include <zeroserve.h>

static int hex_roundtrip(const char *input, zs_u64 input_len, zs_u64 case_flag) {
  char buf[128];
  zs_s64 enc_len = zs_hex_encode(input, input_len, buf, sizeof(buf), case_flag);
  if (enc_len != (zs_s64)(input_len * 2)) return 0;
  zs_s64 dec_len = zs_hex_decode_in_place(buf, enc_len);
  if (dec_len != (zs_s64)input_len) return 0;
  if (zs_memcmp(buf, input, input_len) != 0) return 0;
  return 1;
}

static int hex_expected(void) {
  zs_u8 bytes[4] = {0xde, 0xad, 0xbe, 0xef};
  char buf[16];

  // Test lowercase encoding
  zs_s64 len = zs_hex_encode(bytes, sizeof(bytes), buf, sizeof(buf), ZS_HEX_LOWERCASE);
  if (len != 8 || zs_memcmp(buf, "deadbeef", 8) != 0) return 0;

  // Test uppercase encoding
  len = zs_hex_encode(bytes, sizeof(bytes), buf, sizeof(buf), ZS_HEX_UPPERCASE);
  if (len != 8 || zs_memcmp(buf, "DEADBEEF", 8) != 0) return 0;

  // Test length query (out_len = 0)
  len = zs_hex_encode(bytes, sizeof(bytes), buf, 0, ZS_HEX_LOWERCASE);
  if (len != 8) return 0;

  // Test decoding lowercase
  zs_memcpy(buf, "cafebabe", 8);
  zs_s64 dec_len = zs_hex_decode_in_place(buf, 8);
  if (dec_len != 4) return 0;
  if ((zs_u8)buf[0] != 0xca || (zs_u8)buf[1] != 0xfe ||
      (zs_u8)buf[2] != 0xba || (zs_u8)buf[3] != 0xbe) return 0;

  // Test decoding uppercase
  zs_memcpy(buf, "CAFEBABE", 8);
  dec_len = zs_hex_decode_in_place(buf, 8);
  if (dec_len != 4) return 0;
  if ((zs_u8)buf[0] != 0xca || (zs_u8)buf[1] != 0xfe ||
      (zs_u8)buf[2] != 0xba || (zs_u8)buf[3] != 0xbe) return 0;

  // Test decoding mixed case
  zs_memcpy(buf, "CaFeBaBe", 8);
  dec_len = zs_hex_decode_in_place(buf, 8);
  if (dec_len != 4) return 0;
  if ((zs_u8)buf[0] != 0xca || (zs_u8)buf[1] != 0xfe ||
      (zs_u8)buf[2] != 0xba || (zs_u8)buf[3] != 0xbe) return 0;

  // Test odd length returns -1
  zs_memcpy(buf, "abc", 3);
  dec_len = zs_hex_decode_in_place(buf, 3);
  if (dec_len != (zs_s64)-1) return 0;

  // Test invalid hex char returns -1
  zs_memcpy(buf, "ghij", 4);
  dec_len = zs_hex_decode_in_place(buf, 4);
  if (dec_len != (zs_s64)-1) return 0;

  // Test empty input
  dec_len = zs_hex_decode_in_place(buf, 0);
  if (dec_len != 0) return 0;

  return 1;
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/hex") != 0) {
    return 0;
  }

  int ok = 1;
  if (!hex_roundtrip("hello", sizeof("hello") - 1, ZS_HEX_LOWERCASE)) ok = 0;
  if (!hex_roundtrip("hello", sizeof("hello") - 1, ZS_HEX_UPPERCASE)) ok = 0;
  if (!hex_roundtrip("\x00\xff\x7f\x80", 4, ZS_HEX_LOWERCASE)) ok = 0;
  if (!hex_expected()) ok = 0;

  // Build response with hex-encoded random bytes
  zs_u8 rand_bytes[16];
  zs_getrandom(rand_bytes, sizeof(rand_bytes));
  char rand_hex[64];
  zs_s64 rand_hex_len = zs_hex_encode(rand_bytes, sizeof(rand_bytes), rand_hex, sizeof(rand_hex), ZS_HEX_LOWERCASE);

  char body[256];
  char *bp = zs_stpcpy(body, "{\"rand_hex\":\"");
  zs_memcpy(bp, rand_hex, rand_hex_len);
  bp += rand_hex_len;
  bp = zs_stpcpy(bp, "\",\"hex_ok\":");
  bp += zs_utoa10(ok, bp, 8);
  bp = zs_stpcpy(bp, "}\n");

  zs_meta_set(ZS_STR("zs.response.header.content-type"), ZS_STR("application/json"));
  zs_respond(200, body, bp - body);
  return 0;
}
`;

            await Deno.writeTextFile(
                join(scriptsDir, "10-hex-helpers.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/hex`);
                assertEquals(res.status, 200);
                const payload = (await res.json()) as {
                    rand_hex: string;
                    hex_ok: number;
                };

                assertEquals(payload.hex_ok, 1);
                // Verify hex format: 16 bytes = 32 hex chars
                assertEquals(payload.rand_hex.length, 32);
                // Verify all lowercase hex chars
                assert(/^[0-9a-f]+$/.test(payload.rand_hex));
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

// Shared by the re-entrancy and depth-limit tests below. A single script that
// is both the request gateway and a callee: its `recurse` call function invokes
// itself through `zs_call`, decrementing "remaining" until it bottoms out. Each
// frame reports the total depth it observed and whether the runtime's call-depth
// ceiling was hit (`zs_call` returning -1).
const RECURSE_SCRIPT = String.raw`#include <zeroserve.h>

static ZS_INLINE void set_i64(zs_s64 obj, const char *key, zs_u64 klen,
                              zs_s64 v) {
  zs_s64 n = zs_json_new_object();
  zs_json_set_i64(n, v);
  zs_json_set(obj, key, klen, n);
  zs_object_free(n);
}

static ZS_INLINE zs_s64 get_i64(zs_s64 obj, const char *key, zs_u64 klen) {
  zs_s64 value = 0;
  zs_s64 node = zs_json_get(obj, key, klen);
  if (node >= 0) {
    zs_json_read_i64(node, &value, sizeof(value));
    zs_object_free(node);
  }
  return value;
}

ZS_CALL_ENTRY(recurse, input) {
  zs_s64 remaining = get_i64(input, ZS_STR("remaining"));

  zs_s64 out = zs_json_new_object();
  if (remaining <= 0) {
    set_i64(out, ZS_STR("depth"), 0);
    set_i64(out, ZS_STR("limited"), 0);
    return out;
  }

  zs_s64 child_in = zs_json_new_object();
  set_i64(child_in, ZS_STR("remaining"), remaining - 1);
  zs_s64 child = zs_call(ZS_STR("recurse"), ZS_STR("recurse"), child_in);
  zs_object_free(child_in);

  if (child < 0) {
    /* The runtime refused to nest any deeper. */
    set_i64(out, ZS_STR("depth"), remaining);
    set_i64(out, ZS_STR("limited"), 1);
    return out;
  }

  set_i64(out, ZS_STR("depth"), get_i64(child, ZS_STR("depth")) + 1);
  set_i64(out, ZS_STR("limited"), get_i64(child, ZS_STR("limited")));
  zs_object_free(child);
  return out;
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/recurse") != 0)
    return 0;

  char nbuf[16];
  nbuf[0] = '\0';
  zs_req_query_param(ZS_STR("n"), nbuf, sizeof(nbuf));
  zs_s64 n = 0;
  for (zs_s64 i = 0; nbuf[i] >= '0' && nbuf[i] <= '9'; i++)
    n = n * 10 + (nbuf[i] - '0');

  zs_s64 payload = zs_json_new_object();
  set_i64(payload, ZS_STR("remaining"), n);
  zs_s64 reply = zs_call(ZS_STR("recurse"), ZS_STR("recurse"), payload);
  zs_object_free(payload);

  if (reply < 0) {
    zs_respond(502, ZS_STR("call failed\n"));
    return 0;
  }
  zs_json_respond(200, reply);
  zs_object_free(reply);
  return 0;
}
`;

async function buildRecurseSite(): Promise<
    { siteDir: string; tarPath: string }
> {
    const siteDir = await Deno.makeTempDir();
    await Deno.writeTextFile(join(siteDir, "index.html"), "recurse\n");
    const scriptsDir = join(siteDir, ".zeroserve", "scripts");
    await Deno.mkdir(scriptsDir, { recursive: true });
    await Deno.writeTextFile(join(scriptsDir, "recurse.c"), RECURSE_SCRIPT);
    const tarPath = await packSite(siteDir);
    return { siteDir, tarPath };
}

Deno.test({
    name: "e2e: inter-script call re-entrancy (nested zs_call)",
    ignore: !canRunScripts,
    fn: async () => {
        const { siteDir, tarPath } = await buildRecurseSite();
        try {
            await withZeroserve(tarPath, async (baseUrl) => {
                // A single, non-nested call still resolves the callee.
                const one = await fetch(`${baseUrl}/recurse?n=1`);
                assertEquals(one.status, 200);
                assertEquals(await one.json(), { depth: 1, limited: 0 });

                // Several frames of the same script re-entering itself through
                // zs_call. depth == n proves every nested frame ran and unwound.
                const five = await fetch(`${baseUrl}/recurse?n=5`);
                assertEquals(five.status, 200);
                assertEquals(await five.json(), { depth: 5, limited: 0 });
            });
        } finally {
            await Deno.remove(tarPath).catch(() => {});
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: inter-script call depth limit is enforced",
    ignore: !canRunScripts,
    fn: async () => {
        const { siteDir, tarPath } = await buildRecurseSite();
        try {
            await withZeroserve(tarPath, async (baseUrl) => {
                // MAX_CALL_DEPTH is 8: the request runs at depth 0 and each
                // zs_call adds one, so up to 7 nested recurse frames complete
                // before the 8th is refused. n=7 is the last fully-successful
                // depth.
                const ok = await fetch(`${baseUrl}/recurse?n=7`);
                assertEquals(ok.status, 200);
                assertEquals(await ok.json(), { depth: 7, limited: 0 });

                // One past the ceiling: the chain is truncated and the limit is
                // reported rather than the runtime recursing without bound.
                const limited = await fetch(`${baseUrl}/recurse?n=8`);
                assertEquals(limited.status, 200);
                assertEquals(
                    (await limited.json() as { limited: number }).limited,
                    1,
                );

                // Far past the ceiling behaves identically — no crash, no hang.
                const deep = await fetch(`${baseUrl}/recurse?n=50`);
                assertEquals(deep.status, 200);
                assertEquals(
                    (await deep.json() as { limited: number }).limited,
                    1,
                );
            });
        } finally {
            await Deno.remove(tarPath).catch(() => {});
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

// A two-level call chain whose deepest frame spins forever. The gateway calls
// `outer`, which calls `inner`, which never returns — so the /spin request can
// only ever terminate by being cancelled. Any other path responds normally,
// letting us prove the server stayed healthy after the chain was torn down.
const SPIN_SCRIPT = String.raw`#include <zeroserve.h>

ZS_CALL_ENTRY(inner, input) {
  (void)input;
  volatile zs_u64 place = 0;
  while (1)
    place += 1;
  return 0; /* unreachable */
}

ZS_CALL_ENTRY(outer, payload) {
  (void)payload;
  zs_s64 in = zs_json_new_object();
  zs_s64 r = zs_call(ZS_STR("spin"), ZS_STR("inner"), in);
  zs_object_free(in);
  return r; /* unreachable: inner never returns */
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/spin") == 0) {
    zs_s64 in = zs_json_new_object();
    zs_s64 r = zs_call(ZS_STR("spin"), ZS_STR("outer"), in);
    zs_object_free(in);
    zs_json_respond(200, r); /* unreachable unless cancelled */
    return 0;
  }
  zs_respond(200, ZS_STR("ok\n"));
  return 0;
}
`;

Deno.test({
    name: "e2e: request cancellation tears down the whole call chain",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(join(siteDir, "index.html"), "spin\n");
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.writeTextFile(join(scriptsDir, "spin.c"), SPIN_SCRIPT);
            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                // Baseline: the server serves a normal request.
                const before = await fetch(`${baseUrl}/healthz`);
                assertEquals(before.status, 200);
                assertEquals(await before.text(), "ok\n");

                // Fire a request whose call chain spins forever, then abort it.
                // It can never resolve on its own, so a prompt AbortError proves
                // the in-flight chain was cancelled rather than left running.
                const controller = new AbortController();
                const spinning = fetch(`${baseUrl}/spin`, {
                    signal: controller.signal,
                });
                const settled = spinning.then(
                    () => "resolved",
                    (err) => (err as Error).name,
                );

                // Give the chain time to enter the spin, then cancel.
                await new Promise((r) => setTimeout(r, 300));
                controller.abort();

                let cancelTimer: ReturnType<typeof setTimeout> | undefined;
                const cancelDeadline = new Promise<string>((resolve) => {
                    cancelTimer = setTimeout(() => resolve("timeout"), 5000);
                });
                const outcome = await Promise.race([settled, cancelDeadline]);
                clearTimeout(cancelTimer);
                assertEquals(
                    outcome,
                    "AbortError",
                    "spinning request should reject with AbortError, not hang or resolve",
                );

                // The single-threaded worker must be free again immediately: a
                // normal request right after cancellation still succeeds fast.
                let afterTimer: ReturnType<typeof setTimeout> | undefined;
                const afterDeadline = new Promise<Response | null>((resolve) => {
                    afterTimer = setTimeout(() => resolve(null), 5000);
                });
                const after = await Promise.race([
                    fetch(`${baseUrl}/healthz`),
                    afterDeadline,
                ]);
                clearTimeout(afterTimer);
                assert(
                    after !== null,
                    "server should keep serving after the chain was cancelled",
                );
                assertEquals(after.status, 200);
                assertEquals(await after.text(), "ok\n");
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

async function rawGetTextWithDeadline(
    baseUrl: string,
    path: string,
    timeoutMs: number,
): Promise<{ status: number; body: string } | null> {
    const url = new URL(baseUrl);
    const hostname = url.hostname;
    const port = Number(url.port);
    let conn: Deno.Conn | null = null;
    let timedOut = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const request = (async () => {
        conn = await Deno.connect({ hostname, port });
        try {
            const text = [
                `GET ${path} HTTP/1.1`,
                `Host: ${hostname}:${port}`,
                "User-Agent: deno-test",
                "Accept: text/plain",
                "Accept-Encoding: identity",
                "Connection: close",
                "",
                "",
            ].join("\r\n");
            await writeAll(conn, encoder.encode(text));
            const { head, rest } = await readUntil(
                conn,
                encoder.encode("\r\n\r\n"),
            );
            const responseHead = decoder.decode(head);
            const lines = responseHead
                .split("\r\n")
                .filter((line) => line.length > 0);
            if (lines.length === 0) {
                throw new Error("missing response status line");
            }
            const [_, statusCode] = lines[0].split(" ");
            const status = Number.parseInt(statusCode ?? "", 10);
            if (!Number.isFinite(status)) {
                throw new Error(`invalid response status: ${lines[0]}`);
            }
            const headers = new Headers();
            for (const line of lines.slice(1)) {
                const idx = line.indexOf(":");
                if (idx === -1) {
                    continue;
                }
                headers.append(
                    line.slice(0, idx).trim(),
                    line.slice(idx + 1).trim(),
                );
            }
            const transferEncoding = headers.get("transfer-encoding");
            const contentLength = headers.get("content-length");
            let body: ByteArray;
            if (
                transferEncoding &&
                transferEncoding.toLowerCase().includes("chunked")
            ) {
                body = await readChunkedBody(conn, rest);
            } else if (contentLength) {
                body = await readContentLengthBody(
                    conn,
                    rest,
                    Number.parseInt(contentLength, 10),
                );
            } else {
                body = await readToEnd(conn, rest);
            }
            return {
                status,
                body: decoder.decode(body),
            };
        } catch (err) {
            if (timedOut) {
                return null;
            }
            throw err;
        } finally {
            conn.close();
            conn = null;
        }
    })();
    const timeout = new Promise<null>((resolve) => {
        timer = setTimeout(() => {
            timedOut = true;
            conn?.close();
            resolve(null);
        }, timeoutMs);
    });
    try {
        return await Promise.race([request, timeout]);
    } finally {
        clearTimeout(timer);
    }
}

Deno.test({
    name:
        "e2e: async preemption lets a healthy request run while another spins on one thread",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(join(siteDir, "index.html"), "spin\n");
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.writeTextFile(join(scriptsDir, "spin.c"), SPIN_SCRIPT);
            tarPath = await packSite(siteDir);

            await withZeroserve(
                tarPath,
                async (baseUrl) => {
                    const before = await rawGetTextWithDeadline(
                        baseUrl,
                        "/healthz",
                        1000,
                    );
                    assert(before !== null, "baseline request timed out");
                    assertEquals(before.status, 200);
                    assertEquals(before.body, "ok\n");

                    const controller = new AbortController();
                    const spinning = fetch(`${baseUrl}/spin`, {
                        signal: controller.signal,
                    }).catch((err) => err);
                    try {
                        await new Promise((resolve) => setTimeout(resolve, 300));

                        const healthy = await rawGetTextWithDeadline(
                            baseUrl,
                            "/healthz",
                            2000,
                        );
                        assert(
                            healthy !== null,
                            "healthy request timed out while another request spun",
                        );
                        assertEquals(healthy.status, 200);
                        assertEquals(healthy.body, "ok\n");
                    } finally {
                        controller.abort();
                        await spinning;
                    }
                },
                ["--threads", "1", "--preempt-timer-interval-ms", "10"],
            );
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

// A single script that is both gateway and callee. Its `mutate` call mutates the
// shared request and metadata, then the request handler reads those back —
// proving that request mutations and metadata set by a callee propagate to the
// caller and out to the wire.
const PROPAGATE_SCRIPT = String.raw`#include <zeroserve.h>

ZS_CALL_ENTRY(mutate, input) {
  (void)input;
  zs_req_set_header(ZS_STR("x-from-callee"), ZS_STR("yes"));
  zs_meta_set(ZS_STR("callee-note"), ZS_STR("hi"));
  zs_meta_set(ZS_STR("zs.response.header.x-callee"), ZS_STR("1"));
  return zs_json_new_object();
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/propagate") != 0)
    return 0;

  zs_s64 payload = zs_json_new_object();
  zs_s64 reply = zs_call(ZS_STR("propagate"), ZS_STR("mutate"), payload);
  zs_object_free(payload);
  if (reply < 0) {
    zs_respond(502, ZS_STR("call failed\n"));
    return 0;
  }
  zs_object_free(reply);

  /* Read back the request header and metadata the callee set on the shared
     state. */
  char hdr[32];
  hdr[0] = '\0';
  zs_req_header(ZS_STR("x-from-callee"), hdr, sizeof(hdr));
  char note[32];
  note[0] = '\0';
  zs_meta_get(ZS_STR("callee-note"), note, sizeof(note));

  zs_s64 result = zs_json_new_object();
  zs_s64 hv = zs_json_new_object();
  zs_json_set_string(hv, ZS_STR(hdr));
  zs_json_set(result, ZS_STR("header"), hv);
  zs_object_free(hv);
  zs_s64 mv = zs_json_new_object();
  zs_json_set_string(mv, ZS_STR(note));
  zs_json_set(result, ZS_STR("meta"), mv);
  zs_object_free(mv);

  zs_json_respond(200, result);
  zs_object_free(result);
  return 0;
}
`;

Deno.test({
    name: "e2e: callee shares the caller's request and metadata",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(join(siteDir, "index.html"), "propagate\n");
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.writeTextFile(
                join(scriptsDir, "propagate.c"),
                PROPAGATE_SCRIPT,
            );
            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/propagate`);
                assertEquals(res.status, 200);
                // Request header + metadata the callee set are visible to the
                // caller through the shared context.
                assertEquals(await res.json(), { header: "yes", meta: "hi" });
                // Metadata the callee set also propagated out to the response.
                assertEquals(res.headers.get("x-callee"), "1");
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

const RESPONSE_HOOK_METADATA_SCRIPT = String.raw`#include <zeroserve.h>

ZS_CALL_ENTRY(after_response, input) {
  (void)input;
  char phase[32];
  phase[0] = '\0';
  zs_meta_get(ZS_STR("phase-note"), phase, sizeof(phase));
  if (zs_strcmp(phase, "entry") == 0) {
    zs_meta_set(ZS_STR("zs.response.header.x-hook-saw-meta"), ZS_STR("yes"));
  }
  zs_meta_set(ZS_STR("phase-note"), ZS_STR("hook"));
  zs_meta_set(ZS_STR("zs.response.header.x-hook-set"), ZS_STR("set-in-hook"));
  return zs_json_new_object();
}

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/hook-cleared") == 0) {
    zs_s64 payload = zs_json_new_object();
    zs_res_hook(ZS_STR(""), ZS_STR("after_response"), payload);
    zs_object_free(payload);
    zs_res_hooks_clear();
    zs_respond(200, ZS_STR("cleared body"));
    return 0;
  }

  if (zs_strcmp(path, "/hook-metadata") != 0)
    return 0;

  zs_meta_set(ZS_STR("phase-note"), ZS_STR("entry"));
  zs_s64 payload = zs_json_new_object();
  zs_res_hook(ZS_STR(""), ZS_STR("after_response"), payload);
  zs_object_free(payload);
  zs_respond(200, ZS_STR("hook body"));
  return 0;
}
`;

Deno.test({
    name: "e2e: response hooks share metadata and metadata response headers",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(join(siteDir, "index.html"), "fallback\n");
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.writeTextFile(
                join(scriptsDir, "hook-metadata.c"),
                RESPONSE_HOOK_METADATA_SCRIPT,
            );
            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const res = await fetch(`${baseUrl}/hook-metadata`);
                assertEquals(res.status, 200);
                assertEquals(await res.text(), "hook body");
                assertEquals(res.headers.get("x-hook-saw-meta"), "yes");
                assertEquals(res.headers.get("x-hook-set"), "set-in-hook");

                const cleared = await fetch(`${baseUrl}/hook-cleared`);
                assertEquals(cleared.status, 200);
                assertEquals(await cleared.text(), "cleared body");
                assertEquals(cleared.headers.get("x-hook-set"), null);
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

const REQ_BODY_LIMIT_REPORT_SCRIPT = String.raw`#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/body-limit") != 0)
    return 0;

  if (zs_req_body_limit(8)) {
    zs_respond(200, ZS_STR("exceeded"));
  } else {
    zs_respond(200, ZS_STR("ok"));
  }
  return 0;
}
`;

Deno.test({
    name: "e2e: zs_req_body_limit reports oversized content length",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;
        try {
            await Deno.writeTextFile(join(siteDir, "index.html"), "fallback\n");
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });
            await Deno.writeTextFile(
                join(scriptsDir, "body_limit_report.c"),
                REQ_BODY_LIMIT_REPORT_SCRIPT,
            );
            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const exceeded = await fetch(`${baseUrl}/body-limit`, {
                    method: "POST",
                    body: "123456789",
                });
                assertEquals(exceeded.status, 200);
                assertEquals(await exceeded.text(), "exceeded");

                const ok = await fetch(`${baseUrl}/body-limit`, {
                    method: "POST",
                    body: "12345678",
                });
                assertEquals(ok.status, 200);
                assertEquals(await ok.text(), "ok");
            });
        } finally {
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});
