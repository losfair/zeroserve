import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
    denoSupportsH2cMidStreamResponses,
    hasBpfToolchain,
    packSite,
    withZeroserve,
} from "./test_utils.ts";
import * as http2 from "node:http2";
import { Buffer } from "node:buffer";

const canRunScripts = await hasBpfToolchain();

/** Deno.Conn.write may write partially; loop until the whole buffer is out. */
async function writeAll(conn: Deno.Conn, data: Uint8Array): Promise<void> {
    let offset = 0;
    while (offset < data.length) {
        offset += await conn.write(data.subarray(offset));
    }
}

/**
 * Raw h1 backend that rejects uploads mid-stream: it reads the request head
 * plus a small prefix of the body, sends a final 413 response, and then keeps
 * draining whatever else arrives until the proxy closes the connection —
 * the way a backend with an upload size limit behaves (RFC 9110 §9.5).
 */
async function startEarlyRejectBackend(rejectAfterBytes: number): Promise<{
    url: string;
    close: () => void;
}> {
    const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
    const port = (listener.addr as Deno.NetAddr).port;

    (async () => {
        for await (const conn of listener) {
            handleConn(conn, rejectAfterBytes).catch(() => {});
        }
    })();

    return {
        url: `http://127.0.0.1:${port}`,
        close: () => listener.close(),
    };
}

async function handleConn(conn: Deno.Conn, rejectAfterBytes: number) {
    const encoder = new TextEncoder();
    try {
        // Read until the end of the request head plus a prefix of the body.
        let received = 0;
        let sawHeadEnd = false;
        let holdover = new Uint8Array(0);
        const buf = new Uint8Array(65536);
        while (!sawHeadEnd || received < rejectAfterBytes) {
            const n = await conn.read(buf);
            if (n === null) return;
            if (sawHeadEnd) {
                received += n;
                continue;
            }
            const merged = new Uint8Array(holdover.length + n);
            merged.set(holdover);
            merged.set(buf.subarray(0, n), holdover.length);
            holdover = merged;
            for (let i = 0; i + 4 <= holdover.length; i++) {
                if (
                    holdover[i] === 13 && holdover[i + 1] === 10 &&
                    holdover[i + 2] === 13 && holdover[i + 3] === 10
                ) {
                    sawHeadEnd = true;
                    received = holdover.length - (i + 4);
                    break;
                }
            }
        }

        const body = JSON.stringify({ error: "upload too large" });
        await writeAll(conn,
            encoder.encode(
                `HTTP/1.1 413 Payload Too Large\r\ncontent-type: application/json\r\ncontent-length: ${body.length}\r\n\r\n${body}`,
            ),
        );

        // Lingering drain: keep reading until the proxy closes.
        while (true) {
            const n = await conn.read(buf);
            if (n === null) break;
        }
    } finally {
        try {
            conn.close();
        } catch {
            // already closed
        }
    }
}

async function buildProxySite(backendUrl: string): Promise<string> {
    const siteDir = await Deno.makeTempDir();
    await Deno.writeTextFile(join(siteDir, "index.html"), "early response test\n");
    const scriptsDir = join(siteDir, ".zeroserve", "scripts");
    await Deno.mkdir(scriptsDir, { recursive: true });
    await Deno.writeTextFile(
        join(scriptsDir, "10-early-proxy.c"),
        `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  zs_reverse_proxy(ZS_STR("${backendUrl}"));
  return 0;
}
`,
    );
    const tarPath = await packSite(siteDir);
    await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    return tarPath;
}

/**
 * h2c upload that only finishes if the server responds early: chunks are sent
 * with delays and sending stops as soon as a response arrives. If the proxy
 * required the full body before relaying the backend's early 413, this would
 * hit the timeout instead.
 */
function h2cUploadUntilResponse(
    hostname: string,
    port: number,
    path: string,
    chunkCount: number,
    chunkSize: number,
    delayMs: number,
    timeoutMs = 30000,
): Promise<{ status: number; body: string; chunksSent: number }> {
    return new Promise((resolve, reject) => {
        const client = http2.connect(`http://${hostname}:${port}`);
        const timer = setTimeout(() => {
            client.close();
            reject(new Error("h2c upload timed out waiting for early response"));
        }, timeoutMs);
        client.on("error", (err) => {
            clearTimeout(timer);
            client.close();
            reject(err);
        });

        const req = client.request({
            ":path": path,
            ":method": "POST",
            "content-type": "application/octet-stream",
        });

        let status = 0;
        let chunksSent = 0;
        let responded = false;
        let settled = false;
        const responseChunks: Buffer[] = [];

        const settle = () => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            client.close();
            if (status === 0) {
                reject(new Error("h2c stream ended without a response"));
                return;
            }
            resolve({
                status,
                body: Buffer.concat(responseChunks).toString("utf-8"),
                chunksSent,
            });
        };

        req.on("response", (hdrs) => {
            responded = true;
            status = hdrs[":status"] as number;
        });
        req.on("data", (chunk: Buffer) => {
            responseChunks.push(chunk);
        });
        req.on("end", settle);
        req.on("close", settle);
        req.on("error", () => {
            // The proxy resets the stream (NO_ERROR) after an early response;
            // 'end'/'close' settle with whatever was received.
        });

        (async () => {
            const chunk = Buffer.alloc(chunkSize, 0x61);
            for (let i = 0; i < chunkCount && !responded; i++) {
                try {
                    req.write(chunk);
                } catch {
                    break;
                }
                chunksSent++;
                await new Promise((r) => setTimeout(r, delayMs));
            }
            try {
                req.end();
            } catch {
                // stream may already be closed by the early response
            }
        })();
    });
}

/** Raw h1 client: streams a chunked body, then reads the final response. */
async function h1ChunkedUpload(
    hostname: string,
    port: number,
    path: string,
    chunkCount: number,
    chunkSize: number,
): Promise<{ status: number; rest: string }> {
    const conn = await Deno.connect({ hostname, port });
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    try {
        await writeAll(conn,
            encoder.encode(
                `POST ${path} HTTP/1.1\r\nhost: ${hostname}:${port}\r\ntransfer-encoding: chunked\r\n\r\n`,
            ),
        );
        const chunk = new Uint8Array(chunkSize).fill(0x61);
        const framing = encoder.encode(`${chunkSize.toString(16)}\r\n`);
        for (let i = 0; i < chunkCount; i++) {
            await writeAll(conn, framing);
            await writeAll(conn, chunk);
            await writeAll(conn, encoder.encode("\r\n"));
        }
        await writeAll(conn, encoder.encode("0\r\n\r\n"));

        let buf = "";
        while (!buf.includes("\r\n\r\n")) {
            const b = new Uint8Array(65536);
            const n = await conn.read(b);
            if (n === null) {
                throw new Error("connection closed before response head");
            }
            buf += decoder.decode(b.subarray(0, n), { stream: true });
        }
        const status = Number(buf.split("\r\n")[0].split(" ")[1]);
        return { status, rest: buf };
    } finally {
        try {
            conn.close();
        } catch {
            // already closed
        }
    }
}

Deno.test({
    name: "e2e: backend response before the request body completes is relayed (h2c)",
    // The h2c client here needs the runtime to deliver a response while the
    // request stream is still open — see denoSupportsH2cMidStreamResponses.
    ignore: !canRunScripts || !denoSupportsH2cMidStreamResponses(),
    fn: async () => {
        const backend = await startEarlyRejectBackend(64 * 1024);
        let tarPath: string | null = null;
        try {
            tarPath = await buildProxySite(backend.url);
            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                const chunkCount = 64;
                const result = await h2cUploadUntilResponse(
                    url.hostname,
                    Number(url.port),
                    "/upload",
                    chunkCount,
                    256 * 1024,
                    50,
                );
                assertEquals(result.status, 413);
                assert(
                    result.body.includes("upload too large"),
                    `backend error body should be relayed, got: ${result.body}`,
                );
                assert(
                    result.chunksSent < chunkCount,
                    `response should arrive before the upload completes (sent ${result.chunksSent}/${chunkCount})`,
                );
            });
        } finally {
            backend.close();
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
        }
    },
});

Deno.test({
    name: "e2e: backend response before the request body completes is relayed (h1)",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startEarlyRejectBackend(64 * 1024);
        let tarPath: string | null = null;
        try {
            tarPath = await buildProxySite(backend.url);
            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                // The h1 client streams the whole body (an h1 client cannot
                // abort a request without killing the connection); the proxy
                // must drain it and still deliver the backend's 413 instead
                // of failing with a write error.
                const result = await h1ChunkedUpload(
                    url.hostname,
                    Number(url.port),
                    "/upload",
                    16,
                    256 * 1024,
                );
                assertEquals(result.status, 413);
            });
        } finally {
            backend.close();
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
        }
    },
});

/**
 * Raw h1 backend that runs a bidirectional exchange the way git smart HTTP
 * does: it sends its (non-error) response head immediately — before consuming
 * any of the request body — then reads the entire chunked body, then streams
 * the response body. The proxy must NOT treat the early head as a reason to
 * abort the upload (that would truncate the request and, through intermediary
 * proxies, surface as "client closed request" failures).
 */
async function startBidirectionalBackend(): Promise<{
    url: string;
    close: () => void;
}> {
    const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
    const port = (listener.addr as Deno.NetAddr).port;

    (async () => {
        for await (const conn of listener) {
            handleBidirectionalConn(conn).catch(() => {});
        }
    })();

    return {
        url: `http://127.0.0.1:${port}`,
        close: () => listener.close(),
    };
}

async function handleBidirectionalConn(conn: Deno.Conn) {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    let buf = new Uint8Array(0);

    const readMore = async (): Promise<boolean> => {
        const chunk = new Uint8Array(65536);
        const n = await conn.read(chunk);
        if (n === null) return false;
        const merged = new Uint8Array(buf.length + n);
        merged.set(buf);
        merged.set(chunk.subarray(0, n), buf.length);
        buf = merged;
        return true;
    };
    const findCrlf = (): number => {
        for (let i = 0; i + 2 <= buf.length; i++) {
            if (buf[i] === 13 && buf[i + 1] === 10) return i;
        }
        return -1;
    };

    try {
        // Request head
        let headEnd = -1;
        while (headEnd < 0) {
            for (let i = 0; i + 4 <= buf.length; i++) {
                if (
                    buf[i] === 13 && buf[i + 1] === 10 &&
                    buf[i + 2] === 13 && buf[i + 3] === 10
                ) {
                    headEnd = i;
                    break;
                }
            }
            if (headEnd < 0 && !(await readMore())) return;
        }
        buf = buf.subarray(headEnd + 4);

        // Respond with the head IMMEDIATELY, like git http-backend.
        await writeAll(
            conn,
            encoder.encode("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n"),
        );

        // Now consume the entire chunked request body.
        let totalBytes = 0;
        while (true) {
            let lineEnd = findCrlf();
            while (lineEnd < 0) {
                if (!(await readMore())) return;
                lineEnd = findCrlf();
            }
            const size = parseInt(
                decoder.decode(buf.subarray(0, lineEnd)).split(";")[0],
                16,
            );
            buf = buf.subarray(lineEnd + 2);
            if (size === 0) {
                let tEnd = findCrlf();
                while (tEnd < 0) {
                    if (!(await readMore())) return;
                    tEnd = findCrlf();
                }
                buf = buf.subarray(tEnd + 2);
                break;
            }
            while (buf.length < size + 2) {
                if (!(await readMore())) return;
            }
            totalBytes += size;
            buf = buf.subarray(size + 2);
        }

        // Only now stream the response body and finish.
        const body = `done ${totalBytes}`;
        await writeAll(
            conn,
            encoder.encode(
                `${body.length.toString(16)}\r\n${body}\r\n0\r\n\r\n`,
            ),
        );
    } finally {
        try {
            conn.close();
        } catch {
            // already closed
        }
    }
}

/** h2c client that uploads the whole body, then reads the response. */
function h2cFullUpload(
    hostname: string,
    port: number,
    path: string,
    chunkCount: number,
    chunkSize: number,
    timeoutMs = 30000,
): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
        const client = http2.connect(`http://${hostname}:${port}`);
        const timer = setTimeout(() => {
            client.close();
            reject(new Error("h2c bidirectional upload timed out"));
        }, timeoutMs);
        client.on("error", (err) => {
            clearTimeout(timer);
            client.close();
            reject(err);
        });
        const req = client.request({
            ":path": path,
            ":method": "POST",
            "content-type": "application/octet-stream",
        });
        let status = 0;
        const responseChunks: Buffer[] = [];
        req.on("response", (hdrs) => {
            status = hdrs[":status"] as number;
        });
        req.on("data", (chunk: Buffer) => {
            responseChunks.push(chunk);
        });
        req.on("end", () => {
            clearTimeout(timer);
            client.close();
            resolve({
                status,
                body: Buffer.concat(responseChunks).toString("utf-8"),
            });
        });
        req.on("error", (err) => {
            clearTimeout(timer);
            client.close();
            reject(err);
        });
        // Write chunks one at a time, waiting for each flush. Letting them
        // pile up in the stream buffer makes Writable flush them via _writev,
        // which some runtimes' node:http2 shims (e.g. the Deno packaged for
        // OpenBSD) leave unimplemented.
        const chunk = Buffer.alloc(chunkSize, 0x61);
        (async () => {
            for (let i = 0; i < chunkCount; i++) {
                await new Promise<void>((res, rej) =>
                    req.write(chunk, (err: Error | null | undefined) => err ? rej(err) : res())
                );
            }
            req.end();
        })().catch((err) => {
            clearTimeout(timer);
            client.close();
            reject(err);
        });
    });
}

Deno.test({
    name:
        "e2e: early non-error response head does not abort the upload (git-style bidirectional exchange)",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startBidirectionalBackend();
        let tarPath: string | null = null;
        try {
            tarPath = await buildProxySite(backend.url);
            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                const chunkCount = 16;
                const chunkSize = 256 * 1024;
                const total = chunkCount * chunkSize;

                // h1 client: the full body must reach the backend even though
                // the backend sent its 200 head before reading any of it.
                let sent = 0;
                const stream = new ReadableStream<Uint8Array>({
                    pull(controller) {
                        if (sent >= chunkCount) {
                            controller.close();
                            return;
                        }
                        controller.enqueue(new Uint8Array(chunkSize).fill(0x61));
                        sent++;
                    },
                });
                const res = await fetch(`${baseUrl}/upload`, {
                    method: "POST",
                    body: stream,
                    // @ts-ignore: Deno supports duplex
                    duplex: "half",
                });
                assertEquals(res.status, 200);
                assertEquals(await res.text(), `done ${total}`);

                // h2c client, same exchange.
                const h2 = await h2cFullUpload(
                    url.hostname,
                    Number(url.port),
                    "/upload",
                    chunkCount,
                    chunkSize,
                );
                assertEquals(h2.status, 200);
                assertEquals(h2.body, `done ${total}`);
            });
        } finally {
            backend.close();
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
        }
    },
});
