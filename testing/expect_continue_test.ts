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

interface InterimBackendResult {
    sawExpect: boolean;
    totalBytes: number;
}

/**
 * Raw h1 backend that behaves like a server honoring `Expect: 100-continue`
 * (git-http-backend, nginx, ...): it emits interim 1xx responses before the
 * final one. The interim responses are sent unconditionally so the test also
 * covers backends that send them unsolicited.
 */
async function startInterimResponseBackend(): Promise<{
    url: string;
    close: () => void;
}> {
    const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
    const port = (listener.addr as Deno.NetAddr).port;

    (async () => {
        for await (const conn of listener) {
            handleBackendConn(conn).catch(() => {});
        }
    })();

    return {
        url: `http://127.0.0.1:${port}`,
        close: () => listener.close(),
    };
}

async function handleBackendConn(conn: Deno.Conn): Promise<void> {
    const decoder = new TextDecoder();
    const encoder = new TextEncoder();
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

    const findSeq = (seq: Uint8Array, from = 0): number => {
        outer: for (let i = from; i + seq.length <= buf.length; i++) {
            for (let j = 0; j < seq.length; j++) {
                if (buf[i + j] !== seq[j]) continue outer;
            }
            return i;
        }
        return -1;
    };
    const CRLF2 = encoder.encode("\r\n\r\n");
    const CRLF = encoder.encode("\r\n");

    try {
        while (true) {
            // Read request head
            let headEnd = findSeq(CRLF2);
            while (headEnd < 0) {
                if (!(await readMore())) return;
                headEnd = findSeq(CRLF2);
            }
            const head = decoder.decode(buf.subarray(0, headEnd));
            buf = buf.subarray(headEnd + 4);
            const headers = new Map<string, string>();
            for (const line of head.split("\r\n").slice(1)) {
                const idx = line.indexOf(":");
                if (idx > 0) {
                    headers.set(
                        line.slice(0, idx).trim().toLowerCase(),
                        line.slice(idx + 1).trim(),
                    );
                }
            }
            const sawExpect = headers.has("expect");

            // Interim responses before consuming the body, like a backend
            // honoring `Expect: 100-continue` (plus an unsolicited 103).
            await writeAll(conn,
                encoder.encode(
                    "HTTP/1.1 103 Early Hints\r\nlink: </style.css>; rel=preload\r\n\r\n" +
                        "HTTP/1.1 100 Continue\r\n\r\n",
                ),
            );

            // Read the body (chunked or content-length)
            let totalBytes = 0;
            if ((headers.get("transfer-encoding") ?? "").includes("chunked")) {
                while (true) {
                    let lineEnd = findSeq(CRLF);
                    while (lineEnd < 0) {
                        if (!(await readMore())) return;
                        lineEnd = findSeq(CRLF);
                    }
                    const size = parseInt(
                        decoder.decode(buf.subarray(0, lineEnd)).split(";")[0],
                        16,
                    );
                    buf = buf.subarray(lineEnd + 2);
                    if (size === 0) {
                        // trailers
                        let tEnd = findSeq(CRLF);
                        while (tEnd < 0) {
                            if (!(await readMore())) return;
                            tEnd = findSeq(CRLF);
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
            } else if (headers.has("content-length")) {
                const len = Number(headers.get("content-length"));
                while (buf.length < len) {
                    if (!(await readMore())) return;
                }
                totalBytes = len;
                buf = buf.subarray(len);
            }

            const body = JSON.stringify(
                { sawExpect, totalBytes } satisfies InterimBackendResult,
            );
            await writeAll(conn,
                encoder.encode(
                    `HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${body.length}\r\n\r\n${body}`,
                ),
            );
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
    await Deno.writeTextFile(join(siteDir, "index.html"), "expect test\n");
    const scriptsDir = join(siteDir, ".zeroserve", "scripts");
    await Deno.mkdir(scriptsDir, { recursive: true });
    await Deno.writeTextFile(
        join(scriptsDir, "10-expect-proxy.c"),
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
 * Raw h1 client that performs the RFC 9110 `Expect: 100-continue` dance the
 * way git/curl do for large pushes: send the head, wait for an interim 100
 * from the proxy, then stream the body chunked and read the final response.
 */
async function h1ExpectContinueUpload(
    hostname: string,
    port: number,
    path: string,
    bodySize: number,
): Promise<{ interimStatuses: number[]; status: number; body: string }> {
    const conn = await Deno.connect({ hostname, port });
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    try {
        await writeAll(conn,
            encoder.encode(
                `POST ${path} HTTP/1.1\r\nhost: ${hostname}:${port}\r\n` +
                    "expect: 100-continue\r\ntransfer-encoding: chunked\r\n\r\n",
            ),
        );

        let buf = "";
        const readChunk = async (): Promise<boolean> => {
            const chunk = new Uint8Array(65536);
            const n = await conn.read(chunk);
            if (n === null) return false;
            buf += decoder.decode(chunk.subarray(0, n), { stream: true });
            return true;
        };
        let lastHead = "";
        const readResponseHead = async (): Promise<number> => {
            while (!buf.includes("\r\n\r\n")) {
                if (!(await readChunk())) {
                    throw new Error("connection closed while reading response head");
                }
            }
            const headEnd = buf.indexOf("\r\n\r\n");
            lastHead = buf.slice(0, headEnd);
            buf = buf.slice(headEnd + 4);
            return Number(lastHead.split("\r\n")[0].split(" ")[1]);
        };

        // The proxy must acknowledge the expectation before we send the body.
        const interimStatuses: number[] = [];
        let status = await readResponseHead();
        while (status >= 100 && status < 200) {
            interimStatuses.push(status);
            if (status === 100) break;
            status = await readResponseHead();
        }
        assert(
            interimStatuses.includes(100),
            `expected an interim 100 Continue before sending the body, got ${interimStatuses}`,
        );

        // Now stream the body.
        const chunk = new Uint8Array(64 * 1024).fill(0x61);
        let remaining = bodySize;
        while (remaining > 0) {
            const take = Math.min(remaining, chunk.length);
            await writeAll(conn, encoder.encode(`${take.toString(16)}\r\n`));
            await writeAll(conn, chunk.subarray(0, take));
            await writeAll(conn, encoder.encode("\r\n"));
            remaining -= take;
        }
        await writeAll(conn, encoder.encode("0\r\n\r\n"));

        // Final response (skip any further interim responses).
        status = await readResponseHead();
        while (status >= 100 && status < 200) {
            status = await readResponseHead();
        }
        // Read the full content-length body (ASCII JSON, so byte length
        // equals string length); a single read may return a partial body.
        const lenMatch = lastHead.match(/content-length:\s*(\d+)/i);
        const bodyLen = lenMatch ? Number(lenMatch[1]) : 0;
        while (buf.length < bodyLen) {
            if (!(await readChunk())) break;
        }
        return { interimStatuses, status, body: buf.slice(0, bodyLen) };
    } finally {
        try {
            conn.close();
        } catch {
            // already closed
        }
    }
}

function h2cExpectContinueUpload(
    hostname: string,
    port: number,
    path: string,
    bodySize: number,
    timeoutMs = 30000,
): Promise<{ gotContinue: boolean; status: number; body: string }> {
    return new Promise((resolve, reject) => {
        const client = http2.connect(`http://${hostname}:${port}`);
        const timer = setTimeout(() => {
            client.close();
            reject(new Error("h2c expect-continue upload timed out"));
        }, timeoutMs);
        client.on("error", (err) => {
            clearTimeout(timer);
            client.close();
            reject(err);
        });

        const req = client.request({
            ":path": path,
            ":method": "POST",
            "expect": "100-continue",
            "content-type": "application/octet-stream",
        });

        let gotContinue = false;
        let status = 0;
        const responseChunks: Buffer[] = [];
        // Respect backpressure: writing the whole body in a tight loop stacks
        // multiple chunks in the stream's write buffer, which routes through
        // ClientHttp2Stream._writev — unimplemented in Deno's node:http2
        // compat layer (observed on the slower OpenBSD CI VM). One chunk per
        // drain keeps the buffer at a single chunk and exercises the same
        // proxy behavior.
        const sendBody = () => {
            const chunk = Buffer.alloc(64 * 1024, 0x61);
            let remaining = bodySize;
            const writeMore = () => {
                while (remaining > 0) {
                    const take = Math.min(remaining, chunk.length);
                    remaining -= take;
                    if (!req.write(chunk.subarray(0, take))) {
                        req.once("drain", writeMore);
                        return;
                    }
                }
                req.end();
            };
            writeMore();
        };

        // Like curl, wait for the interim response before uploading, with a
        // fallback so a missing 100 fails the test via assertion, not timeout.
        const fallback = setTimeout(sendBody, 3000);
        req.on("continue", () => {
            gotContinue = true;
            clearTimeout(fallback);
            sendBody();
        });
        req.on("response", (hdrs) => {
            status = hdrs[":status"] as number;
        });
        req.on("data", (chunk: Buffer) => {
            responseChunks.push(chunk);
        });
        req.on("end", () => {
            clearTimeout(timer);
            clearTimeout(fallback);
            client.close();
            resolve({
                gotContinue,
                status,
                body: Buffer.concat(responseChunks).toString("utf-8"),
            });
        });
        req.on("error", (err) => {
            clearTimeout(timer);
            clearTimeout(fallback);
            client.close();
            reject(err);
        });
    });
}

Deno.test({
    name:
        "e2e: reverse proxy owns Expect: 100-continue and skips backend interim responses",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startInterimResponseBackend();
        let tarPath: string | null = null;
        try {
            tarPath = await buildProxySite(backend.url);
            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                const bodySize = 4 * 1024 * 1024;

                // h1 client: proxy must send its own interim 100 (asserted
                // inside the helper before the body goes out), strip Expect
                // from the forwarded request, and relay only the backend's
                // final response.
                const h1 = await h1ExpectContinueUpload(
                    url.hostname,
                    Number(url.port),
                    "/upload",
                    bodySize,
                );
                assertEquals(h1.status, 200);
                const h1Result: InterimBackendResult = JSON.parse(h1.body);
                assertEquals(h1Result.sawExpect, false);
                assertEquals(h1Result.totalBytes, bodySize);

                // h2c client (the git-over-HTTP/2 push shape). Needs the
                // runtime to surface the interim 100 mid-stream — see
                // denoSupportsH2cMidStreamResponses.
                if (denoSupportsH2cMidStreamResponses()) {
                    const h2 = await h2cExpectContinueUpload(
                        url.hostname,
                        Number(url.port),
                        "/upload",
                        bodySize,
                    );
                    assertEquals(h2.status, 200);
                    assert(h2.gotContinue, "expected an interim 100 over h2c");
                    const h2Result: InterimBackendResult = JSON.parse(h2.body);
                    assertEquals(h2Result.sawExpect, false);
                    assertEquals(h2Result.totalBytes, bodySize);
                }
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
    name: "e2e: unsolicited backend 1xx responses are skipped on bodyless requests",
    ignore: !canRunScripts,
    fn: async () => {
        const backend = await startInterimResponseBackend();
        let tarPath: string | null = null;
        try {
            tarPath = await buildProxySite(backend.url);
            await withZeroserve(tarPath, async (baseUrl) => {
                // GET goes through the simple proxy fast path; the backend
                // still sends 103 + 100 before the 200.
                const res = await fetch(`${baseUrl}/`, { method: "GET" });
                assertEquals(res.status, 200);
                const result: InterimBackendResult = await res.json();
                assertEquals(result.sawExpect, false);
                assertEquals(result.totalBytes, 0);
            });
        } finally {
            backend.close();
            if (tarPath) {
                await Deno.remove(tarPath).catch(() => {});
            }
        }
    },
});
