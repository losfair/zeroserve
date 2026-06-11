import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import { hasBpfToolchain, packSite, withZeroserve } from "./test_utils.ts";
import * as http2 from "node:http2";
import { Buffer } from "node:buffer";

const canRunScripts = await hasBpfToolchain();

interface ChunkTiming {
    chunkIndex: number;
    byteCount: number;
    receivedAt: number;
}

interface StreamingBackendResponse {
    totalBytes: number;
    chunkCount: number;
    timings: ChunkTiming[];
    firstChunkAt: number;
    lastChunkAt: number;
}

async function startStreamingBackend(): Promise<{
    url: string;
    close: () => Promise<void>;
}> {
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
        async (req) => {
            const url = new URL(req.url);

            if (url.pathname !== "/upload") {
                return new Response("not found", { status: 404 });
            }

            if (!req.body) {
                return Response.json({
                    totalBytes: 0,
                    chunkCount: 0,
                    timings: [],
                    firstChunkAt: 0,
                    lastChunkAt: 0,
                } satisfies StreamingBackendResponse);
            }

            const timings: ChunkTiming[] = [];
            const reader = req.body.getReader();
            let totalBytes = 0;
            let chunkIndex = 0;
            let firstChunkAt = 0;
            let lastChunkAt = 0;

            while (true) {
                const { done, value } = await reader.read();
                const receivedAt = performance.now();

                if (done) break;

                if (chunkIndex === 0) {
                    firstChunkAt = receivedAt;
                }
                lastChunkAt = receivedAt;

                timings.push({
                    chunkIndex,
                    byteCount: value.byteLength,
                    receivedAt,
                });

                totalBytes += value.byteLength;
                chunkIndex++;
            }

            return Response.json({
                totalBytes,
                chunkCount: chunkIndex,
                timings,
                firstChunkAt,
                lastChunkAt,
            } satisfies StreamingBackendResponse);
        },
    );

    if (port === 0) {
        await new Promise((resolve) => setTimeout(resolve, 0));
    }

    if (port === 0) {
        controller.abort();
        await server.finished;
        throw new Error("failed to start streaming backend server");
    }

    return {
        url: `http://127.0.0.1:${port}`,
        close: async () => {
            controller.abort();
            await server.finished;
        },
    };
}

function createDelayedChunks(
    chunkSize: number,
    chunkCount: number,
): Uint8Array[] {
    const chunks: Uint8Array[] = [];
    for (let i = 0; i < chunkCount; i++) {
        const chunk = new Uint8Array(chunkSize);
        chunk.fill(i % 256);
        chunks.push(chunk);
    }
    return chunks;
}

async function h1PostWithStreamingBody(
    baseUrl: string,
    path: string,
    chunks: Uint8Array[],
    delayMs: number,
    includeContentLength: boolean,
): Promise<StreamingBackendResponse> {
    const totalSize = chunks.reduce((sum, c) => sum + c.byteLength, 0);
    let chunkIndex = 0;

    const stream = new ReadableStream<Uint8Array>({
        async pull(controller) {
            if (chunkIndex >= chunks.length) {
                controller.close();
                return;
            }

            controller.enqueue(chunks[chunkIndex]);
            chunkIndex++;

            if (chunkIndex < chunks.length && delayMs > 0) {
                await new Promise((r) => setTimeout(r, delayMs));
            }
        },
    });

    const headers: Record<string, string> = {
        "content-type": "application/octet-stream",
    };
    if (includeContentLength) {
        headers["content-length"] = String(totalSize);
    }

    const res = await fetch(`${baseUrl}${path}`, {
        method: "POST",
        body: stream,
        headers,
        // @ts-ignore: Deno supports duplex
        duplex: "half",
    });

    assertEquals(res.status, 200);
    return await res.json();
}

function h2cPostWithStreamingBody(
    hostname: string,
    port: number,
    path: string,
    chunks: Uint8Array[],
    delayMs: number,
    includeContentLength: boolean,
    timeoutMs = 30000,
): Promise<StreamingBackendResponse> {
    return new Promise((resolve, reject) => {
        const client = http2.connect(`http://${hostname}:${port}`);
        let timer: ReturnType<typeof setTimeout> | null = null;

        const cleanup = () => {
            if (timer) {
                clearTimeout(timer);
                timer = null;
            }
        };

        client.on("error", (err) => {
            cleanup();
            client.close();
            reject(err);
        });

        const totalSize = chunks.reduce((sum, c) => sum + c.byteLength, 0);
        const headers: http2.OutgoingHttpHeaders = {
            ":path": path,
            ":method": "POST",
            "accept-encoding": "identity",
            "content-type": "application/octet-stream",
        };
        if (includeContentLength) {
            headers["content-length"] = String(totalSize);
        }

        const req = client.request(headers);

        let status = 0;
        const responseChunks: Buffer[] = [];

        timer = setTimeout(() => {
            cleanup();
            client.close();
            reject(new Error("h2c POST request timed out"));
        }, timeoutMs);

        req.on("response", (hdrs) => {
            status = hdrs[":status"] as number;
        });

        req.on("data", (chunk: Buffer) => {
            responseChunks.push(chunk);
        });

        req.on("end", () => {
            cleanup();
            client.close();
            if (status !== 200) {
                reject(new Error(`h2c POST failed with status ${status}`));
                return;
            }
            const body = Buffer.concat(responseChunks).toString("utf-8");
            resolve(JSON.parse(body));
        });

        req.on("error", (err) => {
            cleanup();
            client.close();
            reject(err);
        });

        // Send chunks with delays
        (async () => {
            for (let i = 0; i < chunks.length; i++) {
                req.write(Buffer.from(chunks[i]));
                if (i < chunks.length - 1 && delayMs > 0) {
                    await new Promise((r) => setTimeout(r, delayMs));
                }
            }
            req.end();
        })();
    });
}

function assertStreamingBehavior(
    result: StreamingBackendResponse,
    expectedTotalSize: number,
    chunkCount: number,
    delayMs: number,
    protocol: string,
): void {
    assertEquals(
        result.totalBytes,
        expectedTotalSize,
        `${protocol}: Backend should receive all bytes`,
    );

    // The key assertion: verify the backend received chunks over time,
    // not all at once. If buffered, all chunks would arrive together
    // with minimal time spread. If streamed, the spread should be
    // close to (chunkCount - 1) * delayMs.
    const timeSpread = result.lastChunkAt - result.firstChunkAt;
    const expectedMinSpread = (chunkCount - 1) * delayMs * 0.5; // Allow 50% tolerance

    assert(
        timeSpread >= expectedMinSpread,
        `${protocol}: Request body should be streamed, not buffered. ` +
            `Time spread between first and last chunk: ${timeSpread.toFixed(1)}ms, ` +
            `expected at least ${expectedMinSpread.toFixed(1)}ms (based on ${delayMs}ms delays between ${chunkCount} chunks). ` +
            `If buffered, all chunks would arrive at once.`,
    );

    // Also verify we got multiple chunks (not coalesced into one)
    assert(
        result.chunkCount >= 2,
        `${protocol}: Backend should receive multiple chunks, got ${result.chunkCount}`,
    );
}

Deno.test({
    name: "e2e: request body is streamed to backend over h1 and h2c",
    ignore: !canRunScripts,
    fn: async () => {
        const chunkSize = 64 * 1024; // 64KB chunks
        const chunkCount = 5;
        const delayMs = 100; // 100ms between chunks

        const backend = await startStreamingBackend();
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;

        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "Body streaming test\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/proxy-upload") == 0) {
    zs_req_set_uri(ZS_STR("/upload"));
    zs_reverse_proxy(ZS_STR("${backend.url}"));
  }
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-upload-proxy.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                const totalSize = chunkSize * chunkCount;

                // Test h1 streaming
                const h1Chunks = createDelayedChunks(chunkSize, chunkCount);
                const h1Result = await h1PostWithStreamingBody(
                    baseUrl,
                    "/proxy-upload",
                    h1Chunks,
                    delayMs,
                    true,
                );
                assertStreamingBehavior(h1Result, totalSize, chunkCount, delayMs, "h1");

                // Test h2c streaming
                const h2cChunks = createDelayedChunks(chunkSize, chunkCount);
                const h2cResult = await h2cPostWithStreamingBody(
                    url.hostname,
                    Number(url.port),
                    "/proxy-upload",
                    h2cChunks,
                    delayMs,
                    true,
                );
                assertStreamingBehavior(h2cResult, totalSize, chunkCount, delayMs, "h2c");
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
    name: "e2e: large request body streams without memory issues over h1 and h2c",
    ignore: !canRunScripts,
    fn: async () => {
        // Use a larger body to ensure it's not being fully buffered
        const chunkSize = 256 * 1024; // 256KB chunks
        const chunkCount = 20; // 5MB total
        const delayMs = 10; // Small delay

        const backend = await startStreamingBackend();
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;

        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "Large body streaming test\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/proxy-large") == 0) {
    zs_req_set_uri(ZS_STR("/upload"));
    zs_reverse_proxy(ZS_STR("${backend.url}"));
  }
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-large-proxy.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                const totalSize = chunkSize * chunkCount;
                const expectedMinSpread = (chunkCount - 1) * delayMs * 0.3; // More lenient for larger transfers

                // Test h1 with large body
                const h1Chunks = createDelayedChunks(chunkSize, chunkCount);
                const h1Result = await h1PostWithStreamingBody(
                    baseUrl,
                    "/proxy-large",
                    h1Chunks,
                    delayMs,
                    true,
                );
                assertEquals(
                    h1Result.totalBytes,
                    totalSize,
                    `h1: Backend should receive all ${totalSize} bytes (${(totalSize / 1024 / 1024).toFixed(1)}MB)`,
                );
                const h1Spread = h1Result.lastChunkAt - h1Result.firstChunkAt;
                assert(
                    h1Spread >= expectedMinSpread,
                    `h1: Large request body should be streamed. Time spread: ${h1Spread.toFixed(1)}ms, ` +
                        `expected at least ${expectedMinSpread.toFixed(1)}ms`,
                );

                // Test h2c with large body
                const h2cChunks = createDelayedChunks(chunkSize, chunkCount);
                const h2cResult = await h2cPostWithStreamingBody(
                    url.hostname,
                    Number(url.port),
                    "/proxy-large",
                    h2cChunks,
                    delayMs,
                    true,
                );
                assertEquals(
                    h2cResult.totalBytes,
                    totalSize,
                    `h2c: Backend should receive all ${totalSize} bytes (${(totalSize / 1024 / 1024).toFixed(1)}MB)`,
                );
                const h2cSpread = h2cResult.lastChunkAt - h2cResult.firstChunkAt;
                assert(
                    h2cSpread >= expectedMinSpread,
                    `h2c: Large request body should be streamed. Time spread: ${h2cSpread.toFixed(1)}ms, ` +
                        `expected at least ${expectedMinSpread.toFixed(1)}ms`,
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
    name: "e2e: chunked transfer encoding request body streams correctly over h1 and h2c",
    ignore: !canRunScripts,
    fn: async () => {
        const chunkSize = 32 * 1024; // 32KB chunks
        const chunkCount = 8;
        const delayMs = 75;

        const backend = await startStreamingBackend();
        const siteDir = await Deno.makeTempDir();
        let tarPath: string | null = null;

        try {
            await Deno.writeTextFile(
                join(siteDir, "index.html"),
                "Chunked body streaming test\n",
            );

            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            const scriptSource = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[32];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/proxy-chunked") == 0) {
    zs_req_set_uri(ZS_STR("/upload"));
    zs_reverse_proxy(ZS_STR("${backend.url}"));
  }
  return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-chunked-proxy.c"),
                scriptSource,
            );

            tarPath = await packSite(siteDir);

            await withZeroserve(tarPath, async (baseUrl) => {
                const url = new URL(baseUrl);
                const totalSize = chunkSize * chunkCount;
                const expectedMinSpread = (chunkCount - 1) * delayMs * 0.5;

                // Test h1 chunked (no content-length)
                const h1Chunks = createDelayedChunks(chunkSize, chunkCount);
                const h1Result = await h1PostWithStreamingBody(
                    baseUrl,
                    "/proxy-chunked",
                    h1Chunks,
                    delayMs,
                    false, // No content-length -> chunked encoding
                );
                assertEquals(
                    h1Result.totalBytes,
                    totalSize,
                    "h1: Backend should receive all bytes via chunked encoding",
                );
                const h1Spread = h1Result.lastChunkAt - h1Result.firstChunkAt;
                assert(
                    h1Spread >= expectedMinSpread,
                    `h1: Chunked request body should be streamed. Time spread: ${h1Spread.toFixed(1)}ms, ` +
                        `expected at least ${expectedMinSpread.toFixed(1)}ms`,
                );

                // Test h2c without content-length (h2 uses its own framing, not chunked)
                const h2cChunks = createDelayedChunks(chunkSize, chunkCount);
                const h2cResult = await h2cPostWithStreamingBody(
                    url.hostname,
                    Number(url.port),
                    "/proxy-chunked",
                    h2cChunks,
                    delayMs,
                    false, // No content-length
                );
                assertEquals(
                    h2cResult.totalBytes,
                    totalSize,
                    "h2c: Backend should receive all bytes without content-length",
                );
                const h2cSpread = h2cResult.lastChunkAt - h2cResult.firstChunkAt;
                assert(
                    h2cSpread >= expectedMinSpread,
                    `h2c: Request body without content-length should be streamed. Time spread: ${h2cSpread.toFixed(1)}ms, ` +
                        `expected at least ${expectedMinSpread.toFixed(1)}ms`,
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
