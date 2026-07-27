import { assert, assertEquals } from "@std/assert";
import { join } from "@std/path";
import {
    hasBpfToolchain,
    packSite,
    repoRoot,
    withZeroserve,
} from "./test_utils.ts";

const canRunScripts = await hasBpfToolchain();

Deno.test({
    name: "e2e: rate limiting by custom key",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            // Create a rate limiting script that limits by API key header
            const rateLimitScript = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    char apiKey[128];
    int n = zs_req_header("X-API-Key", 9, apiKey, sizeof(apiKey));

    if (n <= 0) {
        zs_respond(401, ZS_STR("{\\"error\\":\\"missing api key\\"}"));
        return 0;
    }

    // Rate limit by API key: 2 per second
    zs_s64 result = zs_rate_limit(ZS_STR(apiKey), 2, 0, 0);

    if (result != ZS_RATE_LIMIT_ALLOWED) {
        zs_respond(429, ZS_STR("{\\"error\\":\\"rate limit exceeded\\"}"));
        return 0;
    }

    zs_respond(200, ZS_STR("{\\"status\\":\\"ok\\"}"));
    return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-api-key-rate-limit.c"),
                rateLimitScript,
            );

            const tarPath = await packSite(siteDir);
            try {
                await withZeroserve(tarPath, async (baseUrl) => {
                    // Two requests with key "abc" should succeed
                    for (let i = 0; i < 2; i++) {
                        const resp = await fetch(`${baseUrl}/`, {
                            headers: { "X-API-Key": "abc" },
                        });
                        assertEquals(
                            resp.status,
                            200,
                            `Request ${i + 1} with key abc should succeed`,
                        );
                        await resp.body?.cancel();
                    }

                    // Subsequent requests with key "abc" should hit the
                    // per-second limit. The limiter uses fixed wall-clock
                    // second windows, so a rollover between requests can let
                    // extra requests through; keep requesting until the 429
                    // shows up. Rollovers happen at most once per second while
                    // this loop runs in milliseconds, so it converges fast.
                    let sawRateLimit = false;
                    for (let i = 0; i < 8; i++) {
                        const resp = await fetch(`${baseUrl}/`, {
                            headers: { "X-API-Key": "abc" },
                        });
                        await resp.body?.cancel();
                        if (resp.status === 429) {
                            sawRateLimit = true;
                            break;
                        }
                        assertEquals(
                            resp.status,
                            200,
                            `Request ${i + 3} with key abc should be 200 or 429`,
                        );
                    }
                    assert(
                        sawRateLimit,
                        "requests with key abc should eventually be rate limited",
                    );

                    // Request with different key "xyz" should still succeed
                    const respX = await fetch(`${baseUrl}/`, {
                        headers: { "X-API-Key": "xyz" },
                    });
                    assertEquals(
                        respX.status,
                        200,
                        "Request with different key xyz should succeed",
                    );
                    await respX.body?.cancel();

                    // Request without API key should be 401
                    const respNoKey = await fetch(`${baseUrl}/`);
                    assertEquals(
                        respNoKey.status,
                        401,
                        "Request without API key should be 401",
                    );
                    await respNoKey.body?.cancel();
                });
            } finally {
                await Deno.remove(tarPath).catch(() => {});
            }
        } finally {
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});

Deno.test({
    name: "e2e: rate limiting bucket limit",
    ignore: !canRunScripts,
    fn: async () => {
        const siteDir = await Deno.makeTempDir();
        try {
            const scriptsDir = join(siteDir, ".zeroserve", "scripts");
            await Deno.mkdir(scriptsDir, { recursive: true });

            // Create a rate limiting script that limits by API key
            // We'll set max-buckets to 2 and test with 3 different keys
            const rateLimitScript = `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
    char apiKey[128];
    int n = zs_req_header("X-API-Key", 9, apiKey, sizeof(apiKey));

    if (n <= 0) {
        zs_respond(401, ZS_STR("missing api key"));
        return 0;
    }

    // Rate limit by API key with high limits
    zs_s64 result = zs_rate_limit(ZS_STR(apiKey), 1000, 1000, 1000);

    if (result == ZS_RATE_LIMIT_EXCEEDED_BUCKET_LIMIT) {
        zs_respond(429, ZS_STR("bucket limit exceeded"));
        return 0;
    }
    if (result != ZS_RATE_LIMIT_ALLOWED) {
        zs_respond(429, ZS_STR("rate limit exceeded"));
        return 0;
    }

    zs_respond(200, ZS_STR("OK"));
    return 0;
}
`;
            await Deno.writeTextFile(
                join(scriptsDir, "10-rate-limit.c"),
                rateLimitScript,
            );

            const tarPath = await packSite(siteDir);
            try {
                // Start zeroserve with max-rate-limit-buckets=2
                const zeroservePath = await import("./test_utils.ts").then((m) =>
                    m.getZeroservePath()
                );
                const port = await Deno.makeTempFile().then(() =>
                    Deno.listen({ hostname: "127.0.0.1", port: 0 })
                ).then((l) => {
                    const p = (l.addr as Deno.NetAddr).port;
                    l.close();
                    return p;
                });

                const child = new Deno.Command(zeroservePath, {
                    args: [
                        "--addr",
                        `127.0.0.1:${port}`,
                        "--disable-request-logging",
                        "--max-rate-limit-buckets",
                        "2",
                        tarPath,
                    ],
                    cwd: repoRoot,
                    stdin: "null",
                    stdout: "null",
                    stderr: "inherit",
                }).spawn();

                const statusPromise = child.status;

                // Wait for server
                const deadline = Date.now() + 10000;
                let connected = false;
                while (Date.now() < deadline && !connected) {
                    try {
                        const conn = await Deno.connect({
                            hostname: "127.0.0.1",
                            port,
                        });
                        conn.close();
                        connected = true;
                    } catch {
                        await new Promise((r) => setTimeout(r, 100));
                    }
                }
                if (!connected) {
                    throw new Error("server failed to start");
                }

                try {
                    const baseUrl = `http://127.0.0.1:${port}`;

                    // First two unique keys should succeed
                    const resp1 = await fetch(`${baseUrl}/`, {
                        headers: { "X-API-Key": "key1" },
                    });
                    assertEquals(resp1.status, 200, "First key should succeed");
                    await resp1.body?.cancel();

                    const resp2 = await fetch(`${baseUrl}/`, {
                        headers: { "X-API-Key": "key2" },
                    });
                    assertEquals(resp2.status, 200, "Second key should succeed");
                    await resp2.body?.cancel();

                    // Third unique key should hit bucket limit
                    const resp3 = await fetch(`${baseUrl}/`, {
                        headers: { "X-API-Key": "key3" },
                    });
                    assertEquals(
                        resp3.status,
                        429,
                        "Third key should hit bucket limit",
                    );
                    const body3 = await resp3.text();
                    assert(
                        body3.includes("bucket limit"),
                        `Expected "bucket limit" in body, got: ${body3}`,
                    );

                    // Existing keys should still work
                    const resp1Again = await fetch(`${baseUrl}/`, {
                        headers: { "X-API-Key": "key1" },
                    });
                    assertEquals(
                        resp1Again.status,
                        200,
                        "Existing key should still work",
                    );
                    await resp1Again.body?.cancel();
                } finally {
                    try {
                        child.kill("SIGTERM");
                    } catch {
                        // ignore
                    }
                    await statusPromise.catch(() => {});
                }
            } finally {
                await Deno.remove(tarPath).catch(() => {});
            }
        } finally {
            await Deno.remove(siteDir, { recursive: true }).catch(() => {});
        }
    },
});
