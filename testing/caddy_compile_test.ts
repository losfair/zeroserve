import { assert, assertEquals } from "@std/assert";
import { join, relative } from "@std/path";
import * as http2 from "node:http2";
import { Buffer } from "node:buffer";
import {
  generateSelfSignedCert,
  getZeroservePath,
  hasBpfToolchain,
  packSite,
  repoRoot,
  withZeroserve,
  withZeroserveTls,
} from "./test_utils.ts";

const canRunScripts = await hasBpfToolchain();

function h2cPost(
  hostname: string,
  port: number,
  path: string,
  body: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const client = http2.connect(`http://${hostname}:${port}`);
    client.on("error", (err) => {
      client.close();
      reject(err);
    });

    const req = client.request({
      ":path": path,
      ":method": "POST",
      "content-length": String(new TextEncoder().encode(body).length),
      ...headers,
    });
    let status = 0;
    const chunks: Buffer[] = [];

    req.on("response", (hdrs) => {
      status = hdrs[":status"] as number;
    });
    req.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
    });
    req.on("end", () => {
      client.close();
      resolve({ status, body: Buffer.concat(chunks).toString("utf-8") });
    });
    req.on("error", (err) => {
      client.close();
      reject(err);
    });
    req.end(body);
  });
}

async function h2PostTls(
  baseUrl: string,
  path: string,
  body: string,
  certPath: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; body: string }> {
  const caCert = await Deno.readTextFile(certPath);
  const client = Deno.createHttpClient({
    caCerts: [caCert],
    http2: true,
  });
  try {
    const res = await fetch(`${baseUrl}${path}`, {
      client,
      method: "POST",
      body,
      headers: {
        "Content-Type": "text/plain",
        ...headers,
      },
    });
    return { status: res.status, body: await res.text() };
  } finally {
    client.close();
  }
}

async function gzipBytes(input: string): Promise<Uint8Array> {
  const stream = new Blob([input]).stream().pipeThrough(
    new CompressionStream("gzip"),
  );
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function startBackend(): Promise<
  { dial: string; close: () => Promise<void> }
> {
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
      const requestPath = new URL(req.url).pathname;
      if (
        requestPath === "/forwarded" ||
        requestPath === "/trusted-forwarded" ||
        requestPath === "/header-up-forwarded" ||
        requestPath === "/delete-forwarded" ||
        requestPath === "/server-trusted-forwarded"
      ) {
        return Response.json({
          forwardedFor: req.headers.get("x-forwarded-for"),
          forwardedProto: req.headers.get("x-forwarded-proto"),
          forwardedHost: req.headers.get("x-forwarded-host"),
          te: req.headers.get("te"),
          altSvc: req.headers.get("alt-svc"),
          proxyAuthenticate: req.headers.get("proxy-authenticate"),
          proxyAuthorization: req.headers.get("proxy-authorization"),
          userAgent: req.headers.get("user-agent"),
        });
      }
      if (new URL(req.url).pathname === "/teapot") {
        return new Response("upstream body", {
          status: 418,
          headers: {
            "X-Copy-Me": "copied",
            "X-Secret-Token": "backend-secret",
          },
        });
      }
      if (new URL(req.url).pathname === "/proxy-host") {
        return Response.json({
          host: req.headers.get("host"),
        });
      }
      if (new URL(req.url).pathname === "/header-order") {
        const headers = new Headers();
        headers.append("X-Order", "upstream");
        return new Response("ordered", { headers });
      }
      if (new URL(req.url).pathname === "/header-leak") {
        return Response.json({
          upstreamOnly: req.headers.get("x-upstream-only"),
          original: req.headers.get("x-original"),
          forwardedFor: req.headers.get("x-forwarded-for"),
        });
      }
      const bodyText = await req.text();
      const res = Response.json({
        method: req.method,
        path: new URL(req.url).pathname,
        query: new URL(req.url).search,
        body: bodyText,
        header: req.headers.get("x-caddy-compiled"),
        rewrittenMethodHeader: req.headers.get("x-rewritten-method"),
        rewrittenPathHeader: req.headers.get("x-rewritten-path"),
        upstreamAddress: req.headers.get("x-upstream-address"),
        upstreamHost: req.headers.get("x-upstream-host"),
        upstreamPort: req.headers.get("x-upstream-port"),
        addedHeader: req.headers.get("x-caddy-added"),
        removedHeader: req.headers.get("x-remove-me"),
      });
      res.headers.set("X-Secret-Token", "backend-secret");
      res.headers.set("X-Origin-Match", "ok-from-backend");
      return res;
    },
  );

  if (port === 0) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  if (port === 0) {
    controller.abort();
    await server.finished;
    throw new Error("failed to start backend");
  }

  return {
    dial: `127.0.0.1:${port}`,
    close: async () => {
      controller.abort();
      await server.finished;
    },
  };
}

async function startUnixBackend(): Promise<
  { dial: string; socketPath: string; close: () => Promise<void> }
> {
  const socketPath = await Deno.makeTempFile();
  await Deno.remove(socketPath);
  const controller = new AbortController();
  const server = Deno.serve(
    {
      path: socketPath,
      transport: "unix",
      signal: controller.signal,
      onListen() {},
    },
    async (req) => {
      const url = new URL(req.url);
      const bodyText = await req.text();
      return Response.json({
        method: req.method,
        path: url.pathname,
        query: url.search,
        body: bodyText,
        host: req.headers.get("host"),
        upstreamAddress: req.headers.get("x-upstream-address"),
        upstreamHost: req.headers.get("x-upstream-host"),
        upstreamPort: req.headers.get("x-upstream-port"),
      });
    },
  );

  return {
    dial: `unix/${socketPath}`,
    socketPath,
    close: async () => {
      controller.abort();
      await server.finished.catch(() => {});
      await Deno.remove(socketPath).catch(() => {});
    },
  };
}

async function startForwardAuthBackends(): Promise<
  {
    authDial: string;
    appDial: string;
    authRequests: () => Array<{ method: string; path: string; body: string }>;
    close: () => Promise<void>;
  }
> {
  const authController = new AbortController();
  const appController = new AbortController();
  let authPort = 0;
  let appPort = 0;
  const authRequests: Array<{ method: string; path: string; body: string }> =
    [];
  const authServer = Deno.serve(
    {
      hostname: "127.0.0.1",
      port: 0,
      signal: authController.signal,
      onListen: ({ port }) => {
        authPort = port;
      },
    },
    async (req) => {
      const path = new URL(req.url).pathname;
      authRequests.push({
        method: req.method,
        path,
        body: await req.text(),
      });
      if (path === "/deny") {
        return new Response("denied", { status: 401 });
      }
      return new Response(null, {
        status: 204,
        headers: { "Remote-User": "alice" },
      });
    },
  );
  const appServer = Deno.serve(
    {
      hostname: "127.0.0.1",
      port: 0,
      signal: appController.signal,
      onListen: ({ port }) => {
        appPort = port;
      },
    },
    async (req) =>
      Response.json({
        method: req.method,
        path: new URL(req.url).pathname,
        remoteUser: req.headers.get("remote-user"),
        xAuthUser: req.headers.get("x-auth-user"),
        body: await req.text(),
      }),
  );

  for (let i = 0; i < 10 && (authPort === 0 || appPort === 0); i++) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  if (authPort === 0 || appPort === 0) {
    authController.abort();
    appController.abort();
    await Promise.allSettled([authServer.finished, appServer.finished]);
    throw new Error("failed to start forward_auth backends");
  }

  return {
    authDial: `127.0.0.1:${authPort}`,
    appDial: `127.0.0.1:${appPort}`,
    authRequests: () => authRequests.slice(),
    close: async () => {
      authController.abort();
      appController.abort();
      await Promise.allSettled([authServer.finished, appServer.finished]);
    },
  };
}

async function startRawTeapotBackend(): Promise<
  { dial: string; close: () => Promise<void> }
> {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  let closed = false;
  const serveTask = (async () => {
    while (!closed) {
      let conn: Deno.Conn;
      try {
        conn = await listener.accept();
      } catch (err) {
        if (closed || err instanceof Deno.errors.BadResource) {
          break;
        }
        throw err;
      }
      void (async () => {
        try {
          const buf = new Uint8Array(1024);
          await conn.read(buf);
          const response = [
            "HTTP/1.1 418 I'm a Teapot",
            "Connection: close",
            "Content-Length: 13",
            "Content-Type: text/plain;charset=UTF-8",
            "X-Copy-Me: copied",
            "X-Secret-Token: backend-secret",
            "X-Multi-Copy: one",
            "X-Multi-Copy: two",
            "X-Placeholder-Match: ready",
            "",
            "upstream body",
          ].join("\r\n");
          await conn.write(new TextEncoder().encode(response));
        } finally {
          conn.close();
        }
      })();
    }
  })();
  const addr = listener.addr as Deno.NetAddr;
  return {
    dial: `${addr.hostname}:${addr.port}`,
    close: async () => {
      closed = true;
      listener.close();
      await serveTask;
    },
  };
}

async function startRawHeaderCaptureBackend(): Promise<
  { dial: string; requestHead: Promise<string>; close: () => Promise<void> }
> {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  let closed = false;
  const requestHead = (async () => {
    const conn = await listener.accept();
    try {
      let raw = "";
      const decoder = new TextDecoder();
      const buf = new Uint8Array(1024);
      while (!raw.includes("\r\n\r\n")) {
        const n = await conn.read(buf);
        if (n === null) {
          break;
        }
        raw += decoder.decode(buf.subarray(0, n), { stream: true });
      }
      const response = [
        "HTTP/1.1 200 OK",
        "Connection: close",
        "Content-Length: 2",
        "",
        "ok",
      ].join("\r\n");
      await conn.write(new TextEncoder().encode(response));
      return raw.split("\r\n\r\n", 1)[0];
    } finally {
      conn.close();
      if (!closed) {
        closed = true;
        listener.close();
      }
    }
  })();
  const addr = listener.addr as Deno.NetAddr;
  return {
    dial: `${addr.hostname}:${addr.port}`,
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

async function rawHttpGet(
  baseUrl: string,
  path: string,
  host: string,
  extraHeaders: Record<string, string> = {},
): Promise<
  {
    status: number;
    headers: Record<string, string>;
    headerLines: string[];
    body: string;
  }
> {
  return await rawHttpGetWithHeaderLines(
    baseUrl,
    path,
    host,
    Object.entries(extraHeaders).map(([name, value]) => `${name}: ${value}`),
  );
}

async function rawHttpGetWithHeaderLines(
  baseUrl: string,
  path: string,
  host: string,
  extraHeaderLines: string[] = [],
): Promise<
  {
    status: number;
    headers: Record<string, string>;
    headerLines: string[];
    body: string;
  }
> {
  const url = new URL(baseUrl);
  const conn = await Deno.connect({
    hostname: url.hostname,
    port: Number(url.port),
  });
  try {
    const headerLines = extraHeaderLines
      .map((line) => `${line}\r\n`)
      .join("");
    const request =
      `GET ${path} HTTP/1.1\r\nHost: ${host}\r\n${headerLines}Connection: close\r\n\r\n`;
    await conn.write(new TextEncoder().encode(request));
    const chunks: Uint8Array[] = [];
    const buf = new Uint8Array(4096);
    while (true) {
      const n = await conn.read(buf);
      if (n === null) {
        break;
      }
      chunks.push(buf.slice(0, n));
      const response = concatBytes(chunks);
      const split = findHeaderEnd(response);
      if (split >= 0) {
        const head = new TextDecoder().decode(response.slice(0, split));
        const body = response.slice(split + 4);
        const status = Number(head.split(/\s+/)[1]);
        if (
          (status >= 100 && status < 200) || status === 204 || status === 304
        ) {
          return parseRawResponse(head, "");
        }
        const length = head
          .split("\r\n")
          .find((line) => line.toLowerCase().startsWith("content-length:"))
          ?.split(":")
          .slice(1)
          .join(":")
          .trim();
        if (length && body.byteLength >= Number(length)) {
          return await parseRawResponseBytes(
            head,
            body.slice(0, Number(length)),
          );
        }
      }
    }
    const response = concatBytes(chunks);
    const split = findHeaderEnd(response);
    if (split < 0) {
      return parseRawResponse(new TextDecoder().decode(response), "");
    }
    return await parseRawResponseBytes(
      new TextDecoder().decode(response.slice(0, split)),
      response.slice(split + 4),
    );
  } finally {
    conn.close();
  }
}

async function rawHttpRequest(
  baseUrl: string,
  request: string,
): Promise<{
  status: number;
  headers: Record<string, string>;
  headerLines: string[];
  body: string;
}> {
  const response = await rawHttpPipeline(baseUrl, [request]);
  const [head, body = ""] = response.split("\r\n\r\n");
  return parseRawResponse(head, body);
}

async function rawHttpPipeline(
  baseUrl: string,
  requests: string[],
): Promise<string> {
  const url = new URL(baseUrl);
  const conn = await Deno.connect({
    hostname: url.hostname,
    port: Number(url.port),
  });
  try {
    await conn.write(new TextEncoder().encode(requests.join("")));
    const chunks: Uint8Array[] = [];
    const buf = new Uint8Array(4096);
    while (true) {
      const n = await Promise.race([
        conn.read(buf),
        new Promise<null>((resolve) => setTimeout(() => resolve(null), 500)),
      ]);
      if (n === null) {
        break;
      }
      chunks.push(buf.slice(0, n));
    }
    return new TextDecoder().decode(concatBytes(chunks));
  } finally {
    conn.close();
  }
}

function parseRawResponse(
  head: string,
  body: string,
): {
  status: number;
  headers: Record<string, string>;
  headerLines: string[];
  body: string;
} {
  const [statusLine, ...headerLines] = head.split("\r\n");
  const headers: Record<string, string> = {};
  for (const line of headerLines) {
    const split = line.indexOf(":");
    if (split < 0) {
      continue;
    }
    const name = line.slice(0, split).trim().toLowerCase();
    const value = line.slice(split + 1).trim();
    headers[name] = headers[name] ? `${headers[name]},${value}` : value;
  }
  return {
    status: Number(statusLine.split(/\s+/)[1]),
    headers,
    headerLines,
    body,
  };
}

async function parseRawResponseBytes(
  head: string,
  bodyBytes: Uint8Array,
): Promise<{
  status: number;
  headers: Record<string, string>;
  headerLines: string[];
  body: string;
}> {
  const response = parseRawResponse(head, "");
  if (response.headers["content-encoding"]?.toLowerCase() === "gzip") {
    const compressed = new ArrayBuffer(bodyBytes.byteLength);
    new Uint8Array(compressed).set(bodyBytes);
    const stream = new Blob([compressed]).stream().pipeThrough(
      new DecompressionStream("gzip"),
    );
    bodyBytes = new Uint8Array(await new Response(stream).arrayBuffer());
  }
  response.body = new TextDecoder().decode(bodyBytes);
  return response;
}

function findHeaderEnd(bytes: Uint8Array): number {
  for (let i = 0; i + 3 < bytes.length; i++) {
    if (
      bytes[i] === 13 &&
      bytes[i + 1] === 10 &&
      bytes[i + 2] === 13 &&
      bytes[i + 3] === 10
    ) {
      return i;
    }
  }
  return -1;
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

Deno.test({
  name: "compile Caddy JSON to eBPF middleware and serve it",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "public", "static", "docs"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "public", "static", "private"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "public", "limited"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "public", "assets"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "public", "assets", "private"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "file.txt"),
        "from caddy file server",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "app.js"),
        "console.log('caddy');",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "space name.txt"),
        "space",
      );
      await Deno.mkdir(join(siteDir, "public", "static", "space dir"), {
        recursive: true,
      });
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "space dir", "child.txt"),
        "space child",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "%.html"),
        "percent file",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "?.html"),
        "question file",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "nested%2Ffile.html"),
        "encoded slash file",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "no-type.caddyunknown"),
        "unknown content type",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "empty-etag.txt"),
        "empty etag sidecar",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "empty-etag.txt.etag"),
        "",
      );
      await Deno.writeFile(
        join(siteDir, "public", "static", "file.txt.gz"),
        await gzipBytes("from caddy gzip sidecar"),
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "assets", "existing.txt"),
        "pass-through hit",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "assets", "private", "nested.txt"),
        "hidden pass-through file",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "secret.txt"),
        "hidden",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "priv8.txt"),
        "hidden by glob",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "private", "nested.txt"),
        "hidden by path prefix",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "static", "docs", "index.txt"),
        "directory index",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "limited", "a.txt"),
        "a",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "limited", "b.txt"),
        "b",
      );
      const olderStaticMtime = new Date("2019-01-03T04:05:06Z");
      for (
        const rel of [
          "file.txt",
          "app.js",
          "file.txt.gz",
          "space name.txt",
          "%.html",
          "?.html",
          "nested%2Ffile.html",
          "no-type.caddyunknown",
          "empty-etag.txt",
          "empty-etag.txt.etag",
          "secret.txt",
          "priv8.txt",
          "docs",
          "space dir",
          join("space dir", "child.txt"),
          "private",
        ]
      ) {
        await Deno.utime(
          join(siteDir, "public", "static", rel),
          olderStaticMtime,
          olderStaticMtime,
        );
      }
      const staticDirMtime = new Date("2020-01-03T04:05:06Z");
      await Deno.utime(
        join(siteDir, "public", "static"),
        staticDirMtime,
        staticDirMtime,
      );

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{
                      method: ["GET", "POST"],
                      path: ["/API/*"],
                      query: { debug: ["2"] },
                    }],
                    handle: [
                      {
                        handler: "rewrite",
                        method: "post",
                        uri: "?compiled=1",
                      },
                      {
                        handler: "request_body",
                        max_size: 8,
                      },
                      {
                        handler: "headers",
                        request: {
                          add: {
                            "X-Caddy-Added": ["one"],
                          },
                          delete: ["X-Remove-*"],
                          set: {
                            "X-Caddy-Compiled": ["yes"],
                          },
                        },
                        response: {
                          add: {
                            "X-Added-Response": ["one"],
                          },
                          delete: ["X-Secret-*"],
                          set: {
                            "Cache-Control": ["no-store"],
                          },
                          require: {
                            status_code: [2],
                            headers: {
                              "X-Origin-Match": ["ok*"],
                            },
                          },
                        },
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                  },
                  {
                    match: [{ method: ["GET", "POST"], path: ["/static*"] }],
                    handle: [
                      {
                        handler: "file_server",
                        root: "public",
                        hide: [
                          "secret.txt",
                          "priv?.txt",
                          "public/static/private",
                        ],
                        index_names: ["index.txt"],
                        browse: { sort: ["name", "asc"] },
                        precompressed: { gzip: {} },
                        precompressed_order: ["gzip"],
                        etag_file_extensions: [".etag"],
                        status_code: 203,
                      },
                    ],
                  },
                  {
                    match: [{
                      expression:
                        "path('/expr/*') && method('GET') && query({'mode': ['debug']}) && header({'X-Mode': ['debug']})",
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 226,
                        body: "expression matched",
                      },
                    ],
                  },
                  {
                    match: [{ method: ["GET"], path: ["/assets*"] }],
                    handle: [
                      {
                        handler: "file_server",
                        root: "public",
                        browse: {},
                        pass_thru: true,
                        hide: ["public/assets/private"],
                      },
                      {
                        handler: "static_response",
                        status_code: 299,
                        body: "asset fallback",
                      },
                    ],
                  },
                  {
                    match: [{ method: ["GET"], path: ["/limited*"] }],
                    handle: [
                      {
                        handler: "file_server",
                        root: "public",
                        browse: { file_limit: 1, sort: ["name", "asc"] },
                      },
                    ],
                  },
                  {
                    match: [{ method: ["GET"], path: ["/intercept"] }],
                    handle: [
                      {
                        handler: "intercept",
                        handle_response: [
                          {
                            match: { status_code: [2] },
                            status_code: 218,
                          },
                        ],
                      },
                      {
                        handler: "static_response",
                        status_code: 201,
                        body: "intercept body",
                      },
                    ],
                  },
                  {
                    match: [{
                      method: ["GET"],
                      path: ["/intercept-placeholders"],
                    }],
                    handle: [
                      {
                        handler: "intercept",
                        handle_response: [
                          {
                            match: { status_code: [2] },
                            routes: [
                              {
                                terminal: true,
                                handle: [
                                  {
                                    handler: "headers",
                                    response: {
                                      set: {
                                        "X-Intercept-Status": [
                                          "{http.intercept.status_code}",
                                        ],
                                        "X-Intercept-Origin": [
                                          "{http.intercept.header.X-Origin}",
                                        ],
                                      },
                                    },
                                  },
                                ],
                              },
                            ],
                          },
                        ],
                      },
                      {
                        handler: "static_response",
                        status_code: 202,
                        body: "intercept placeholder body",
                        headers: {
                          "X-Origin": ["intercept-origin"],
                        },
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/items?debug=1&debug=2`, {
          headers: {
            "X-Remove-Me": "remove-this",
          },
        });
        assertEquals(res.status, 200);
        assertEquals(res.headers.get("cache-control"), "no-store");
        assertEquals(res.headers.get("x-added-response"), "one");
        assertEquals(res.headers.get("x-origin-match"), "ok-from-backend");
        assertEquals(res.headers.get("x-secret-token"), null);
        const body = await res.json();
        assertEquals(body, {
          method: "POST",
          path: "/api/items",
          query: "?compiled=1",
          body: "",
          header: "yes",
          upstreamAddress: null,
          upstreamHost: null,
          upstreamPort: null,
          addedHeader: "one",
          removedHeader: null,
          rewrittenMethodHeader: null,
          rewrittenPathHeader: null,
        });

        const oversized = await fetch(`${baseUrl}/api/items?debug=2`, {
          method: "POST",
          body: "this body is too large",
        });
        assertEquals(oversized.status, 413);
        assertEquals(await oversized.text(), "Request Entity Too Large");

        const intercepted = await fetch(`${baseUrl}/intercept`);
        assertEquals(intercepted.status, 201);
        assertEquals(await intercepted.text(), "intercept body");

        const interceptedPlaceholders = await fetch(
          `${baseUrl}/intercept-placeholders`,
        );
        assertEquals(interceptedPlaceholders.status, 202);
        assertEquals(
          interceptedPlaceholders.headers.get("x-intercept-status"),
          "202",
        );
        assertEquals(
          interceptedPlaceholders.headers.get("x-intercept-origin"),
          "intercept-origin",
        );
        assertEquals(
          await interceptedPlaceholders.text(),
          "intercept placeholder body",
        );

        const exprMatched = await fetch(`${baseUrl}/expr/ok?mode=debug`, {
          headers: { "X-Mode": "debug" },
        });
        assertEquals(exprMatched.status, 226);
        assertEquals(await exprMatched.text(), "expression matched");

        const exprMiss = await fetch(`${baseUrl}/expr/ok?mode=release`, {
          headers: { "X-Mode": "release" },
        });
        assertEquals(exprMiss.status, 200);

        const fileRes = await fetch(`${baseUrl}/static/file.txt`, {
          headers: { "Accept-Encoding": "identity" },
        });
        assertEquals(fileRes.status, 203);
        assertEquals(typeof fileRes.headers.get("last-modified"), "string");
        assertEquals(typeof fileRes.headers.get("etag"), "string");
        assertEquals(await fileRes.text(), "from caddy file server");

        const jsRes = await fetch(`${baseUrl}/static/app.js`);
        assertEquals(jsRes.status, 203);
        assertEquals(
          jsRes.headers.get("content-type"),
          "text/javascript; charset=utf-8",
        );
        assertEquals(await jsRes.text(), "console.log('caddy');");

        const percentFileRes = await fetch(`${baseUrl}/static/%25.html`);
        assertEquals(percentFileRes.status, 203);
        assertEquals(await percentFileRes.text(), "percent file");

        const questionFileRes = await fetch(`${baseUrl}/static/%3F.html`);
        assertEquals(questionFileRes.status, 203);
        assertEquals(await questionFileRes.text(), "question file");

        const encodedSlashFileRes = await fetch(
          `${baseUrl}/static/nested%252Ffile.html`,
        );
        assertEquals(encodedSlashFileRes.status, 203);
        assertEquals(await encodedSlashFileRes.text(), "encoded slash file");

        const unknownTypeRes = await fetch(
          `${baseUrl}/static/no-type.caddyunknown`,
        );
        assertEquals(unknownTypeRes.status, 203);
        assertEquals(unknownTypeRes.headers.get("content-type"), null);
        assertEquals(await unknownTypeRes.text(), "unknown content type");

        const emptyEtagRes = await fetch(`${baseUrl}/static/empty-etag.txt`, {
          headers: { "Accept-Encoding": "identity" },
        });
        assertEquals(emptyEtagRes.status, 203);
        assertEquals(emptyEtagRes.headers.get("etag"), null);
        assertEquals(await emptyEtagRes.text(), "empty etag sidecar");

        const emptyEtagQuotedConditionalRes = await fetch(
          `${baseUrl}/static/empty-etag.txt`,
          {
            headers: {
              "Accept-Encoding": "identity",
              "If-None-Match": '""',
            },
          },
        );
        assertEquals(emptyEtagQuotedConditionalRes.status, 203);
        assertEquals(
          await emptyEtagQuotedConditionalRes.text(),
          "empty etag sidecar",
        );

        const emptyEtagStarConditionalRes = await fetch(
          `${baseUrl}/static/empty-etag.txt`,
          {
            headers: {
              "Accept-Encoding": "identity",
              "If-None-Match": "*",
            },
          },
        );
        assertEquals(emptyEtagStarConditionalRes.status, 203);
        assertEquals(emptyEtagStarConditionalRes.headers.get("etag"), null);
        assertEquals(await emptyEtagStarConditionalRes.text(), "");

        const conditionalFileRes = await fetch(`${baseUrl}/static/file.txt`, {
          headers: {
            "Accept-Encoding": "identity",
            "If-None-Match": fileRes.headers.get("etag")!,
          },
        });
        assertEquals(conditionalFileRes.status, 203);
        assertEquals(
          conditionalFileRes.headers.get("vary"),
          "Accept-Encoding",
        );
        assertEquals(conditionalFileRes.headers.get("content-length"), "0");
        assertEquals(await conditionalFileRes.text(), "");

        const failedPreconditionFileRes = await fetch(
          `${baseUrl}/static/file.txt`,
          {
            headers: {
              "Accept-Encoding": "identity",
              "If-Match": '"does-not-match"',
            },
          },
        );
        assertEquals(failedPreconditionFileRes.status, 203);
        assertEquals(
          failedPreconditionFileRes.headers.get("vary"),
          "Accept-Encoding",
        );
        assertEquals(
          failedPreconditionFileRes.headers.get("content-length"),
          "0",
        );
        assertEquals(await failedPreconditionFileRes.text(), "");

        const filePost = await fetch(`${baseUrl}/static/file.txt`, {
          method: "POST",
          headers: { "Accept-Encoding": "identity" },
        });
        assertEquals(filePost.status, 405);
        assertEquals(filePost.headers.get("allow"), "GET, HEAD");

        const missingFilePost = await fetch(`${baseUrl}/static/missing.txt`, {
          method: "POST",
          headers: { "Accept-Encoding": "identity" },
        });
        assertEquals(missingFilePost.status, 404);
        assertEquals(missingFilePost.headers.get("allow"), null);

        const rangeRes = await fetch(`${baseUrl}/static/file.txt`, {
          headers: {
            "Accept-Encoding": "identity",
            Range: "bytes=5-9",
          },
        });
        assertEquals(rangeRes.status, 203);
        assertEquals(rangeRes.headers.get("content-range"), "bytes 5-9/22");
        assertEquals(await rangeRes.text(), "caddy");

        const badRangeRes = await fetch(`${baseUrl}/static/file.txt`, {
          headers: {
            "Accept-Encoding": "identity",
            Range: "bytes=999-1000",
          },
        });
        assertEquals(badRangeRes.status, 203);
        assertEquals(badRangeRes.headers.get("content-range"), "bytes */22");
        assertEquals(
          await badRangeRes.text(),
          "invalid range: failed to overlap\n",
        );

        const gzipRes = await fetch(`${baseUrl}/static/file.txt`, {
          headers: { "Accept-Encoding": "gzip" },
        });
        assertEquals(gzipRes.status, 203);
        assertEquals(await gzipRes.text(), "from caddy gzip sidecar");

        const hiddenRes = await fetch(`${baseUrl}/static/secret.txt`);
        assertEquals(hiddenRes.status, 404);
        const hiddenGlobRes = await fetch(`${baseUrl}/static/priv8.txt`);
        assertEquals(hiddenGlobRes.status, 404);
        const hiddenNestedRes = await fetch(
          `${baseUrl}/static/private/nested.txt`,
        );
        assertEquals(hiddenNestedRes.status, 404);

        const browseRes = await fetch(`${baseUrl}/static/`, {
          headers: { Accept: "application/json" },
        });
        assertEquals(browseRes.status, 200);
        const browseLastModified = browseRes.headers.get("last-modified");
        assertEquals(browseLastModified, "Fri, 03 Jan 2020 04:05:06 GMT");
        const browseBody = await browseRes.text();
        assertEquals(browseBody.endsWith("\n"), true);
        const listing = JSON.parse(browseBody);
        assertEquals(Array.isArray(listing), true);
        assertEquals(listing.length, 13);
        assertEquals(
          listing.some((item: { name: string }) => item.name === "file.txt"),
          true,
        );
        const fileItem = listing.find((item: { name: string }) =>
          item.name === "file.txt"
        );
        assertEquals(fileItem.mod_time, "2019-01-03T04:05:06Z");
        const docsItem = listing.find((item: { name: string }) =>
          item.name === "docs/"
        );
        assertEquals(docsItem.url, "./docs/");
        const spaceItem = listing.find((item: { name: string }) =>
          item.name === "space name.txt"
        );
        assertEquals(spaceItem.url, "./space%20name.txt");
        const spaceDirItem = listing.find((item: { name: string }) =>
          item.name === "space dir/"
        );
        assertEquals(spaceDirItem.url, "./space%20dir/");
        const spaceDirBrowseRes = await fetch(
          `${baseUrl}/static/space%20dir/`,
          {
            headers: { Accept: "application/json" },
          },
        );
        assertEquals(spaceDirBrowseRes.status, 200);
        const spaceDirListing = await spaceDirBrowseRes.json();
        assertEquals(Array.isArray(spaceDirListing), true);
        assertEquals(spaceDirListing[0].name, "child.txt");
        assertEquals(
          listing.some((item: { name: string }) => item.name === "secret.txt"),
          false,
        );
        assertEquals(
          listing.some((item: { name: string }) => item.name === "priv8.txt"),
          false,
        );
        const browseNoSlashRes = await fetch(`${baseUrl}/static`, {
          headers: { Accept: "application/json" },
          redirect: "manual",
        });
        assertEquals(browseNoSlashRes.status, 308);
        assertEquals(browseNoSlashRes.headers.get("location"), "/static/");
        assertEquals(await browseNoSlashRes.text(), "");
        const browseTextRes = await fetch(`${baseUrl}/static/`, {
          headers: { Accept: "text/plain" },
        });
        assertEquals(browseTextRes.status, 200);
        const browseText = await browseTextRes.text();
        assert(
          browseText.includes("file.txt\t22 B\t"),
          `unexpected browse text body: ${browseText}`,
        );
        assertEquals(
          listing.some((item: { name: string }) => item.name === "private/"),
          true,
        );
        const freshBrowseRes = await fetch(`${baseUrl}/static/`, {
          headers: {
            Accept: "application/json",
            "If-Modified-Since": browseLastModified!,
          },
        });
        assertEquals(freshBrowseRes.status, 304);
        assertEquals(await freshBrowseRes.text(), "");

        const redirectRes = await fetch(`${baseUrl}/static/docs?x=1`, {
          redirect: "manual",
        });
        assertEquals(redirectRes.status, 308);
        assertEquals(redirectRes.headers.get("location"), "/static/docs/?x=1");

        const indexRes = await fetch(`${baseUrl}/static/docs/`);
        assertEquals(indexRes.status, 203);
        assertEquals(await indexRes.text(), "directory index");

        const limitedBrowseRes = await fetch(`${baseUrl}/limited/`, {
          headers: { Accept: "application/json" },
        });
        assertEquals(limitedBrowseRes.status, 200);
        const limitedListing = await limitedBrowseRes.json();
        assertEquals(limitedListing.length, 1);
        assertEquals(limitedListing[0].name, "b.txt");

        const passThruHit = await fetch(`${baseUrl}/assets/existing.txt`);
        assertEquals(passThruHit.status, 200);
        assertEquals(await passThruHit.text(), "pass-through hit");

        const passThruMiss = await fetch(`${baseUrl}/assets/missing.txt`);
        assertEquals(passThruMiss.status, 299);
        assertEquals(await passThruMiss.text(), "asset fallback");

        const passThruHidden = await fetch(
          `${baseUrl}/assets/private/nested.txt`,
        );
        assertEquals(passThruHidden.status, 299);
        assertEquals(await passThruHidden.text(), "asset fallback");

        const passThruHiddenDir = await fetch(`${baseUrl}/assets/private/`);
        assertEquals(passThruHiddenDir.status, 299);
        assertEquals(await passThruHiddenDir.text(), "asset fallback");
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy intercept status zero runs response routes",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/intercept-zero-routes"] }],
                    handle: [
                      {
                        handler: "intercept",
                        handle_response: [
                          {
                            match: { status_code: [2] },
                            status_code: 0,
                            routes: [
                              {
                                terminal: true,
                                handle: [
                                  {
                                    handler: "headers",
                                    response: {
                                      set: {
                                        "X-Intercept-Zero": ["yes"],
                                      },
                                    },
                                  },
                                ],
                              },
                            ],
                          },
                          {
                            match: { status_code: [2] },
                            status_code: 299,
                          },
                        ],
                      },
                      {
                        handler: "static_response",
                        status_code: 203,
                        body: "intercept zero body",
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/intercept-zero-routes`);
        assertEquals(res.status, 203);
        assertEquals(res.headers.get("x-intercept-zero"), "yes");
        assertEquals(await res.text(), "intercept zero body");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy expression regexp macros expose captures",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      await Deno.writeTextFile(
        join(siteDir, ".zeroserve", "scripts", "00_seed.c"),
        `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  zs_meta_set(ZS_STR("http.vars.mode"), ZS_STR("debug"));
  zs_meta_set(ZS_STR("http.vars.query_key"), ZS_STR("dynamic"));
  return 0;
}
`,
      );

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{
                      expression:
                        "path('/comparison') && {http.request.uri.query} == 'token=ok'",
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 233,
                        body: "comparison",
                      },
                    ],
                  },
                  {
                    match: [{
                      expression: "path('/bool-literal') && true",
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 234,
                        body: "bool literal",
                      },
                    ],
                  },
                  {
                    match: [{
                      expression:
                        "header({'X-' + {http.request.uri.query.header}: 'ok'}) && vars({'mo' + {http.request.uri.query.key}: 'debug'})",
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 231,
                        body: "expanded keys",
                      },
                    ],
                  },
                  {
                    match: [{
                      expression:
                        "path('/placeholder-map-key') && query({{http.vars.query_key}: '1'})",
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 236,
                        body: "placeholder map key",
                      },
                    ],
                  },
                  {
                    match: [{
                      expression:
                        "path('/escaped-placeholder-key') && vars({'\\\\{http.vars.mode}': 'debug'})",
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 232,
                        body: "escaped placeholder key",
                      },
                    ],
                  },
                  {
                    match: [{
                      expression:
                        "path('/concat/' + {http.request.uri.query.slug}) && query({'mo' + {http.request.uri.query.key}: 'de' + {http.request.uri.query.suffix}})",
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 229,
                        body: "concat expression",
                      },
                    ],
                  },
                  {
                    match: [{
                      expression:
                        "path('/membership') && {http.request.uri.query.mode} in ['debug', 'trace'] && {http.request.uri.query.code} in ['200', '204']",
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 226,
                        body: "membership",
                      },
                    ],
                  },
                  {
                    match: [{
                      expression:
                        "path({http.request.uri.path}) && query({'mode': {http.request.uri.query.mode}}) && file({http.request.uri.path})",
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 228,
                        body: "placeholder expression",
                      },
                    ],
                  },
                  {
                    match: [{
                      expression: {
                        expr: "path_regexp('^/expr-name/(.+)$')",
                        name: "exprDefault",
                      },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 230,
                        body: "{http.regexp.exprDefault.1}",
                      },
                    ],
                  },
                  {
                    match: [{
                      expression:
                        "path_regexp('expr', '^/expr-re/(.+)$') && header_regexp('tok', 'X-Token', '^Bearer (.+)$')",
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 227,
                        body: "{http.regexp.expr.1}|{http.regexp.tok.1}",
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const comparisonMatched = await fetch(
          `${baseUrl}/comparison?token=ok`,
        );
        assertEquals(comparisonMatched.status, 233);
        assertEquals(await comparisonMatched.text(), "comparison");

        const comparisonMiss = await fetch(`${baseUrl}/comparison?token=no`);
        assertEquals(comparisonMiss.status, 200);

        const boolLiteral = await fetch(`${baseUrl}/bool-literal`);
        assertEquals(boolLiteral.status, 234);
        assertEquals(await boolLiteral.text(), "bool literal");

        const expandedKeysMatched = await fetch(
          `${baseUrl}/expanded-keys?header=Mode&key=de`,
          { headers: { "X-Mode": "ok" } },
        );
        assertEquals(expandedKeysMatched.status, 231);
        assertEquals(await expandedKeysMatched.text(), "expanded keys");

        const expandedKeysMiss = await fetch(
          `${baseUrl}/expanded-keys?header=Mode&key=de`,
          { headers: { "X-Mode": "nope" } },
        );
        assertEquals(expandedKeysMiss.status, 200);

        const placeholderMapKey = await fetch(
          `${baseUrl}/placeholder-map-key?dynamic=1`,
        );
        assertEquals(placeholderMapKey.status, 236);
        assertEquals(await placeholderMapKey.text(), "placeholder map key");

        const placeholderMapKeyMiss = await fetch(
          `${baseUrl}/placeholder-map-key?other=1`,
        );
        assertEquals(placeholderMapKeyMiss.status, 200);

        const escapedPlaceholderKey = await fetch(
          `${baseUrl}/escaped-placeholder-key`,
        );
        assertEquals(escapedPlaceholderKey.status, 232);
        assertEquals(
          await escapedPlaceholderKey.text(),
          "escaped placeholder key",
        );

        const concatMatched = await fetch(
          `${baseUrl}/concat/item?slug=item&key=de&suffix=bug&mode=debug`,
        );
        assertEquals(concatMatched.status, 229);
        assertEquals(await concatMatched.text(), "concat expression");

        const concatMiss = await fetch(
          `${baseUrl}/concat/item?slug=item&key=de&suffix=bug&mode=release`,
        );
        assertEquals(concatMiss.status, 200);

        const membershipMatched = await fetch(
          `${baseUrl}/membership?mode=trace&code=204`,
        );
        assertEquals(membershipMatched.status, 226);
        assertEquals(await membershipMatched.text(), "membership");

        const membershipMiss = await fetch(
          `${baseUrl}/membership?mode=release&code=204`,
        );
        assertEquals(membershipMiss.status, 200);

        const numericMembershipMiss = await fetch(
          `${baseUrl}/membership?mode=debug&code=500`,
        );
        assertEquals(numericMembershipMiss.status, 200);

        const defaultNameMatched = await fetch(`${baseUrl}/expr-name/capture`);
        assertEquals(defaultNameMatched.status, 230);
        assertEquals(await defaultNameMatched.text(), "capture");

        const placeholderMatched = await fetch(
          `${baseUrl}/index.html?mode=debug`,
        );
        assertEquals(placeholderMatched.status, 228);
        assertEquals(await placeholderMatched.text(), "placeholder expression");

        const matched = await fetch(`${baseUrl}/expr-re/capture`, {
          headers: { "X-Token": "Bearer abc123" },
        });
        assertEquals(matched.status, 227);
        assertEquals(await matched.text(), "capture|abc123");

        const miss = await fetch(`${baseUrl}/expr-re/capture`, {
          headers: { "X-Token": "Basic abc123" },
        });
        assertEquals(miss.status, 200);
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy expression protocol lowercases argument",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{
                      expression:
                        "path('/expression-protocol') && protocol('HTTPs')",
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 235,
                        body: "expression protocol",
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      const cert = await generateSelfSignedCert();
      try {
        await withZeroserveTls(
          tarPath,
          cert.certPath,
          cert.keyPath,
          async (httpUrl, httpsUrl) => {
            const plain = await fetch(`${httpUrl}/expression-protocol`);
            assertEquals(plain.status, 200);

            const caCert = await Deno.readTextFile(cert.certPath);
            const client = Deno.createHttpClient({ caCerts: [caCert] });
            try {
              const tls = await fetch(`${httpsUrl}/expression-protocol`, {
                client,
              });
              assertEquals(tls.status, 235);
              assertEquals(await tls.text(), "expression protocol");
            } finally {
              client.close();
            }
          },
        );
      } finally {
        await cert.cleanup();
      }
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy non-positive request body max size is unlimited",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{
                      method: ["POST"],
                      path: ["/body-limited-static"],
                    }],
                    handle: [
                      {
                        handler: "request_body",
                        max_size: 8,
                      },
                      {
                        handler: "static_response",
                        status_code: 200,
                        body: "body not read",
                      },
                    ],
                  },
                  {
                    match: [{
                      method: ["POST"],
                      path: ["/body-limited-proxy"],
                    }],
                    handle: [
                      {
                        handler: "request_body",
                        max_size: 8,
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                  },
                  {
                    match: [{ method: ["POST"], path: ["/body-unlimited"] }],
                    handle: [
                      {
                        handler: "request_body",
                        max_size: -1,
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const requestBody = "this body would exceed the positive limit";
        const limitedStatic = await fetch(`${baseUrl}/body-limited-static`, {
          method: "POST",
          body: requestBody,
        });
        assertEquals(limitedStatic.status, 200);
        assertEquals(await limitedStatic.text(), "body not read");

        const limitedProxyOk = await fetch(`${baseUrl}/body-limited-proxy`, {
          method: "POST",
          body: "12345678",
        });
        assertEquals(limitedProxyOk.status, 200);
        const limitedProxyOkJson = await limitedProxyOk.json();
        assertEquals(limitedProxyOkJson.body, "12345678");

        const limitedProxyTooLarge = await fetch(
          `${baseUrl}/body-limited-proxy`,
          {
            method: "POST",
            body: "123456789",
          },
        );
        assertEquals(limitedProxyTooLarge.status, 413);

        const unlimited = await fetch(`${baseUrl}/body-unlimited`, {
          method: "POST",
          body: requestBody,
        });
        assertEquals(unlimited.status, 200);
        const unlimitedJson = await unlimited.json();
        assertEquals(unlimitedJson.body, requestBody);
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy static_response preserves repeated headers",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/cookies"] }],
                  handle: [{
                    handler: "static_response",
                    status_code: 204,
                    headers: {
                      "Set-Cookie": ["a=1; Path=/", "b=2; Path=/"],
                    },
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/unknown-placeholder"] }],
                  handle: [{
                    handler: "headers",
                    response: {
                      deferred: true,
                      set: {
                        "X-Unknown": [
                          "known-{http.request.uri.path}-unknown-{missing.placeholder}",
                        ],
                      },
                    },
                  }, {
                    handler: "static_response",
                    status_code: 204,
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/implicit-content-type"] }],
                  handle: [{
                    handler: "static_response",
                    body: '{"ok":true}',
                    headers: {
                      "Content-Type": ["{missing.placeholder}"],
                    },
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/implicit-empty-object"] }],
                  handle: [{
                    handler: "static_response",
                    body: "{}",
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/implicit-empty-array"] }],
                  handle: [{
                    handler: "static_response",
                    body: "[]",
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/escaped-placeholders"] }],
                  handle: [{
                    handler: "static_response",
                    body: "\\{http.request.uri.path\\}|{http.request.uri.path}",
                    headers: {
                      "X-Escaped": [
                        "\\{http.request.uri.path\\}|{http.request.uri.path}",
                      ],
                    },
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/dynamic-header-name"] }],
                  handle: [{
                    handler: "vars",
                    header_name: "X-Dynamic-Name",
                  }, {
                    handler: "static_response",
                    body: "dynamic header name",
                    headers: {
                      "{http.vars.header_name}": ["expanded"],
                    },
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/custom-status"] }],
                  handle: [{
                    handler: "static_response",
                    status_code: 777,
                    body: "custom status",
                    headers: {
                      "X-Custom-Status": ["yes"],
                    },
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/dynamic-status"] }],
                  handle: [{
                    handler: "vars",
                    status: "226",
                  }, {
                    handler: "static_response",
                    status_code: "{http.vars.status}",
                    body: "dynamic status",
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/dynamic-invalid-status"] }],
                  handle: [{
                    handler: "vars",
                    status: "0",
                  }, {
                    handler: "static_response",
                    status_code: "{http.vars.status}",
                    body: "invalid status",
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/null-header-values"] }],
                  handle: [{
                    handler: "static_response",
                    status_code: 204,
                    body: null,
                    headers: {
                      "X-Empty": null,
                      "X-Blank": [null],
                    },
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await rawHttpGet(baseUrl, "/cookies", "localhost");
        assertEquals(res.status, 204);
        assertEquals(
          res.headerLines.filter((line) =>
            line.toLowerCase().startsWith("set-cookie:")
          ),
          ["set-cookie: a=1; Path=/", "set-cookie: b=2; Path=/"],
        );

        const unknown = await fetch(`${baseUrl}/unknown-placeholder`);
        assertEquals(unknown.status, 204);
        assertEquals(
          unknown.headers.get("x-unknown"),
          "known-/unknown-placeholder-unknown-{missing.placeholder}",
        );

        const implicit = await fetch(`${baseUrl}/implicit-content-type`);
        assertEquals(implicit.status, 200);
        assertEquals(implicit.headers.get("content-type"), "application/json");
        assertEquals(await implicit.json(), { ok: true });

        const emptyObject = await fetch(`${baseUrl}/implicit-empty-object`);
        assertEquals(emptyObject.status, 200);
        assertEquals(
          emptyObject.headers.get("content-type"),
          "text/plain; charset=utf-8",
        );
        assertEquals(await emptyObject.text(), "{}");

        const emptyArray = await fetch(`${baseUrl}/implicit-empty-array`);
        assertEquals(emptyArray.status, 200);
        assertEquals(
          emptyArray.headers.get("content-type"),
          "text/plain; charset=utf-8",
        );
        assertEquals(await emptyArray.text(), "[]");

        const escaped = await fetch(`${baseUrl}/escaped-placeholders`);
        assertEquals(escaped.status, 200);
        assertEquals(
          escaped.headers.get("x-escaped"),
          "{http.request.uri.path}|/escaped-placeholders",
        );
        assertEquals(
          await escaped.text(),
          "{http.request.uri.path}|/escaped-placeholders",
        );

        const dynamicHeaderName = await fetch(
          `${baseUrl}/dynamic-header-name`,
        );
        assertEquals(dynamicHeaderName.status, 200);
        assertEquals(
          dynamicHeaderName.headers.get("x-dynamic-name"),
          "expanded",
        );
        assertEquals(await dynamicHeaderName.text(), "dynamic header name");

        const custom = await rawHttpGet(
          baseUrl,
          "/custom-status",
          "localhost",
        );
        assertEquals(custom.status, 777);
        assertEquals(custom.headers["x-custom-status"], "yes");
        assertEquals(custom.body, "custom status");

        const dynamic = await fetch(`${baseUrl}/dynamic-status`);
        assertEquals(dynamic.status, 226);
        assertEquals(await dynamic.text(), "dynamic status");

        const invalidDynamic = await fetch(
          `${baseUrl}/dynamic-invalid-status`,
        );
        assertEquals(invalidDynamic.status, 500);

        const nullHeaders = await fetch(`${baseUrl}/null-header-values`);
        assertEquals(nullHeaders.status, 204);
        assertEquals(nullHeaders.headers.get("x-empty"), null);
        assertEquals(nullHeaders.headers.get("x-blank"), "");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy static_response close ends the H1 connection",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/close"] }],
                    handle: [{
                      handler: "static_response",
                      close: true,
                      body: "closed",
                    }],
                    terminal: true,
                  },
                  {
                    match: [{ path: ["/close-override"] }],
                    handle: [{
                      handler: "static_response",
                      close: true,
                      body: "closed override",
                      headers: {
                        "Connection": ["keep-alive"],
                      },
                    }],
                    terminal: true,
                  },
                  {
                    match: [{ path: ["/after"] }],
                    handle: [{
                      handler: "static_response",
                      body: "after",
                    }],
                    terminal: true,
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const raw = await rawHttpPipeline(baseUrl, [
          "GET /close HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
          "GET /after HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        ]);
        assertEquals((raw.match(/^HTTP\/1\.1 /gm) ?? []).length, 1);
        assertEquals(raw.toLowerCase().includes("connection: close"), true);
        assertEquals(raw.includes("closed"), true);
        assertEquals(raw.includes("after"), false);

        const overrideRaw = await rawHttpPipeline(baseUrl, [
          "GET /close-override HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
          "GET /after HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        ]);
        assertEquals((overrideRaw.match(/^HTTP\/1\.1 /gm) ?? []).length, 1);
        assertEquals(
          overrideRaw.toLowerCase().includes("connection: keep-alive"),
          true,
        );
        assertEquals(overrideRaw.includes("closed override"), true);
        assertEquals(overrideRaw.includes("after"), false);
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy static_response abort closes without response",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/abort"] }],
                    handle: [{
                      handler: "static_response",
                      abort: true,
                    }],
                    terminal: true,
                  },
                  {
                    match: [{ path: ["/after"] }],
                    handle: [{
                      handler: "static_response",
                      body: "after",
                    }],
                    terminal: true,
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const raw = await rawHttpPipeline(baseUrl, [
          "GET /abort HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
          "GET /after HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        ]);
        assertEquals(raw, "");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy query matcher treats embedded stars literally",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{
                      path: ["/query-literal-star"],
                      query: { debug: ["*bar*"] },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 222,
                        body: "literal star",
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/query-any-star"],
                      query: { debug: ["*"] },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 223,
                        body: "wildcard star",
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/query-present"],
                      query: { debug: null },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 224,
                        body: "null value",
                      },
                    ],
                  },
                  {
                    handle: [
                      {
                        handler: "vars",
                        query_key: "debug",
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/query-present-placeholder"],
                      query: { "{http.vars.query_key}": null },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 225,
                        body: "null placeholder key",
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/query-empty"],
                      query: {},
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 226,
                        body: "empty query",
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/query-empty-values"],
                      query: { debug: [] },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 227,
                        body: "empty values",
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const literalStarHit = await fetch(
          `${baseUrl}/query-literal-star?debug=*bar*`,
        );
        assertEquals(literalStarHit.status, 222);
        assertEquals(await literalStarHit.text(), "literal star");

        const literalStarMiss = await fetch(
          `${baseUrl}/query-literal-star?debug=xbarx`,
        );
        assertEquals(literalStarMiss.status, 200);
        assertEquals(await literalStarMiss.text(), "");

        const wildcardStarHit = await fetch(
          `${baseUrl}/query-any-star?debug=xbarx`,
        );
        assertEquals(wildcardStarHit.status, 223);
        assertEquals(await wildcardStarHit.text(), "wildcard star");

        const presentHit = await fetch(`${baseUrl}/query-present?debug`);
        assertEquals(presentHit.status, 200);
        assertEquals(await presentHit.text(), "");

        const presentMiss = await fetch(`${baseUrl}/query-present?other`);
        assertEquals(presentMiss.status, 200);
        assertEquals(await presentMiss.text(), "");

        const dynamicPresentHit = await fetch(
          `${baseUrl}/query-present-placeholder?debug=anything`,
        );
        assertEquals(dynamicPresentHit.status, 200);
        assertEquals(await dynamicPresentHit.text(), "");

        const badPercent = await rawHttpGet(
          baseUrl,
          "/query-present?debug=%zz",
          "127.0.0.1",
        );
        assertEquals(badPercent.status, 200);
        assertEquals(badPercent.body, "");

        const badSemicolon = await rawHttpGet(
          baseUrl,
          "/query-present?debug=1;other=2",
          "127.0.0.1",
        );
        assertEquals(badSemicolon.status, 200);
        assertEquals(badSemicolon.body, "");

        const malformedEmpty = await rawHttpGet(
          baseUrl,
          "/query-empty?debug=%zz",
          "127.0.0.1",
        );
        assertEquals(malformedEmpty.status, 226);
        assertEquals(malformedEmpty.body, "empty query");

        const malformedWithValidPair = await rawHttpGet(
          baseUrl,
          "/query-empty?ok=1&debug=%zz",
          "127.0.0.1",
        );
        assertEquals(malformedWithValidPair.status, 200);
        assertEquals(malformedWithValidPair.body, "");

        const emptyValuesWithKey = await fetch(
          `${baseUrl}/query-empty-values?debug=anything`,
        );
        assertEquals(emptyValuesWithKey.status, 200);
        assertEquals(await emptyValuesWithKey.text(), "");

        const emptyValuesWithoutKey = await fetch(
          `${baseUrl}/query-empty-values`,
        );
        assertEquals(emptyValuesWithoutKey.status, 200);
        assertEquals(await emptyValuesWithoutKey.text(), "");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy method matcher is case-sensitive",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ method: ["get"] }],
                  handle: [{
                    handler: "static_response",
                    status_code: 200,
                    body: "lowercase method",
                  }],
                }, {
                  handle: [{
                    handler: "static_response",
                    status_code: 404,
                    body: "fallback",
                  }],
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/`);
        assertEquals(res.status, 404);
        assertEquals(await res.text(), "fallback");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy header matchers inspect Host",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{
                    path: ["/padded-request-header"],
                    header: { " Host ": [] },
                  }],
                  handle: [{
                    handler: "static_response",
                    body: "padded host matched",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/host-header"],
                    header: { Host: ["Example.Test:4321"] },
                  }],
                  handle: [{
                    handler: "static_response",
                    body: "host header matched",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/host-regexp"],
                    header_regexp: {
                      Host: {
                        name: "hostport",
                        pattern: "^Example\\.Test:(\\d+)$",
                      },
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    body: "{http.regexp.hostport.1}",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/mutate-host"],
                  }],
                  handle: [
                    {
                      handler: "headers",
                      request: {
                        add: {
                          Host: ["Mutated.Test"],
                        },
                      },
                    },
                    {
                      handler: "subroute",
                      routes: [{
                        match: [{
                          host: ["Mutated.Test"],
                        }],
                        handle: [{
                          handler: "static_response",
                          body: "{http.request.host}",
                        }],
                        terminal: true,
                      }],
                    },
                  ],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/proxy-host"],
                  }],
                  handle: [
                    {
                      handler: "headers",
                      request: {
                        set: {
                          Host: ["BackendHost.Test"],
                        },
                      },
                    },
                    {
                      handler: "reverse_proxy",
                      upstreams: [{ dial: backend.dial }],
                    },
                  ],
                  terminal: true,
                }, {
                  handle: [{
                    handler: "static_response",
                    status_code: 404,
                    body: "fallback",
                  }],
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const padded = await rawHttpGet(
          baseUrl,
          "/padded-request-header",
          "Example.Test:4321",
        );
        assertEquals(padded.status, 404);
        assertEquals(padded.body, "fallback");

        const header = await rawHttpGet(
          baseUrl,
          "/host-header",
          "Example.Test:4321",
        );
        assertEquals(header.status, 200);
        assertEquals(header.body, "host header matched");

        const regexp = await rawHttpGet(
          baseUrl,
          "/host-regexp",
          "Example.Test:4321",
        );
        assertEquals(regexp.status, 200);
        assertEquals(regexp.body, "4321");

        const miss = await rawHttpGet(
          baseUrl,
          "/host-header",
          "other.test:4321",
        );
        assertEquals(miss.status, 404);
        assertEquals(miss.body, "fallback");

        const mutated = await rawHttpGet(
          baseUrl,
          "/mutate-host",
          "Original.Test",
        );
        assertEquals(mutated.status, 200);
        assertEquals(mutated.body, "Mutated.Test");

        const proxied = await fetch(`${baseUrl}/proxy-host`);
        assertEquals(proxied.status, 200);
        assertEquals(await proxied.json(), { host: "BackendHost.Test" });

        const url = new URL(baseUrl);
        const h2Mutated = await h2cPost(
          url.hostname,
          Number(url.port),
          "/mutate-host",
          "",
        );
        assertEquals(h2Mutated.status, 200);
        assertEquals(h2Mutated.body, "Mutated.Test");

        const h2Proxied = await h2cPost(
          url.hostname,
          Number(url.port),
          "/proxy-host",
          "",
        );
        assertEquals(h2Proxied.status, 200);
        assertEquals(JSON.parse(h2Proxied.body), { host: "BackendHost.Test" });
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
      await backend.close();
    }
  },
});

Deno.test({
  name: "compiled Caddy header matchers inspect Transfer-Encoding",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{
                    path: ["/chunked"],
                    header: { "Transfer-Encoding": ["chunked"] },
                  }],
                  handle: [{
                    handler: "static_response",
                    body: "chunked matched",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/chunked-regexp"],
                    header_regexp: {
                      "Transfer-Encoding": {
                        name: "te",
                        pattern: "^(chunk)ed$",
                      },
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    body: "{http.regexp.te.1}",
                  }],
                  terminal: true,
                }, {
                  handle: [{
                    handler: "static_response",
                    status_code: 404,
                    body: "fallback",
                  }],
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const chunked = await rawHttpRequest(
          baseUrl,
          "POST /chunked HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
        );
        assertEquals(chunked.status, 200);
        assertEquals(chunked.body, "chunked matched");

        const regexp = await rawHttpRequest(
          baseUrl,
          "POST /chunked-regexp HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
        );
        assertEquals(regexp.status, 200);
        assertEquals(regexp.body, "chunk");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy empty method path and host arrays never match",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ method: [], path: ["/empty-method"] }],
                  handle: [{
                    handler: "static_response",
                    status_code: 220,
                    body: "empty method",
                  }],
                  terminal: true,
                }, {
                  match: [{ path: [] }],
                  handle: [{
                    handler: "static_response",
                    status_code: 221,
                    body: "empty path",
                  }],
                  terminal: true,
                }, {
                  match: [{ host: [], path: ["/empty-host"] }],
                  handle: [{
                    handler: "static_response",
                    status_code: 222,
                    body: "empty host",
                  }],
                  terminal: true,
                }, {
                  handle: [{
                    handler: "static_response",
                    status_code: 404,
                    body: "fallback",
                  }],
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        for (const path of ["/empty-method", "/empty-path", "/empty-host"]) {
          const res = await fetch(`${baseUrl}${path}`);
          assertEquals(res.status, 404);
          assertEquals(await res.text(), "fallback");
        }
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy query and header matchers expand placeholders",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    handle: [{
                      handler: "vars",
                      query_key: "debug",
                      query_value: "enabled",
                      header_value: "token-42",
                    }],
                  },
                  {
                    match: [{
                      path: ["/placeholder-match"],
                      query: {
                        "{http.vars.query_key}": ["{http.vars.query_value}"],
                      },
                      header: {
                        "X-Mode": ["{http.vars.header_value}"],
                      },
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 224,
                      body: "placeholder matcher",
                    }],
                    terminal: true,
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const hit = await fetch(
          `${baseUrl}/placeholder-match?debug=enabled`,
          { headers: { "X-Mode": "token-42" } },
        );
        assertEquals(hit.status, 224);
        assertEquals(await hit.text(), "placeholder matcher");

        const wrongHeader = await fetch(
          `${baseUrl}/placeholder-match?debug=enabled`,
          { headers: { "X-Mode": "wrong" } },
        );
        assertEquals(wrongHeader.status, 200);

        const wrongQuery = await fetch(
          `${baseUrl}/placeholder-match?debug=wrong`,
          { headers: { "X-Mode": "token-42" } },
        );
        assertEquals(wrongQuery.status, 200);
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy header matcher checks presence and absence",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{
                      path: ["/header-absent"],
                      header: { "X-Forbidden": null },
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 226,
                      body: "absent",
                    }],
                    terminal: true,
                  },
                  {
                    match: [{
                      path: ["/header-present"],
                      header: { "X-Present": [] },
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 227,
                      body: "present",
                    }],
                    terminal: true,
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const absentHit = await fetch(`${baseUrl}/header-absent`);
        assertEquals(absentHit.status, 226);
        assertEquals(await absentHit.text(), "absent");

        const absentMiss = await fetch(`${baseUrl}/header-absent`, {
          headers: { "X-Forbidden": "no" },
        });
        assertEquals(absentMiss.status, 200);

        const presentHit = await fetch(`${baseUrl}/header-present`, {
          headers: { "X-Present": "" },
        });
        assertEquals(presentHit.status, 227);
        assertEquals(await presentHit.text(), "present");

        const presentMiss = await fetch(`${baseUrl}/header-present`);
        assertEquals(presentMiss.status, 200);
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy response status matcher accepts zero as no match",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/status-zero"] }],
                  handle: [
                    {
                      handler: "headers",
                      response: {
                        deferred: true,
                        require: { status_code: [0] },
                        set: { "X-Zero-Matched": ["yes"] },
                      },
                    },
                    {
                      handler: "static_response",
                      status_code: 204,
                    },
                  ],
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/status-zero`);
        assertEquals(res.status, 204);
        assertEquals(res.headers.get("x-zero-matched"), null);
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy header matchers inspect repeated header values",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{
                      path: ["/repeat-header"],
                      header: { "X-Multi": ["target"] },
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 225,
                      body: "repeated header",
                    }],
                    terminal: true,
                  },
                  {
                    match: [{
                      path: ["/repeat-header-regexp"],
                      header_regexp: {
                        "X-Re": {
                          name: "hdr",
                          pattern: "^target-(.+)$",
                        },
                      },
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 226,
                      body: "{http.regexp.hdr.1}",
                    }],
                    terminal: true,
                  },
                  {
                    match: [{
                      path: ["/empty-header"],
                      header: {},
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 227,
                      body: "empty header",
                    }],
                    terminal: true,
                  },
                  {
                    match: [{
                      path: ["/empty-header-regexp"],
                      header_regexp: {},
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 228,
                      body: "empty header regexp",
                    }],
                    terminal: true,
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const headerHit = await rawHttpGetWithHeaderLines(
          baseUrl,
          "/repeat-header",
          "127.0.0.1",
          ["X-Multi: miss", "X-Multi: target"],
        );
        assertEquals(headerHit.status, 225);
        assertEquals(headerHit.body, "repeated header");

        const regexHit = await rawHttpGetWithHeaderLines(
          baseUrl,
          "/repeat-header-regexp",
          "127.0.0.1",
          ["X-Re: miss", "X-Re: target-capture"],
        );
        assertEquals(regexHit.status, 226);
        assertEquals(regexHit.body, "capture");

        const emptyHeader = await fetch(`${baseUrl}/empty-header`);
        assertEquals(emptyHeader.status, 227);
        assertEquals(await emptyHeader.text(), "empty header");

        const emptyHeaderRegexp = await fetch(`${baseUrl}/empty-header-regexp`);
        assertEquals(emptyHeaderRegexp.status, 228);
        assertEquals(await emptyHeaderRegexp.text(), "empty header regexp");

        const miss = await rawHttpGetWithHeaderLines(
          baseUrl,
          "/repeat-header",
          "127.0.0.1",
          ["X-Multi: miss", "X-Multi: also-miss"],
        );
        assertEquals(miss.status, 200);
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy error handler returns status without body",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/boom"] }],
                    handle: [
                      {
                        handler: "error",
                        status_code: 418,
                        error: "not the response body",
                      },
                    ],
                  },
                  {
                    match: [{ path: ["/null-status"] }],
                    handle: [
                      {
                        handler: "error",
                        status_code: null,
                        error: null,
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/boom`);
        assertEquals(res.status, 418);
        assertEquals(res.headers.get("content-type"), null);
        assertEquals(await res.text(), "");

        const nullStatus = await fetch(`${baseUrl}/null-status`);
        assertEquals(nullStatus.status, 500);
        assertEquals(nullStatus.headers.get("content-type"), null);
        assertEquals(await nullStatus.text(), "");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy server error routes expose error placeholders",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/boom"] }],
                    handle: [
                      {
                        handler: "error",
                        status_code: 418,
                        error: "teapot {http.request.uri.path}",
                      },
                    ],
                  },
                ],
                errors: {
                  routes: [
                    {
                      group: "error_choice",
                      handle: [
                        {
                          handler: "headers",
                          request: {
                            set: {
                              "X-Error-Choice": ["first"],
                            },
                          },
                        },
                      ],
                    },
                    {
                      group: "error_choice",
                      handle: [
                        {
                          handler: "headers",
                          request: {
                            set: {
                              "X-Error-Choice": ["second"],
                            },
                          },
                        },
                      ],
                    },
                    {
                      handle: [
                        {
                          handler: "static_response",
                          body:
                            "{http.error.status_code} {http.error.status_text} {http.error.message} {http.request.header.X-Error-Choice}",
                        },
                      ],
                    },
                  ],
                },
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/boom`);
        assertEquals(res.status, 418);
        assertEquals(await res.text(), "418 I'm a teapot teapot /boom first");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy terminal error route falls back to error status",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/boom"] }],
                  handle: [{
                    handler: "error",
                    status_code: 418,
                  }],
                }],
                errors: {
                  routes: [{
                    terminal: true,
                    handle: [{
                      handler: "headers",
                      response: {
                        deferred: true,
                        set: {
                          "X-Error-Status": ["{http.error.status_code}"],
                        },
                      },
                    }],
                  }],
                },
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/boom`);
        assertEquals(res.status, 418);
        assertEquals(res.headers.get("x-error-status"), "418");
        assertEquals(await res.text(), "");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy file_server misses run server error routes",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "public"), { recursive: true });
      await Deno.writeTextFile(join(siteDir, "public", "exists.txt"), "exists");
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "file_server",
                    root: "public",
                  }],
                  terminal: true,
                }],
                errors: {
                  routes: [{
                    handle: [{
                      handler: "static_response",
                      status_code: "{http.error.status_code}",
                      body:
                        "handled {http.error.status_code} {http.error.status_text}",
                    }],
                  }],
                },
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const exists = await fetch(`${baseUrl}/exists.txt`);
        assertEquals(exists.status, 200);
        assertEquals(await exists.text(), "exists");

        const missing = await fetch(`${baseUrl}/missing.txt`);
        assertEquals(missing.status, 404);
        assertEquals(await missing.text(), "handled 404 Not Found");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy file_server unsupported fs runs server error routes",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [
                    {
                      handler: "vars",
                      fs: "missingfs",
                    },
                    {
                      handler: "file_server",
                      fs: "{http.vars.fs}",
                      pass_thru: true,
                    },
                    {
                      handler: "static_response",
                      body: "fallthrough",
                    },
                  ],
                }],
                errors: {
                  routes: [{
                    handle: [{
                      handler: "static_response",
                      status_code: "{http.error.status_code}",
                      body:
                        "handled {http.error.status_code} {http.error.status_text}",
                    }],
                  }],
                },
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/anything`);
        assertEquals(res.status, 404);
        assertEquals(await res.text(), "handled 404 Not Found");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy error-route file_server keeps error status for POST",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "public"), { recursive: true });
      await Deno.writeTextFile(
        join(siteDir, "public", "404.html"),
        "file error page",
      );
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/boom"] }],
                  handle: [{
                    handler: "error",
                    status_code: 404,
                    error: "missing",
                  }],
                  terminal: true,
                }],
                errors: {
                  routes: [{
                    handle: [{
                      handler: "rewrite",
                      uri: "/404.html",
                    }, {
                      handler: "file_server",
                      root: "public",
                    }],
                  }],
                },
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/boom`, { method: "POST" });
        assertEquals(res.status, 404);
        assertEquals(res.headers.get("allow"), null);
        assertEquals(await res.text(), "file error page");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy subroute error routes handle local errors",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/local"] }],
                    handle: [
                      {
                        handler: "subroute",
                        routes: [
                          {
                            handle: [
                              {
                                handler: "error",
                                status_code: 409,
                                error: "local {http.request.uri.path}",
                              },
                            ],
                          },
                        ],
                        errors: {
                          routes: [
                            {
                              handle: [
                                {
                                  handler: "static_response",
                                  status_code: "{http.error.status_code}",
                                  body:
                                    "subroute {http.error.status_code} {http.error.message}",
                                },
                              ],
                            },
                          ],
                        },
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/local`);
        assertEquals(res.status, 409);
        assertEquals(await res.text(), "subroute 409 local /local");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy conditional subroute error routes can fall through",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/local/*"] }],
                  handle: [{
                    handler: "subroute",
                    routes: [{
                      handle: [{
                        handler: "error",
                        status_code: 409,
                        error: "local {http.request.uri.path}",
                      }],
                    }],
                    errors: {
                      routes: [{
                        match: [{ path: ["/local/handled"] }],
                        handle: [{
                          handler: "static_response",
                          status_code: "{http.error.status_code}",
                          body:
                            "handled {http.error.status_code} {http.error.message}",
                        }],
                        terminal: true,
                      }],
                    },
                  }, {
                    handler: "static_response",
                    status_code: 208,
                    body: "after subroute",
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const handled = await fetch(`${baseUrl}/local/handled`);
        assertEquals(handled.status, 409);
        assertEquals(await handled.text(), "handled 409 local /local/handled");

        const fallthrough = await fetch(`${baseUrl}/local/fallthrough`);
        assertEquals(fallthrough.status, 208);
        assertEquals(await fallthrough.text(), "after subroute");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy subroute groups share request route state",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    group: "choice",
                    match: [{ path: ["/grouped"] }],
                    handle: [
                      {
                        handler: "headers",
                        request: {
                          set: { "X-Subroute-Outer": ["top"] },
                        },
                      },
                    ],
                  },
                  {
                    match: [{ path: ["/grouped"] }],
                    handle: [
                      {
                        handler: "subroute",
                        routes: [
                          {
                            group: "choice",
                            match: [{ path: ["/grouped"] }],
                            handle: [
                              {
                                handler: "headers",
                                request: {
                                  set: { "X-Subroute-Outer": ["subroute"] },
                                },
                              },
                            ],
                          },
                          {
                            group: "inner",
                            match: [{ path: ["/grouped"] }],
                            handle: [
                              {
                                handler: "headers",
                                request: {
                                  set: { "X-Subroute-Inner": ["first"] },
                                },
                              },
                            ],
                          },
                          {
                            group: "inner",
                            match: [{ path: ["/grouped"] }],
                            handle: [
                              {
                                handler: "headers",
                                request: {
                                  set: { "X-Subroute-Inner": ["second"] },
                                },
                              },
                            ],
                          },
                          {
                            handle: [
                              {
                                handler: "static_response",
                                status_code: 220,
                                body:
                                  "{http.request.header.X-Subroute-Outer} {http.request.header.X-Subroute-Inner}",
                              },
                            ],
                          },
                        ],
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/grouped`);
        assertEquals(res.status, 220);
        assertEquals(await res.text(), "top first");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy vars_regexp treats mixed placeholder keys literally",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      await Deno.writeTextFile(
        join(siteDir, ".zeroserve", "scripts", "00_seed.c"),
        `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  zs_meta_set(ZS_STR("http.vars.slot_{http.request.uri.path.1}"), ZS_STR("literal-42"));
  zs_meta_set(ZS_STR("http.vars.slot_foo"), ZS_STR("expanded-99"));
  zs_meta_set(ZS_STR("http.vars.loose"), ZS_STR("loose-42"));
  zs_meta_set(ZS_STR("http.vars.secret"), ZS_STR("{http.request.uri.path}"));
  zs_meta_set(ZS_STR("http.vars.expected_secret"), ZS_STR("{http.request.uri.path}"));
  return 0;
}
`,
      );

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{
                      path: ["/literal/*"],
                      vars_regexp: {
                        "slot_{http.request.uri.path.1}": {
                          name: "slot",
                          pattern: "^literal-([0-9]+)$",
                        },
                      },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 224,
                        body: "literal key",
                        headers: {
                          "X-Slot": ["{http.regexp.slot.1}"],
                        },
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/loose-vars-regexp"],
                      vars_regexp: {
                        "{http.vars.loose}}": {
                          name: "loose",
                          pattern: "^loose-([0-9]+)$",
                        },
                      },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 226,
                        body: "{http.regexp.loose.1}",
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/vars-literal-placeholder"],
                      vars: {
                        secret: ["/vars-literal-placeholder"],
                      },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 227,
                        body: "expanded secret",
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/vars-literal-placeholder"],
                      vars: {
                        secret: ["{http.vars.expected_secret}"],
                      },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 228,
                        body: "literal secret",
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/empty-vars-regexp"],
                      vars_regexp: {},
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 225,
                        body: "empty vars regexp",
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/literal/foo`);
        assertEquals(res.status, 224);
        assertEquals(res.headers.get("x-slot"), "42");
        assertEquals(await res.text(), "literal key");

        const empty = await fetch(`${baseUrl}/empty-vars-regexp`);
        assertEquals(empty.status, 200);

        const loose = await fetch(`${baseUrl}/loose-vars-regexp`);
        assertEquals(loose.status, 226);
        assertEquals(await loose.text(), "42");

        const literalSecret = await fetch(
          `${baseUrl}/vars-literal-placeholder`,
        );
        assertEquals(literalSecret.status, 228);
        assertEquals(await literalSecret.text(), "literal secret");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy vars handler feeds vars matcher",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/vars"] }],
                    handle: [
                      { handler: "vars", feature: "on" },
                      {
                        handler: "subroute",
                        routes: [
                          {
                            match: [{ vars: { feature: ["on"] } }],
                            handle: [
                              {
                                handler: "static_response",
                                status_code: 217,
                                body: "vars matched",
                              },
                            ],
                          },
                        ],
                      },
                    ],
                  },
                  {
                    match: [{ path: ["/vars-or"] }],
                    handle: [
                      { handler: "vars", feature: "on", other: "off" },
                      {
                        handler: "subroute",
                        routes: [
                          {
                            match: [{
                              vars: {
                                feature: ["on"],
                                other: ["missing"],
                              },
                            }],
                            handle: [
                              {
                                handler: "static_response",
                                status_code: 220,
                                body: "vars or matched",
                              },
                            ],
                          },
                        ],
                      },
                    ],
                  },
                  {
                    match: [{ path: ["/vars-json"] }],
                    handle: [
                      {
                        handler: "vars",
                        enabled: true,
                        count: 3,
                        items: ["a", "b"],
                        object: { k: 1 },
                        empty: null,
                      },
                      {
                        handler: "subroute",
                        routes: [
                          {
                            match: [{
                              vars: {
                                enabled: ["true"],
                                count: ["3"],
                                items: ["[a b]"],
                                object: ["map[k:1]"],
                                empty: [""],
                              },
                            }],
                            handle: [
                              {
                                handler: "static_response",
                                status_code: 219,
                                body:
                                  "{http.vars.enabled}|{http.vars.count}|{http.vars.items}|{http.vars.object}|{http.vars.empty}",
                              },
                            ],
                          },
                        ],
                      },
                    ],
                  },
                  {
                    match: [{ path: ["/vars-empty-key"] }],
                    handle: [
                      { handler: "vars", "": "empty-key" },
                      {
                        handler: "subroute",
                        routes: [
                          {
                            match: [{
                              vars: {
                                "": ["empty-key"],
                              },
                            }],
                            handle: [
                              {
                                handler: "static_response",
                                status_code: 222,
                                body: "{http.vars.}",
                              },
                            ],
                          },
                        ],
                      },
                    ],
                  },
                  {
                    match: [{ path: ["/vars/*"] }],
                    handle: [
                      {
                        handler: "vars",
                        "slot_{http.request.uri.path.1}":
                          "{http.request.uri.path.1}",
                        label: "{http.request.uri.path.1}",
                      },
                      {
                        handler: "subroute",
                        routes: [
                          {
                            match: [{
                              vars: {
                                "{http.vars.slot_foo}": [
                                  "{http.request.uri.path.1}",
                                ],
                              },
                            }],
                            handle: [
                              {
                                handler: "static_response",
                                status_code: 218,
                                body: "{http.vars.slot_foo}|{http.vars.label}",
                              },
                            ],
                          },
                        ],
                      },
                    ],
                  },
                  {
                    match: [{ path: ["/vars-loose-key"] }],
                    handle: [
                      { handler: "vars", loose: "loose-on" },
                      {
                        handler: "subroute",
                        routes: [
                          {
                            match: [{
                              vars: {
                                "{http.vars.loose}}": ["loose-on"],
                              },
                            }],
                            handle: [
                              {
                                handler: "static_response",
                                status_code: 221,
                                body: "loose vars key",
                              },
                            ],
                          },
                        ],
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/vars-miss"],
                      vars: { feature: ["on"] },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 216,
                        body: "should not match",
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const matched = await fetch(`${baseUrl}/vars`);
        assertEquals(matched.status, 217);
        assertEquals(await matched.text(), "vars matched");

        const orMatched = await fetch(`${baseUrl}/vars-or`);
        assertEquals(orMatched.status, 220);
        assertEquals(await orMatched.text(), "vars or matched");

        const dynamicMatched = await fetch(`${baseUrl}/vars/foo`);
        assertEquals(dynamicMatched.status, 218);
        assertEquals(await dynamicMatched.text(), "foo|foo");

        const jsonMatched = await fetch(`${baseUrl}/vars-json`);
        assertEquals(jsonMatched.status, 219);
        assertEquals(
          await jsonMatched.text(),
          "true|3|[a b]|map[k:1]|",
        );

        const looseKeyMatched = await fetch(`${baseUrl}/vars-loose-key`);
        assertEquals(looseKeyMatched.status, 221);
        assertEquals(await looseKeyMatched.text(), "loose vars key");

        const emptyKeyMatched = await fetch(`${baseUrl}/vars-empty-key`);
        assertEquals(emptyKeyMatched.status, 222);
        assertEquals(await emptyKeyMatched.text(), "empty-key");

        const missed = await fetch(`${baseUrl}/vars-miss`);
        assertEquals(missed.status, 200);
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy remote_ip matcher matches peer IP ranges",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{
                      path: ["/ip-match"],
                      remote_ip: { ranges: ["127.0.0.0/8"] },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 218,
                        body: "remote matched",
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/ip-miss"],
                      remote_ip: { ranges: ["192.0.2.0/24"] },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 219,
                        body: "should not match",
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/client-ip-match"],
                      client_ip: { ranges: ["127.0.0.0/8"] },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 220,
                        body: "client matched",
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/ip-dynamic"],
                      remote_ip: {
                        ranges: ["{http.request.header.X-Allowed-Range}"],
                      },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 221,
                        body: "dynamic remote matched",
                      },
                    ],
                  },
                  {
                    match: [{
                      path: ["/client-ip-dynamic"],
                      client_ip: {
                        ranges: ["{http.request.header.X-Allowed-Range}"],
                      },
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 222,
                        body: "dynamic client matched",
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const matched = await fetch(`${baseUrl}/ip-match`);
        assertEquals(matched.status, 218);
        assertEquals(await matched.text(), "remote matched");

        const missed = await fetch(`${baseUrl}/ip-miss`);
        assertEquals(missed.status, 200);

        const clientMatched = await fetch(`${baseUrl}/client-ip-match`);
        assertEquals(clientMatched.status, 220);
        assertEquals(await clientMatched.text(), "client matched");

        const dynamicRemote = await fetch(`${baseUrl}/ip-dynamic`, {
          headers: { "X-Allowed-Range": "127.0.0.0/8" },
        });
        assertEquals(dynamicRemote.status, 221);
        assertEquals(await dynamicRemote.text(), "dynamic remote matched");

        const dynamicRemoteMiss = await fetch(`${baseUrl}/ip-dynamic`, {
          headers: { "X-Allowed-Range": "192.0.2.0/24" },
        });
        assertEquals(dynamicRemoteMiss.status, 200);

        const dynamicClient = await fetch(`${baseUrl}/client-ip-dynamic`, {
          headers: { "X-Allowed-Range": "127.0.0.0/8" },
        });
        assertEquals(dynamicClient.status, 222);
        assertEquals(await dynamicClient.text(), "dynamic client matched");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy client_ip matcher honors static trusted proxies",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                trusted_proxies: {
                  source: "static",
                  ranges: ["127.0.0.0/8"],
                },
                client_ip_headers: [
                  "Missing-Header",
                  "CF-Connecting-IP",
                  "X-Forwarded-For",
                ],
                routes: [{
                  match: [{
                    path: ["/trusted-client"],
                    client_ip: { ranges: ["203.0.113.9"] },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 228,
                    body: "trusted client",
                  }],
                }, {
                  match: [{
                    path: ["/trusted-client-cf"],
                    client_ip: { ranges: ["198.51.100.7"] },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 229,
                    body: "trusted cf client",
                  }],
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const noHeader = await fetch(`${baseUrl}/trusted-client`);
        assertEquals(noHeader.status, 200);

        const matched = await fetch(`${baseUrl}/trusted-client`, {
          headers: { "X-Forwarded-For": "203.0.113.9" },
        });
        assertEquals(matched.status, 228);
        assertEquals(await matched.text(), "trusted client");

        const orderedHeader = await fetch(`${baseUrl}/trusted-client-cf`, {
          headers: {
            "CF-Connecting-IP": "198.51.100.7",
            "X-Forwarded-For": "203.0.113.9",
          },
        });
        assertEquals(orderedHeader.status, 229);
        assertEquals(await orderedHeader.text(), "trusted cf client");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy rewrite URI operations mutate path and query",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ method: ["GET"], path: ["/api*"] }],
                    handle: [
                      {
                        handler: "rewrite",
                        strip_path_prefix: "/api",
                        strip_path_suffix: ".json",
                        uri_substring: [
                          { find: "raw", replace: "cooked", limit: 1 },
                        ],
                        path_regexp: [
                          { find: "/{2,}", replace: "/" },
                        ],
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                  },
                  {
                    match: [{ method: ["GET"], path: ["/template*"] }],
                    handle: [
                      {
                        handler: "rewrite",
                        uri:
                          "/templated?p={http.request.header.X-Raw}&{http.request.uri.query}",
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                  },
                  {
                    match: [{ method: ["GET"], path: ["/literal-query"] }],
                    handle: [
                      {
                        handler: "rewrite",
                        uri: "/literal-query-upstream?a=b&&c=d&",
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                  },
                  {
                    match: [{ method: ["GET"], path: ["/placeholder-regex*"] }],
                    handle: [
                      {
                        handler: "rewrite",
                        path_regexp: [
                          { find: "{http.vars.re}", replace: "literal" },
                        ],
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                  },
                  {
                    match: [{
                      method: ["GET"],
                      path: ["/query-placeholder-key"],
                    }],
                    handle: [
                      {
                        handler: "rewrite",
                        uri:
                          "/query-placeholder-key-upstream?prefix{http.request.uri.query}=v",
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                  },
                  {
                    match: [{ method: ["GET"], path: ["/serve/*"] }],
                    handle: [
                      {
                        handler: "rewrite",
                        uri: "/serve/{http.request.header.X-Fwd}?",
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                  },
                  {
                    match: [{ method: ["GET"], path: ["/*.png"] }],
                    handle: [
                      {
                        handler: "rewrite",
                        uri: "/i{http.request.uri}",
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api//raw-file.json?x=raw&y=raw`);
        assertEquals(res.status, 200);
        const body = await res.json();
        assertEquals(body.path, "/cooked-file");
        assertEquals(body.query, "?x=cooked&y=raw");

        const templatedRes = await fetch(
          `${baseUrl}/template?x=1&y=two`,
          { headers: { "X-Raw": "a b&c=d" } },
        );
        assertEquals(templatedRes.status, 200);
        const templatedBody = await templatedRes.json();
        assertEquals(templatedBody.path, "/templated");
        assertEquals(templatedBody.query, "?p=a+b%26c%3Dd&x=1&y=two");

        const literalQueryRes = await fetch(`${baseUrl}/literal-query`);
        assertEquals(literalQueryRes.status, 200);
        const literalQueryBody = await literalQueryRes.json();
        assertEquals(literalQueryBody.path, "/literal-query-upstream");
        assertEquals(literalQueryBody.query, "?a=b&c=d");

        const placeholderRegexRes = await rawHttpGet(
          baseUrl,
          "/placeholder-regex/{http.vars.re}?x=1",
          "localhost",
        );
        assertEquals(placeholderRegexRes.status, 200);
        const placeholderRegexBody = JSON.parse(placeholderRegexRes.body);
        assertEquals(placeholderRegexBody.path, "/placeholder-regex/literal");
        assertEquals(placeholderRegexBody.query, "?x=1");

        const queryPlaceholderKeyRes = await fetch(
          `${baseUrl}/query-placeholder-key?a=b&c=d`,
        );
        assertEquals(queryPlaceholderKeyRes.status, 200);
        const queryPlaceholderKeyBody = await queryPlaceholderKeyRes.json();
        assertEquals(
          queryPlaceholderKeyBody.path,
          "/query-placeholder-key-upstream",
        );
        assertEquals(
          queryPlaceholderKeyBody.query,
          "?prefixa=b&c=d=v",
        );

        const injectedQueryRes = await fetch(`${baseUrl}/serve/start`, {
          headers: {
            "X-Fwd": "foo?{env.CADDY_REWRITE_TEST_SECRET}=leak",
          },
        });
        assertEquals(injectedQueryRes.status, 200);
        const injectedQueryBody = await injectedQueryRes.json();
        assertEquals(injectedQueryBody.path, "/serve/foo");
        assertEquals(
          injectedQueryBody.query,
          "?%7Benv.CADDY_REWRITE_TEST_SECRET%7D=leak",
        );

        const unicodeRes = await fetch(
          `${baseUrl}/%C2%B7%E2%88%B5.png?a=b`,
        );
        assertEquals(unicodeRes.status, 200);
        const unicodeBody = await unicodeRes.json();
        assertEquals(unicodeBody.path, "/i/%C2%B7%E2%88%B5.png");
        assertEquals(unicodeBody.query, "?a=b");
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy rewrite query operations mutate request query",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ method: ["GET"], path: ["/query-specific"] }],
                    handle: [
                      {
                        handler: "rewrite",
                        query: {
                          rename: [{
                            key: "merge_old",
                            val: "merge_new",
                          }],
                          replace: [{
                            key: "target",
                            search: "raw",
                            replace: "cooked",
                          }],
                        },
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                    terminal: true,
                  },
                  {
                    match: [{ method: ["GET"], path: ["/query*"] }],
                    handle: [
                      {
                        handler: "vars",
                        old_key: "old",
                        new_key: "new",
                        set_key: "mode",
                        set_value: "compiled",
                        add_key: "extra",
                        add_value: "1",
                        delete_key: "gone",
                        search_value: "raw",
                        replace_value: "cooked",
                      },
                      {
                        handler: "rewrite",
                        query: {
                          rename: [{
                            key: "{http.vars.old_key}",
                            val: "{http.vars.new_key}",
                          }],
                          set: [{
                            key: "{http.vars.set_key}",
                            val: "{http.vars.set_value}",
                          }],
                          add: [{
                            key: "{http.vars.add_key}",
                            val: "{http.vars.add_value}",
                          }],
                          replace: [
                            {
                              key: "*",
                              search: "{http.vars.search_value}",
                              replace: "{http.vars.replace_value}",
                            },
                          ],
                          delete: ["{http.vars.delete_key}"],
                        },
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(
          `${baseUrl}/query?old=raw-value&gone=1&mode=raw&z=keep`,
        );
        assertEquals(res.status, 200);
        const body = await res.json();
        assertEquals(
          body.query,
          "?extra=1&mode=compiled&new=cooked-value&z=keep",
        );

        const targeted = await fetch(
          `${baseUrl}/query-specific?merge_old=one&merge_new=existing&target=raw&other=raw`,
        );
        assertEquals(targeted.status, 200);
        const targetedBody = await targeted.json();
        assertEquals(
          targetedBody.query,
          "?merge_new=one&other=cooked&target=cooked",
        );
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy reverse_proxy expands upstream placeholders",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/rewrite-proxy"] }],
                  handle: [{
                    handler: "reverse_proxy",
                    rewrite: {
                      uri:
                        "/backend-rewritten?from=proxy&orig={http.request.uri.path}",
                    },
                    upstreams: [{ dial: backend.dial }],
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/nondeferred-proxy"] }],
                  handle: [{
                    handler: "reverse_proxy",
                    headers: {
                      response: {
                        delete: ["X-Origin-Match"],
                        set: {
                          "X-Nondeferred": ["yes"],
                        },
                      },
                    },
                    upstreams: [{ dial: backend.dial }],
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/method-proxy"] }],
                  handle: [{
                    handler: "reverse_proxy",
                    headers: {
                      request: {
                        set: {
                          "X-Rewritten-Method": ["{http.request.method}"],
                          "X-Rewritten-Path": ["{http.request.uri.path}"],
                        },
                      },
                      response: {
                        deferred: true,
                        set: {
                          "X-Hook-Method": ["{http.request.method}"],
                          "X-Hook-Path": ["{http.request.uri.path}"],
                        },
                      },
                    },
                    rewrite: {
                      method: "get",
                      uri: "/method-rewritten",
                    },
                    upstreams: [{ dial: backend.dial }],
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/deferred-static-upstream"] }],
                  handle: [{
                    handler: "headers",
                    response: {
                      deferred: true,
                      set: {
                        "X-Deferred-Upstream": [
                          "{http.reverse_proxy.upstream.hostport}",
                        ],
                      },
                    },
                  }, {
                    handler: "reverse_proxy",
                    upstreams: [{ dial: backend.dial }],
                  }],
                  terminal: true,
                }, {
                  handle: [{
                    handler: "vars",
                    backend: backend.dial,
                    origin_prefix: "ok",
                    proxy_status: "203",
                  }, {
                    handler: "reverse_proxy",
                    handle_response: [{
                      match: {
                        status_code: [2],
                        headers: {
                          "X-Origin-Match": ["ok*"],
                        },
                      },
                      status_code: "{http.vars.proxy_status}",
                    }],
                    headers: {
                      request: {
                        set: {
                          "X-Caddy-Compiled": [
                            "{http.reverse_proxy.upstream.hostport}",
                          ],
                          "X-Upstream-Address": [
                            "{http.reverse_proxy.upstream.address}",
                          ],
                          "X-Upstream-Host": [
                            "{http.reverse_proxy.upstream.host}",
                          ],
                          "X-Upstream-Port": [
                            "{http.reverse_proxy.upstream.port}",
                          ],
                        },
                      },
                      response: {
                        deferred: true,
                        require: {
                          status_code: [203],
                        },
                        set: {
                          "X-Upstream-Status": [
                            "{http.reverse_proxy.status_code}",
                          ],
                          "X-Upstream-Status-Text": [
                            "{http.reverse_proxy.status_text}",
                          ],
                          "X-Upstream-Latency": [
                            "{http.reverse_proxy.upstream.latency}",
                          ],
                          "X-Upstream-Latency-Ms": [
                            "{http.reverse_proxy.upstream.latency_ms}",
                          ],
                          "X-Upstream-Origin": [
                            "{http.reverse_proxy.header.X-Origin-Match}",
                          ],
                        },
                      },
                    },
                    upstreams: [{ dial: "{http.vars.backend}" }],
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/dynamic-proxy`);
        assertEquals(res.status, 203);
        assertEquals(res.headers.get("x-upstream-status"), "200");
        assertEquals(res.headers.get("x-upstream-status-text"), "200 OK");
        assertEquals(
          /^[0-9]/.test(res.headers.get("x-upstream-latency") ?? ""),
          true,
        );
        assertEquals(
          Number.isFinite(Number(res.headers.get("x-upstream-latency-ms"))),
          true,
        );
        assertEquals(res.headers.get("x-upstream-origin"), "ok-from-backend");
        const body = await res.json();
        assertEquals(body.path, "/dynamic-proxy");
        assertEquals(body.header, backend.dial);
        assertEquals(body.upstreamAddress, backend.dial);
        assertEquals(body.upstreamHost, "127.0.0.1");
        assertEquals(body.upstreamPort, backend.dial.split(":")[1]);

        const rewritten = await fetch(`${baseUrl}/rewrite-proxy?old=1`);
        assertEquals(rewritten.status, 200);
        const rewrittenBody = await rewritten.json();
        assertEquals(rewrittenBody.method, "GET");
        assertEquals(rewrittenBody.path, "/backend-rewritten");
        assertEquals(rewrittenBody.query, "?from=proxy&orig=%2Frewrite-proxy");

        const nondeferred = await fetch(`${baseUrl}/nondeferred-proxy`);
        assertEquals(nondeferred.status, 200);
        assertEquals(nondeferred.headers.get("x-origin-match"), null);
        assertEquals(nondeferred.headers.get("x-nondeferred"), "yes");

        const methodRewrite = await fetch(`${baseUrl}/method-proxy`, {
          method: "POST",
          body: "payload",
        });
        assertEquals(methodRewrite.status, 200);
        assertEquals(methodRewrite.headers.get("x-hook-method"), "POST");
        assertEquals(methodRewrite.headers.get("x-hook-path"), "/method-proxy");
        const methodRewriteBody = await methodRewrite.json();
        assertEquals(methodRewriteBody.method, "GET");
        assertEquals(methodRewriteBody.path, "/method-rewritten");
        assertEquals(methodRewriteBody.rewrittenMethodHeader, "POST");
        assertEquals(methodRewriteBody.rewrittenPathHeader, "/method-proxy");

        const deferredStaticUpstream = await fetch(
          `${baseUrl}/deferred-static-upstream`,
        );
        assertEquals(deferredStaticUpstream.status, 200);
        assertEquals(
          deferredStaticUpstream.headers.get("x-deferred-upstream"),
          backend.dial,
        );
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy reverse_proxy supports unix socket upstreams",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startUnixBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "reverse_proxy",
                    headers: {
                      request: {
                        set: {
                          "X-Upstream-Address": [
                            "{http.reverse_proxy.upstream.address}",
                          ],
                          "X-Upstream-Host": [
                            "{http.reverse_proxy.upstream.host}",
                          ],
                          "X-Upstream-Port": [
                            "{http.reverse_proxy.upstream.port}",
                          ],
                        },
                      },
                    },
                    upstreams: [{ dial: backend.dial }],
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/v1.41/info?pretty=1`, {
          method: "POST",
          body: "payload",
        });
        assertEquals(res.status, 200);
        const body = await res.json();
        assertEquals(body.method, "POST");
        assertEquals(body.path, "/v1.41/info");
        assertEquals(body.query, "?pretty=1");
        assertEquals(body.body, "payload");
        assertEquals(body.upstreamAddress, backend.dial);
        assertEquals(body.upstreamHost, backend.socketPath);
        assertEquals(body.upstreamPort, "");
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy reverse_proxy sets forwarded headers",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/trusted-forwarded"] }],
                  handle: [{
                    handler: "reverse_proxy",
                    trusted_proxies: ["127.0.0.0/8"],
                    upstreams: [{ dial: backend.dial }],
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/header-up-forwarded"] }],
                  handle: [{
                    handler: "reverse_proxy",
                    headers: {
                      request: {
                        set: {
                          "X-Forwarded-For": ["configured-client"],
                          "X-Forwarded-Proto": ["configured-proto"],
                          "X-Forwarded-Host": ["configured-host"],
                        },
                      },
                    },
                    upstreams: [{ dial: backend.dial }],
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/delete-forwarded"] }],
                  handle: [{
                    handler: "reverse_proxy",
                    headers: {
                      request: {
                        delete: [
                          "X-Forwarded-For",
                          "X-Forwarded-Proto",
                          "X-Forwarded-Host",
                        ],
                      },
                    },
                    upstreams: [{ dial: backend.dial }],
                  }],
                  terminal: true,
                }, {
                  handle: [{
                    handler: "reverse_proxy",
                    upstreams: [{ dial: backend.dial }],
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await rawHttpGet(baseUrl, "/forwarded", "example.test", {
          "X-Forwarded-For": "203.0.113.1",
          "X-Forwarded-Proto": "https",
          "X-Forwarded-Host": "spoofed.test",
          "TE": "trailers",
          "Alt-Svc": 'h3=":443"',
          "Proxy-Authenticate": "Basic realm=proxy",
          "Proxy-Authorization": "Basic abc123",
        });
        assertEquals(res.status, 200);
        const body = JSON.parse(res.body);
        assertEquals(body.forwardedFor, "127.0.0.1");
        assertEquals(body.forwardedProto, "http");
        assertEquals(body.forwardedHost, "example.test");
        assertEquals(body.te, "trailers");
        assertEquals(body.altSvc, null);
        assertEquals(body.proxyAuthenticate, null);
        assertEquals(body.proxyAuthorization, null);

        const explicitUa = await rawHttpGet(
          baseUrl,
          "/forwarded",
          "example.test",
          {
            "User-Agent": "client-agent",
          },
        );
        assertEquals(explicitUa.status, 200);
        assertEquals(JSON.parse(explicitUa.body).userAgent, "client-agent");

        const configured = await rawHttpGet(
          baseUrl,
          "/header-up-forwarded",
          "example.test",
        );
        assertEquals(configured.status, 200);
        const configuredBody = JSON.parse(configured.body);
        assertEquals(configuredBody.forwardedFor, "configured-client");
        assertEquals(configuredBody.forwardedProto, "configured-proto");
        assertEquals(configuredBody.forwardedHost, "configured-host");

        const deleted = await rawHttpGet(
          baseUrl,
          "/delete-forwarded",
          "example.test",
        );
        assertEquals(deleted.status, 200);
        const deletedBody = JSON.parse(deleted.body);
        assertEquals(deletedBody.forwardedFor, null);
        assertEquals(deletedBody.forwardedProto, null);
        assertEquals(deletedBody.forwardedHost, null);

        const trusted = await rawHttpGet(
          baseUrl,
          "/trusted-forwarded",
          "example.test",
          {
            "X-Forwarded-For": "203.0.113.1",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "spoofed.test",
            "TE": "trailers",
            "Alt-Svc": 'h3=":443"',
            "Proxy-Authenticate": "Basic realm=proxy",
            "Proxy-Authorization": "Basic abc123",
          },
        );
        assertEquals(trusted.status, 200);
        const trustedBody = JSON.parse(trusted.body);
        assertEquals(trustedBody.forwardedFor, "203.0.113.1, 127.0.0.1");
        assertEquals(trustedBody.forwardedProto, "https");
        assertEquals(trustedBody.forwardedHost, "spoofed.test");
        assertEquals(trustedBody.te, "trailers");
        assertEquals(trustedBody.altSvc, null);
        assertEquals(trustedBody.proxyAuthenticate, null);
        assertEquals(trustedBody.proxyAuthorization, null);
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name:
    "compiled Caddy reverse_proxy preserves absent User-Agent and Accept-Encoding",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startRawHeaderCaptureBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "reverse_proxy",
                    upstreams: [{ dial: backend.dial }],
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await rawHttpGet(baseUrl, "/", "example.test");
        assertEquals(res.status, 200);
        assertEquals(res.body, "ok");
      });

      const requestHead = await backend.requestHead;
      assert(
        !requestHead.split("\r\n").some((line) =>
          line.toLowerCase().startsWith("user-agent:")
        ),
        requestHead,
      );
      assert(
        !requestHead.split("\r\n").some((line) =>
          line.toLowerCase().startsWith("accept-encoding:")
        ),
        requestHead,
      );
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy reverse_proxy request headers are proxy-only",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "reverse_proxy",
                    headers: {
                      request: {
                        set: {
                          "X-Upstream-Only": ["yes"],
                          "X-Original": ["mutated"],
                        },
                      },
                      // A response-header hook (header_down) reads the original
                      // request header, proving the request mutation above is
                      // upstream-only. A handle_response route that copied the
                      // upstream body to do this is intentionally unsupported.
                      response: {
                        set: {
                          "X-Original-In-Hook": [
                            "{http.request.header.X-Original}",
                          ],
                        },
                      },
                    },
                    upstreams: [{ dial: backend.dial }],
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/header-leak`, {
          headers: { "X-Original": "incoming" },
        });
        assertEquals(res.status, 200);
        assertEquals(res.headers.get("x-original-in-hook"), "incoming");
        const body = await res.json();
        assertEquals(body.upstreamOnly, "yes");
        assertEquals(body.original, "mutated");
        assertEquals(body.forwardedFor, "127.0.0.1");
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy reverse_proxy uses server trusted proxies",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                trusted_proxies: {
                  source: "static",
                  ranges: ["127.0.0.0/8"],
                },
                routes: [{
                  match: [{ path: ["/server-trusted-forwarded"] }],
                  handle: [{
                    handler: "reverse_proxy",
                    upstreams: [{ dial: backend.dial }],
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await rawHttpGet(
          baseUrl,
          "/server-trusted-forwarded",
          "example.test",
          {
            "X-Forwarded-For": "203.0.113.1",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "spoofed.test",
          },
        );
        assertEquals(res.status, 200);
        const body = JSON.parse(res.body);
        assertEquals(body.forwardedFor, "203.0.113.1, 127.0.0.1");
        assertEquals(body.forwardedProto, "https");
        assertEquals(body.forwardedHost, "spoofed.test");
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy rewrite operations expand placeholders",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/fragment"] }],
                  handle: [{
                    handler: "rewrite",
                    uri: "/rewritten?x=1#frag",
                  }, {
                    handler: "static_response",
                    body: "{http.request.uri}",
                  }],
                  terminal: true,
                }, {
                  handle: [{
                    handler: "vars",
                    method: "post",
                    prefix: "api",
                    find: "raw",
                    replace: "done",
                  }, {
                    handler: "rewrite",
                    method: "{http.vars.method}",
                    strip_path_prefix: "{http.vars.prefix}",
                    uri_substring: [{
                      find: "{http.vars.find}",
                      replace: "{http.vars.replace}",
                    }],
                  }, {
                    handler: "static_response",
                    body:
                      "{http.request.method}|{http.request.uri.path}|{http.request.uri.query}",
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/raw.json?x=raw`);
        assertEquals(res.status, 200);
        assertEquals(await res.text(), "POST|/done.json|x=done");

        const fragmentRes = await fetch(`${baseUrl}/fragment`);
        assertEquals(fragmentRes.status, 200);
        assertEquals(await fragmentRes.text(), "/rewritten?x=1");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name:
    "compiled Caddy headers apply immediate response operations before static_response",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/immediate"] }],
                  handle: [
                    {
                      handler: "headers",
                      response: {
                        add: { "X-Immediate": ["one"] },
                        set: {
                          "Content-Type": ["application/custom"],
                          " X-Padded ": ["must-not-appear"],
                          "X-Overwrite": ["early"],
                        },
                      },
                    },
                    {
                      handler: "static_response",
                      body: '{"ok":true}',
                      headers: {
                        "X-Overwrite": ["late"],
                      },
                    },
                  ],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/immediate`);
        assertEquals(res.status, 200);
        assertEquals(res.headers.get("content-type"), "application/custom");
        assertEquals(res.headers.get("x-padded"), null);
        assertEquals(res.headers.get("x-immediate"), "one");
        assertEquals(res.headers.get("x-overwrite"), "late");
        assertEquals(await res.text(), '{"ok":true}');
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name:
    "compiled Caddy headers apply immediate response operations before file_server",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      await Deno.writeTextFile(join(siteDir, "asset.html"), "<p>asset</p>");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/asset.html"] }],
                  handle: [
                    {
                      handler: "headers",
                      response: {
                        set: {
                          "Accept-Ranges": ["none"],
                          "Content-Type": ["application/custom"],
                          "Content-Range": ["bytes 0-0/1"],
                          "Etag": ['"early"'],
                          "Last-Modified": [
                            "Wed, 21 Oct 2015 07:28:00 GMT",
                          ],
                          "Vary": ["Custom-Input"],
                          "X-Immediate": ["file"],
                        },
                      },
                    },
                    {
                      handler: "file_server",
                      canonical_uris: false,
                    },
                  ],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/asset.html`);
        assertEquals(res.status, 200);
        assertEquals(res.headers.get("content-type"), "application/custom");
        assertEquals(res.headers.get("accept-ranges"), "bytes");
        assert(res.headers.get("etag") !== '"early"');
        assert(
          res.headers.get("last-modified") !==
            "Wed, 21 Oct 2015 07:28:00 GMT",
        );
        assertEquals(res.headers.get("vary"), "Custom-Input, Accept-Encoding");
        assertEquals(res.headers.get("content-range"), "bytes 0-0/1");
        assertEquals(res.headers.get("x-immediate"), "file");
        assertEquals(await res.text(), "<p>asset</p>");

        const rangeRes = await fetch(`${baseUrl}/asset.html`, {
          headers: { Range: "bytes=0-2" },
        });
        assertEquals(rangeRes.status, 206);
        assertEquals(rangeRes.headers.get("content-range"), "bytes 0-2/12");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy response hooks see generated content length",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      await Deno.writeTextFile(join(siteDir, "asset.txt"), "file bytes");
      await Deno.writeTextFile(
        join(siteDir, "immediate-then-deferred"),
        "hook state",
      );

      const requireLengthHeader = {
        handler: "headers",
        response: {
          deferred: true,
          require: {
            headers: {
              "Content-Length": [],
            },
          },
          set: {
            "X-Length-Seen": ["yes"],
            "X-Length-Value": ["{http.response.header.Content-Length}"],
          },
        },
      };
      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/fixed"] }],
                    handle: [
                      requireLengthHeader,
                      {
                        handler: "static_response",
                        body: "fixed bytes",
                      },
                    ],
                    terminal: true,
                  },
                  {
                    match: [{ path: ["/asset.txt"] }],
                    handle: [
                      requireLengthHeader,
                      {
                        handler: "file_server",
                        canonical_uris: false,
                      },
                    ],
                    terminal: true,
                  },
                  {
                    match: [{ path: ["/empty-require-headers"] }],
                    handle: [
                      {
                        handler: "headers",
                        response: {
                          deferred: true,
                          require: {
                            status_code: [2],
                            headers: {},
                          },
                          set: {
                            "X-Empty-Require-Headers": ["yes"],
                          },
                        },
                      },
                      {
                        handler: "static_response",
                        body: "empty matcher",
                      },
                    ],
                    terminal: true,
                  },
                  {
                    match: [{ path: ["/immediate-then-deferred"] }],
                    handle: [
                      {
                        handler: "headers",
                        response: {
                          set: {
                            "X-Immediate-State": ["ready"],
                          },
                        },
                      },
                      {
                        handler: "headers",
                        response: {
                          deferred: true,
                          require: {
                            headers: {
                              "X-Immediate-State": ["ready"],
                            },
                          },
                          set: {
                            "X-Deferred-Saw": [
                              "{http.response.header.X-Immediate-State}",
                            ],
                          },
                        },
                      },
                      {
                        handler: "file_server",
                        canonical_uris: false,
                      },
                    ],
                    terminal: true,
                  },
                  {
                    match: [{ path: ["/padded-response-require"] }],
                    handle: [
                      {
                        handler: "headers",
                        response: {
                          set: {
                            "X-Immediate-State": ["ready"],
                          },
                        },
                      },
                      {
                        handler: "headers",
                        response: {
                          deferred: true,
                          require: {
                            headers: {
                              " X-Immediate-State ": [],
                            },
                          },
                          set: {
                            "X-Padded-Require-Matched": ["no"],
                          },
                        },
                      },
                      {
                        handler: "static_response",
                        body: "padded require",
                      },
                    ],
                    terminal: true,
                  },
                  {
                    match: [{ method: ["HEAD"], path: ["/head-length"] }],
                    handle: [
                      {
                        handler: "headers",
                        response: {
                          deferred: true,
                          set: {
                            "Content-Length": ["123"],
                          },
                        },
                      },
                      {
                        handler: "static_response",
                        body: "fixed bytes",
                      },
                    ],
                    terminal: true,
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const fixed = await fetch(`${baseUrl}/fixed`);
        assertEquals(fixed.status, 200);
        assertEquals(fixed.headers.get("x-length-seen"), "yes");
        assertEquals(fixed.headers.get("x-length-value"), "11");
        assertEquals(await fixed.text(), "fixed bytes");

        const file = await fetch(`${baseUrl}/asset.txt`);
        assertEquals(file.status, 200);
        assertEquals(file.headers.get("x-length-seen"), "yes");
        assertEquals(file.headers.get("x-length-value"), "10");
        assertEquals(await file.text(), "file bytes");

        const empty = await fetch(`${baseUrl}/empty-require-headers`);
        assertEquals(empty.status, 200);
        assertEquals(empty.headers.get("x-empty-require-headers"), "yes");
        assertEquals(await empty.text(), "empty matcher");

        const immediateThenDeferred = await fetch(
          `${baseUrl}/immediate-then-deferred`,
        );
        assertEquals(immediateThenDeferred.status, 200);
        assertEquals(
          immediateThenDeferred.headers.get("x-immediate-state"),
          "ready",
        );
        assertEquals(
          immediateThenDeferred.headers.get("x-deferred-saw"),
          "ready",
        );
        assertEquals(await immediateThenDeferred.text(), "hook state");

        const paddedRequire = await fetch(
          `${baseUrl}/padded-response-require`,
        );
        assertEquals(paddedRequire.status, 200);
        assertEquals(paddedRequire.headers.get("x-immediate-state"), "ready");
        assertEquals(
          paddedRequire.headers.get("x-padded-require-matched"),
          null,
        );
        assertEquals(await paddedRequire.text(), "padded require");

        const headLength = await fetch(`${baseUrl}/head-length`, {
          method: "HEAD",
        });
        assertEquals(headLength.status, 200);
        assertEquals(headLength.headers.get("content-length"), "123");
        assertEquals(await headLength.text(), "");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name:
    "compiled Caddy headers preserve immediate response order before reverse_proxy",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/header-order"] }],
                  handle: [
                    {
                      handler: "headers",
                      response: {
                        add: { "X-Order": ["early"] },
                      },
                    },
                    {
                      handler: "reverse_proxy",
                      upstreams: [{ dial: backend.dial }],
                    },
                  ],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/header-order`);
        assertEquals(res.status, 200);
        assertEquals(res.headers.get("x-order"), "early, upstream");
        assertEquals(await res.text(), "ordered");
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy headers replace request and response values",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ method: ["GET"], path: ["/headers*"] }],
                    handle: [
                      {
                        handler: "vars",
                        req_re: "raw-(.*)",
                        res_re: "backend-(.*)",
                      },
                      {
                        handler: "headers",
                        request: {
                          set: { "X-Caddy-Compiled": ["raw-request-42"] },
                          replace: {
                            "X-Caddy-Compiled": [
                              {
                                search_regexp: "{http.vars.req_re}",
                                replace: "cooked-$1",
                              },
                            ],
                          },
                        },
                        response: {
                          replace: {
                            "X-Secret-Token": [
                              {
                                search_regexp: "{http.vars.res_re}",
                                replace: "compiled-$1",
                              },
                            ],
                          },
                          set: {
                            "X-Require-Matched": ["yes"],
                          },
                          require: {
                            headers: {
                              "X-Origin-Match": ["ok*"],
                              "X-Secret-Token": [],
                              "X-Missing": null,
                            },
                          },
                        },
                      },
                      {
                        handler: "reverse_proxy",
                        upstreams: [{ dial: backend.dial }],
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/headers`);
        assertEquals(res.status, 200);
        assertEquals(res.headers.get("x-secret-token"), "compiled-secret");
        assertEquals(res.headers.get("x-require-matched"), "yes");
        const body = await res.json();
        assertEquals(body.header, "cooked-request-42");
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy headers delete all before add and set",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/clear-headers"] }],
                  handle: [{
                    handler: "headers",
                    request: {
                      delete: ["*"],
                      add: { "X-Caddy-Added": ["one"] },
                      set: { "X-Caddy-Compiled": ["yes"] },
                    },
                    response: {
                      deferred: true,
                      delete: ["*"],
                      add: { "X-Response-Added": ["one"] },
                      set: { "X-Response-Compiled": ["yes"] },
                    },
                  }, {
                    handler: "reverse_proxy",
                    transport: { protocol: "http", compression: false },
                    upstreams: [{ dial: backend.dial }],
                  }],
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/clear-headers`, {
          headers: { "X-Remove-Me": "gone" },
        });
        assertEquals(res.status, 200);
        assertEquals(res.headers.get("x-origin-match"), null);
        assertEquals(res.headers.get("x-secret-token"), null);
        assertEquals(res.headers.get("x-response-added"), "one");
        assertEquals(res.headers.get("x-response-compiled"), "yes");
        const body = await res.json();
        assertEquals(body.header, "yes");
        assertEquals(body.addedHeader, "one");
        assertEquals(body.removedHeader, null);
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name:
    "compiled Caddy deferred response headers preserve null value semantics",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/null-response-headers"] }],
                  handle: [{
                    handler: "headers",
                    response: {
                      deferred: true,
                      add: {
                        "X-Add-None": null,
                        "X-Add-Blank": [null],
                      },
                      set: {
                        "X-Set-Blank": null,
                        "X-Set-Blank-Array": [null],
                      },
                    },
                  }, {
                    handler: "reverse_proxy",
                    upstreams: [{ dial: backend.dial }],
                  }],
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/null-response-headers`);
        assertEquals(res.status, 200);
        assertEquals(res.headers.get("x-add-none"), null);
        assertEquals(res.headers.get("x-add-blank"), "");
        assertEquals(res.headers.get("x-set-blank"), "");
        assertEquals(res.headers.get("x-set-blank-array"), "");
      });
    } finally {
      await backend.close();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy file_server serves absolute filesystem roots",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    const deniedBrowseDir = join(siteDir, "deniedroot", "denied");
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "diskroot", "disk"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "diskroot", "disk", "zzz-dir"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "diskroot", "disk", "visible-dir"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "diskroot", "disk", "hidden-dir"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "etagroot", "etag-error"), {
        recursive: true,
      });
      await Deno.mkdir(deniedBrowseDir, { recursive: true });
      await Deno.mkdir(
        join(siteDir, "etagroot", "etag-error", "bad.txt.etag"),
        {
          recursive: true,
        },
      );
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      await Deno.writeTextFile(
        join(siteDir, "etagroot", "etag-error", "bad.txt"),
        "bad etag sidecar",
      );
      await Deno.writeTextFile(
        join(siteDir, "diskroot", "disk", "000-file.txt"),
        "sort marker",
      );
      await Deno.writeTextFile(
        join(siteDir, "diskroot", "disk", "file.txt"),
        "from host filesystem",
      );
      await Deno.writeTextFile(
        join(siteDir, "diskroot", "disk", "empty-etag.txt"),
        "empty filesystem etag sidecar",
      );
      await Deno.writeTextFile(
        join(siteDir, "diskroot", "disk", "empty-etag.txt.etag"),
        "",
      );
      await Deno.writeTextFile(
        join(siteDir, "diskroot", "disk", "space name.txt"),
        "space",
      );
      await Deno.writeTextFile(
        join(siteDir, "diskroot", "disk", "invalid-mtime.txt"),
        "invalid mtime",
      );
      await Deno.writeTextFile(
        join(siteDir, "diskroot", "disk", "unreadable.txt"),
        "unreadable",
      );
      await Deno.symlink(
        "file.txt",
        join(siteDir, "diskroot", "disk", "file-link.txt"),
      );
      await Deno.writeTextFile(
        join(siteDir, "diskroot", "disk", "hidden.txt"),
        "hidden on disk",
      );
      await Deno.writeTextFile(
        join(siteDir, "diskroot", "disk", "hidden-dir", "nested.txt"),
        "hidden by absolute path prefix",
      );
      await Deno.writeTextFile(
        join(siteDir, "diskroot", "disk", "visible-dir", "nested.txt"),
        "not hidden by root-relative path",
      );

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ method: ["GET"], path: ["/etag-error*"] }],
                    handle: [
                      {
                        handler: "file_server",
                        root: join(siteDir, "etagroot"),
                        etag_file_extensions: [".etag"],
                        canonical_uris: false,
                      },
                    ],
                    terminal: true,
                  },
                  {
                    match: [{ method: ["GET"], path: ["/denied*"] }],
                    handle: [
                      {
                        handler: "file_server",
                        root: join(siteDir, "deniedroot"),
                        browse: {},
                        canonical_uris: false,
                      },
                    ],
                    terminal: true,
                  },
                  {
                    match: [{ method: ["GET"], path: ["/disk*"] }],
                    handle: [
                      {
                        handler: "file_server",
                        root: join(siteDir, "diskroot"),
                        hide: [
                          "hidden.txt",
                          "disk/visible-dir",
                          join(siteDir, "diskroot", "disk", "hidden-dir"),
                        ],
                        browse: { reveal_symlinks: true },
                        etag_file_extensions: [".etag"],
                        canonical_uris: false,
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await Deno.chmod(deniedBrowseDir, 0o000);
      const diskDirMtime = new Date("2020-01-02T03:04:05Z");
      const olderBrowseChildMtime = new Date("2020-01-03T04:05:06Z");
      const fractionalBrowseChildMtime = new Date("2020-01-03T04:05:06.123Z");
      for (
        const path of [
          join(siteDir, "diskroot", "disk", "000-file.txt"),
          join(siteDir, "diskroot", "disk", "zzz-dir"),
          join(siteDir, "diskroot", "disk", "visible-dir"),
          join(siteDir, "diskroot", "disk", "hidden-dir"),
          join(siteDir, "etagroot", "etag-error", "bad.txt"),
          join(siteDir, "diskroot", "disk", "unreadable.txt"),
          join(siteDir, "diskroot", "disk", "empty-etag.txt"),
          join(siteDir, "diskroot", "disk", "empty-etag.txt.etag"),
        ]
      ) {
        await Deno.utime(path, olderBrowseChildMtime, olderBrowseChildMtime);
      }
      await Deno.utime(
        join(siteDir, "diskroot", "disk", "space name.txt"),
        fractionalBrowseChildMtime,
        fractionalBrowseChildMtime,
      );
      await Deno.utime(
        join(siteDir, "diskroot", "disk", "file.txt"),
        new Date("2022-01-02T03:04:05Z"),
        new Date("2022-01-02T03:04:05Z"),
      );
      await Deno.utime(
        join(siteDir, "diskroot", "disk", "invalid-mtime.txt"),
        new Date(1000),
        new Date(1000),
      );
      await Deno.chmod(
        join(siteDir, "diskroot", "disk", "unreadable.txt"),
        0o000,
      );
      await Deno.utime(
        join(siteDir, "diskroot", "disk"),
        diskDirMtime,
        diskDirMtime,
      );
      await withZeroserve(tarPath, async (baseUrl) => {
        const deniedRes = await fetch(`${baseUrl}/disk/file.txt`, {
          headers: { "Accept-Encoding": "identity" },
        });
        assertEquals(deniedRes.status, 404);
        assertEquals(await deniedRes.text(), "");
        const deniedEtagSidecarRes = await fetch(
          `${baseUrl}/etag-error/bad.txt`,
        );
        assertEquals(deniedEtagSidecarRes.status, 404);
      });
      await withZeroserve(tarPath, async (baseUrl) => {
        const badEtagSidecarRes = await fetch(
          `${baseUrl}/etag-error/bad.txt`,
          {
            headers: { "Accept-Encoding": "identity" },
          },
        );
        assertEquals(badEtagSidecarRes.status, 500);
        assertEquals(await badEtagSidecarRes.text(), "Internal Server Error");

        const deniedBrowseRes = await fetch(`${baseUrl}/denied/`, {
          headers: { Accept: "application/json" },
        });
        assertEquals(deniedBrowseRes.status, 403);
        assertEquals(await deniedBrowseRes.text(), "Forbidden");

        const diskRes = await fetch(`${baseUrl}/disk/file.txt`, {
          headers: { "Accept-Encoding": "identity" },
        });
        assertEquals(diskRes.status, 200);
        const diskLastModified = diskRes.headers.get("last-modified");
        assertEquals(typeof diskLastModified, "string");
        assertEquals(diskRes.headers.get("etag"), '"cguushasjtvkk"');
        assertEquals(await diskRes.text(), "from host filesystem");

        const diskEmptyEtagRes = await fetch(
          `${baseUrl}/disk/empty-etag.txt`,
          {
            headers: { "Accept-Encoding": "identity" },
          },
        );
        assertEquals(diskEmptyEtagRes.status, 200);
        assertEquals(diskEmptyEtagRes.headers.get("etag"), null);
        assertEquals(
          await diskEmptyEtagRes.text(),
          "empty filesystem etag sidecar",
        );

        const diskNotDirRes = await fetch(
          `${baseUrl}/disk/file.txt/nested`,
        );
        assertEquals(diskNotDirRes.status, 404);
        assertEquals(await diskNotDirRes.text(), "");

        const diskNotModifiedRes = await fetch(`${baseUrl}/disk/file.txt`, {
          headers: {
            "Accept-Encoding": "identity",
            "If-Modified-Since": diskLastModified!,
          },
        });
        assertEquals(diskNotModifiedRes.status, 304);
        assertEquals(
          diskNotModifiedRes.headers.get("vary"),
          "Accept-Encoding",
        );
        // RFC 7232 / Go's writeNotModified: a 304 with an ETag omits
        // Last-Modified (the ETag is the stronger validator).
        assertEquals(diskNotModifiedRes.headers.get("last-modified"), null);
        assertEquals(await diskNotModifiedRes.text(), "");

        const diskFailedEtagRes = await fetch(`${baseUrl}/disk/file.txt`, {
          headers: {
            "Accept-Encoding": "identity",
            "If-None-Match": '"does-not-match"',
            "If-Modified-Since": diskLastModified!,
          },
        });
        assertEquals(diskFailedEtagRes.status, 200);
        assertEquals(await diskFailedEtagRes.text(), "from host filesystem");

        const invalidMtimeRes = await fetch(
          `${baseUrl}/disk/invalid-mtime.txt`,
          {
            headers: { "Accept-Encoding": "identity" },
          },
        );
        assertEquals(invalidMtimeRes.status, 200);
        assertEquals(invalidMtimeRes.headers.get("etag"), null);
        assertEquals(invalidMtimeRes.headers.get("last-modified"), null);
        assertEquals(await invalidMtimeRes.text(), "invalid mtime");

        const invalidMtimeConditionalRes = await fetch(
          `${baseUrl}/disk/invalid-mtime.txt`,
          {
            headers: {
              "Accept-Encoding": "identity",
              "If-Modified-Since": "Thu, 01 Jan 1970 00:00:01 GMT",
              "If-None-Match": '"anything"',
            },
          },
        );
        assertEquals(invalidMtimeConditionalRes.status, 200);
        assertEquals(
          await invalidMtimeConditionalRes.text(),
          "invalid mtime",
        );

        const unreadableRes = await fetch(`${baseUrl}/disk/unreadable.txt`);
        assertEquals(unreadableRes.status, 403);
        assertEquals(await unreadableRes.text(), "Forbidden");

        const diskFailedIfMatchRes = await fetch(`${baseUrl}/disk/file.txt`, {
          headers: {
            "Accept-Encoding": "identity",
            "If-Match": '"does-not-match"',
          },
        });
        assertEquals(diskFailedIfMatchRes.status, 412);
        assertEquals(
          diskFailedIfMatchRes.headers.get("vary"),
          "Accept-Encoding",
        );
        assertEquals(await diskFailedIfMatchRes.text(), "");

        const diskStaleUnmodifiedRes = await fetch(`${baseUrl}/disk/file.txt`, {
          headers: {
            "Accept-Encoding": "identity",
            "If-Unmodified-Since": "Thu, 01 Jan 1970 00:00:01 GMT",
          },
        });
        assertEquals(diskStaleUnmodifiedRes.status, 412);
        assertEquals(await diskStaleUnmodifiedRes.text(), "");

        const diskRangeRes = await fetch(`${baseUrl}/disk/file.txt`, {
          headers: {
            "Accept-Encoding": "identity",
            Range: "bytes=5-8",
            "If-Range": diskLastModified!,
          },
        });
        assertEquals(diskRangeRes.status, 206);
        assertEquals(await diskRangeRes.text(), "host");

        const staleIfRangeRes = await fetch(`${baseUrl}/disk/file.txt`, {
          headers: {
            "Accept-Encoding": "identity",
            Range: "bytes=5-8",
            "If-Range": "Thu, 01 Jan 1970 00:00:00 GMT",
          },
        });
        assertEquals(staleIfRangeRes.status, 200);
        assertEquals(staleIfRangeRes.headers.get("content-range"), null);
        assertEquals(await staleIfRangeRes.text(), "from host filesystem");

        const diskHiddenRes = await fetch(`${baseUrl}/disk/hidden.txt`);
        assertEquals(diskHiddenRes.status, 404);
        const diskNestedHiddenRes = await fetch(
          `${baseUrl}/disk/hidden-dir/nested.txt`,
        );
        assertEquals(diskNestedHiddenRes.status, 404);
        const diskRootRelativeHideRes = await fetch(
          `${baseUrl}/disk/visible-dir/nested.txt`,
        );
        assertEquals(diskRootRelativeHideRes.status, 200);
        assertEquals(
          await diskRootRelativeHideRes.text(),
          "not hidden by root-relative path",
        );

        const diskBrowseNoSlashRes = await fetch(`${baseUrl}/disk`, {
          headers: { Accept: "application/json" },
          redirect: "manual",
        });
        assertEquals(diskBrowseNoSlashRes.status, 308);
        assertEquals(diskBrowseNoSlashRes.headers.get("location"), "/disk/");
        assertEquals(await diskBrowseNoSlashRes.text(), "");

        const diskBrowseRes = await fetch(`${baseUrl}/disk/`, {
          headers: { Accept: "application/json" },
        });
        assertEquals(diskBrowseRes.status, 200);
        const diskBrowseLastModified = diskBrowseRes.headers.get(
          "last-modified",
        );
        assertEquals(
          diskBrowseLastModified,
          "Sun, 02 Jan 2022 03:04:05 GMT",
        );
        const diskListing = await diskBrowseRes.json();
        assertEquals(Array.isArray(diskListing), true);
        assertEquals(diskListing.length, 11);
        const zzzDirItem = diskListing.find((item: { name: string }) =>
          item.name === "zzz-dir/"
        );
        assertEquals(zzzDirItem.url, "./zzz-dir/");
        assertEquals(
          diskListing.some((item: { name: string }) =>
            item.name === "file.txt"
          ),
          true,
        );
        const diskFileItem = diskListing.find((item: { name: string }) =>
          item.name === "file.txt"
        );
        assertEquals(diskFileItem.mod_time, "2022-01-02T03:04:05Z");
        const diskSpaceItem = diskListing.find((item: { name: string }) =>
          item.name === "space name.txt"
        );
        assertEquals(diskSpaceItem.url, "./space%20name.txt");
        assertEquals(diskSpaceItem.mod_time, "2020-01-03T04:05:06.123Z");
        const symlinkItem = diskListing.find((item: { name: string }) =>
          item.name === "file-link.txt"
        );
        assertEquals(symlinkItem.size, "from host filesystem".length);
        assertEquals(symlinkItem.url, "./file-link.txt");
        assertEquals(symlinkItem.is_dir, false);
        assertEquals(symlinkItem.is_symlink, true);
        assertEquals(symlinkItem.symlink_path, "file.txt");
        assertEquals(
          diskListing.some((item: { name: string }) =>
            item.name === "hidden.txt"
          ),
          false,
        );
        assertEquals(
          diskListing.some((item: { name: string }) =>
            item.name === "hidden-dir/"
          ),
          true,
        );

        const sortedBrowseRes = await fetch(
          `${baseUrl}/disk/?sort=size&order=desc`,
          {
            headers: { Accept: "application/json" },
          },
        );
        assertEquals(sortedBrowseRes.status, 200);
        assertEquals(
          sortedBrowseRes.headers.get("set-cookie")?.includes("sort=size"),
          true,
        );
        assertEquals(
          sortedBrowseRes.headers.get("set-cookie")?.includes("order=desc"),
          true,
        );
        const sortedBrowseBody = await sortedBrowseRes.text();
        assertEquals(sortedBrowseBody.endsWith("\n"), true);
        const sortedListing = JSON.parse(sortedBrowseBody);
        assertEquals(
          sortedListing[0].size,
          "empty filesystem etag sidecar".length,
        );
        assertEquals(
          sortedListing.find((item: { name: string }) =>
            item.name === "file.txt"
          )?.size,
          "from host filesystem".length,
        );

        const textBrowseRes = await fetch(`${baseUrl}/disk/?sort=name`, {
          headers: { Accept: "text/plain" },
        });
        assertEquals(textBrowseRes.status, 200);
        const textBrowse = await textBrowseRes.text();
        assert(
          textBrowse.includes(
            "file.txt\t20 B\tJanuary 2, 2022 at 03:04:05\n",
          ),
          `unexpected browse text body: ${textBrowse}`,
        );

        const invalidOffsetRes = await fetch(`${baseUrl}/disk/?offset=999`, {
          headers: { Accept: "application/json" },
        });
        assertEquals(invalidOffsetRes.status, 200);
        const invalidOffsetListing = await invalidOffsetRes.json();
        assertEquals(invalidOffsetListing.length, diskListing.length);

        const browseNotModifiedRes = await fetch(`${baseUrl}/disk/`, {
          headers: {
            Accept: "application/json",
            "If-Modified-Since": diskBrowseLastModified!,
          },
        });
        assertEquals(browseNotModifiedRes.status, 304);
        assertEquals(await browseNotModifiedRes.text(), "");
      }, ["--expose-filesystem"]);
    } finally {
      await Deno.chmod(
        join(siteDir, "diskroot", "disk", "unreadable.txt"),
        0o644,
      ).catch(() => {});
      await Deno.chmod(deniedBrowseDir, 0o755).catch(() => {});
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy file_server treats slash root as filesystem",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "packed index");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/index.html"] }],
                  handle: [{
                    handler: "file_server",
                    root: "/",
                    pass_thru: true,
                  }, {
                    handler: "static_response",
                    status_code: 209,
                    body: "filesystem root denied",
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/index.html`);
        assertEquals(res.status, 209);
        assertEquals(await res.text(), "filesystem root denied");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name:
    "compiled Caddy file_server honors explicit default filesystem for relative roots",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "diskrel"), { recursive: true });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      await Deno.writeTextFile(join(siteDir, "diskrel", "file.txt"), "disk");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/file.txt"] }],
                  handle: [{
                    handler: "file_server",
                    fs: "default",
                    root: relative(repoRoot, join(siteDir, "diskrel")),
                    pass_thru: true,
                  }, {
                    handler: "static_response",
                    status_code: 209,
                    body: "filesystem denied",
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const deniedRes = await fetch(`${baseUrl}/file.txt`);
        assertEquals(deniedRes.status, 209);
        assertEquals(await deniedRes.text(), "filesystem denied");
      });
      await withZeroserve(tarPath, async (baseUrl) => {
        const diskRes = await fetch(`${baseUrl}/file.txt`);
        assertEquals(diskRes.status, 200);
        assertEquals(await diskRes.text(), "disk");
      }, ["--expose-filesystem"]);
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name:
    "compiled Caddy file_server skips canonical redirect after filename rewrite",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "public", "docs"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      await Deno.writeTextFile(
        join(siteDir, "public", "docs", "index.html"),
        "rewritten index",
      );

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/alias"] }],
                    handle: [
                      {
                        handler: "rewrite",
                        uri: "/docs",
                      },
                      {
                        handler: "file_server",
                        root: "public",
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/alias`, {
          headers: { "Accept-Encoding": "identity" },
          redirect: "manual",
        });
        assertEquals(res.status, 200);
        assertEquals(res.headers.get("location"), null);
        assertEquals(await res.text(), "rewritten index");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy file_server does not redirect unbrowsable directories",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "public", "empty"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      await Deno.writeTextFile(
        join(siteDir, "public", "empty", "note.txt"),
        "not an index",
      );

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/empty"] }],
                    handle: [
                      {
                        handler: "file_server",
                        root: "public",
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/empty`, {
          redirect: "manual",
        });
        assertEquals(res.status, 404);
        assertEquals(res.headers.get("location"), null);
        assertEquals(await res.text(), "");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy file_server redirects empty rewritten browse paths",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "public"), { recursive: true });
      await Deno.writeTextFile(join(siteDir, "public", "note.txt"), "note");
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/browse-root"] }],
                    handle: [
                      {
                        handler: "rewrite",
                        strip_path_prefix: "/browse-root",
                      },
                      {
                        handler: "file_server",
                        root: "public",
                        browse: {},
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/browse-root?x=1`, {
          headers: { Accept: "application/json" },
          redirect: "manual",
        });
        assertEquals(res.status, 308);
        assertEquals(res.headers.get("location"), "/browse-root/?x=1");
        assertEquals(await res.text(), "");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy file_server pass_thru checks exposed filesystem roots",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "diskroot", "disk"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "blockedroot", "private"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      await Deno.writeTextFile(
        join(siteDir, "diskroot", "disk", "file.txt"),
        "pass through disk file",
      );
      await Deno.writeTextFile(
        join(siteDir, "blockedroot", "private", "file.txt"),
        "blocked",
      );

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/disk/*"] }],
                    handle: [
                      {
                        handler: "file_server",
                        root: join(siteDir, "diskroot"),
                        pass_thru: true,
                      },
                      {
                        handler: "static_response",
                        status_code: 209,
                        body: "fallback",
                      },
                    ],
                  },
                  {
                    match: [{ path: ["/private/*"] }],
                    handle: [
                      {
                        handler: "file_server",
                        root: join(siteDir, "blockedroot"),
                        pass_thru: true,
                      },
                      {
                        handler: "static_response",
                        status_code: 209,
                        body: "fallback",
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await Deno.chmod(join(siteDir, "blockedroot", "private"), 0o000);
      await withZeroserve(tarPath, async (baseUrl) => {
        const fallbackRes = await fetch(`${baseUrl}/disk/file.txt`);
        assertEquals(fallbackRes.status, 209);
        assertEquals(await fallbackRes.text(), "fallback");
      });
      await withZeroserve(tarPath, async (baseUrl) => {
        const fileRes = await fetch(`${baseUrl}/disk/file.txt`, {
          headers: { "Accept-Encoding": "identity" },
        });
        assertEquals(fileRes.status, 200);
        assertEquals(await fileRes.text(), "pass through disk file");

        const notDirFallbackRes = await fetch(
          `${baseUrl}/disk/file.txt/nested`,
        );
        assertEquals(notDirFallbackRes.status, 209);
        assertEquals(await notDirFallbackRes.text(), "fallback");

        const blockedRes = await fetch(`${baseUrl}/private/file.txt`);
        assertEquals(blockedRes.status, 403);
        assertEquals(await blockedRes.text(), "Forbidden");
      }, ["--expose-filesystem"]);
    } finally {
      await Deno.chmod(
        join(siteDir, "blockedroot", "private"),
        0o755,
      ).catch(() => {});
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy file_server expands placeholders",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "sites", "alpha"), { recursive: true });
      await Deno.mkdir(join(siteDir, "star*root"), { recursive: true });
      await Deno.writeTextFile(
        join(siteDir, "sites", "alpha", "home.html"),
        "alpha <zs-meta>http.vars.tenant</zs-meta>",
      );
      await Deno.writeTextFile(
        join(siteDir, "sites", "alpha", "home.html{http.vars.etag_ext}"),
        '"alpha-sidecar"',
      );
      await Deno.writeTextFile(
        join(siteDir, "sites", "alpha", "secret.txt"),
        "secret",
      );
      await Deno.writeTextFile(
        join(siteDir, "star*root", "index.html"),
        "literal star root",
      );
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/dynamic/*"] }],
                  handle: [{
                    handler: "vars",
                    tenant: "{http.request.uri.path.1}",
                    root: "sites/{http.request.uri.path.1}",
                    index: "home.html",
                    etag_ext: ".etag",
                    status: "203",
                  }, {
                    handler: "rewrite",
                    uri: "/",
                  }, {
                    handler: "file_server",
                    index_names: ["{http.vars.index}"],
                    etag_file_extensions: ["{http.vars.etag_ext}"],
                    status_code: "{http.vars.status}",
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/literal-root"] }],
                  handle: [{
                    handler: "rewrite",
                    uri: "/",
                  }, {
                    handler: "file_server",
                    root: "star*root",
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/status-zero"] }],
                  handle: [{
                    handler: "vars",
                    status: "0",
                  }, {
                    handler: "rewrite",
                    uri: "/index.html",
                  }, {
                    handler: "file_server",
                    status_code: "{http.vars.status}",
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/status-zero-literal"] }],
                  handle: [{
                    handler: "rewrite",
                    uri: "/index.html",
                  }, {
                    handler: "file_server",
                    status_code: 0,
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/status-invalid"] }],
                  handle: [{
                    handler: "vars",
                    status: "not-a-status",
                  }, {
                    handler: "rewrite",
                    uri: "/index.html",
                  }, {
                    handler: "file_server",
                    status_code: "{http.vars.status}",
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/hidden/*"] }],
                  handle: [{
                    handler: "vars",
                    tenant: "{http.request.uri.path.1}",
                    root: "sites/{http.request.uri.path.1}",
                    secret: "secret.txt",
                  }, {
                    handler: "rewrite",
                    uri: "/secret.txt",
                  }, {
                    handler: "file_server",
                    hide: ["{http.vars.secret}"],
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const indexRes = await fetch(`${baseUrl}/dynamic/alpha`);
        assertEquals(indexRes.status, 203);
        assertEquals(indexRes.headers.get("etag"), '"alpha-sidecar"');
        assertEquals(
          await indexRes.text(),
          "alpha <zs-meta>http.vars.tenant</zs-meta>",
        );

        const hiddenRes = await fetch(`${baseUrl}/hidden/alpha`);
        assertEquals(hiddenRes.status, 404);

        const literalRootRes = await fetch(`${baseUrl}/literal-root`);
        assertEquals(literalRootRes.status, 200);
        assertEquals(await literalRootRes.text(), "literal star root");

        const statusZeroRes = await fetch(`${baseUrl}/status-zero`);
        assertEquals(statusZeroRes.status, 200);
        assertEquals(await statusZeroRes.text(), "fallback");

        const statusZeroLiteralRes = await fetch(
          `${baseUrl}/status-zero-literal`,
        );
        assertEquals(statusZeroLiteralRes.status, 200);
        assertEquals(await statusZeroLiteralRes.text(), "fallback");

        const statusInvalidRes = await fetch(`${baseUrl}/status-invalid`);
        assertEquals(statusInvalidRes.status, 500);
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy host matcher normalizes host headers",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    handle: [{
                      handler: "vars",
                      host_pat: "*.dynamic.test",
                      host_pat_port: "app.dynamic.test:443",
                    }],
                  },
                  {
                    match: [{
                      host: ["{http.vars.host_pat}"],
                      path: ["/dynamic-host"],
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 213,
                        body: "dynamic host matched",
                      },
                    ],
                    terminal: true,
                  },
                  {
                    match: [{
                      host: ["{http.vars.host_pat_port}"],
                      path: ["/dynamic-host-port"],
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 216,
                        body: "dynamic host port matched",
                      },
                    ],
                    terminal: true,
                  },
                  {
                    match: [{
                      host: ["*.Example.test"],
                      path: ["/HOST/*"],
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 212,
                        body: "host matched",
                      },
                    ],
                  },
                  {
                    match: [{
                      host: ["exämple.test", "*.bücher.test"],
                      path: ["/idna-host"],
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 214,
                        body: "idna host matched",
                      },
                    ],
                    terminal: true,
                  },
                  {
                    match: [{
                      host: ["2001:db8::1"],
                      path: ["/ipv6-host"],
                    }],
                    handle: [
                      {
                        handler: "static_response",
                        status_code: 215,
                        body: "ipv6 host matched",
                      },
                    ],
                    terminal: true,
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const matched = await rawHttpGet(
          baseUrl,
          "/host/path",
          "Sub.Example.test:443",
        );
        assertEquals(matched.status, 212);
        assertEquals(matched.body, "host matched");

        const missed = await rawHttpGet(
          baseUrl,
          "/host/path",
          "example.test:443",
        );
        assertEquals(missed.status, 200);

        const dynamic = await rawHttpGet(
          baseUrl,
          "/dynamic-host",
          "app.dynamic.test",
        );
        assertEquals(dynamic.status, 213);
        assertEquals(dynamic.body, "dynamic host matched");

        const dynamicWithPatternPort = await rawHttpGet(
          baseUrl,
          "/dynamic-host-port",
          "app.dynamic.test:443",
        );
        assertEquals(dynamicWithPatternPort.status, 200);

        const idnaExact = await rawHttpGet(
          baseUrl,
          "/idna-host",
          "xn--exmple-cua.test",
        );
        assertEquals(idnaExact.status, 214);
        assertEquals(idnaExact.body, "idna host matched");

        const idnaWildcard = await rawHttpGet(
          baseUrl,
          "/idna-host",
          "docs.xn--bcher-kva.test",
        );
        assertEquals(idnaWildcard.status, 214);
        assertEquals(idnaWildcard.body, "idna host matched");

        const ipv6Bare = await rawHttpGet(
          baseUrl,
          "/ipv6-host",
          "2001:db8::1",
        );
        assertEquals(ipv6Bare.status, 215);
        assertEquals(ipv6Bare.body, "ipv6 host matched");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy path matcher supports Caddy glob syntax",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    handle: [{
                      handler: "vars",
                      dynamic_path: "/dynamic/{http.request.uri.path.1}/end",
                      dynamic_case_path: "/Case/MiXeD/End",
                    }],
                  },
                  {
                    match: [{
                      path: [
                        "/Glob/[a-c]?/End",
                        "/Glob/*/Tail",
                        "/Class/[!]/End",
                        "/Invalid/[-]/End",
                        "/Escaped/%40/End",
                        "/Space/ /End",
                      ],
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 214,
                      body: "path glob matched",
                    }],
                    terminal: true,
                  },
                  {
                    match: [{
                      path_regexp: {
                        name: "trail",
                        pattern: "^/Trail/$",
                      },
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 216,
                      body: "path regexp matched",
                      headers: {
                        "X-Path": ["{http.request.uri.path}"],
                        "X-Trail": ["{http.regexp.trail.0}"],
                      },
                    }],
                    terminal: true,
                  },
                  {
                    match: [{
                      path: ["/Empty-Re/*"],
                      path_regexp: {
                        name: "empty",
                        pattern: "",
                      },
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 217,
                      body: "empty regexp matched",
                      headers: {
                        "X-Empty": ["{http.regexp.empty.0}"],
                      },
                    }],
                    terminal: true,
                  },
                  {
                    match: [{
                      path: ["{http.vars.dynamic_path}"],
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 215,
                      body: "dynamic path matched",
                    }],
                    terminal: true,
                  },
                  {
                    match: [{
                      path: ["{http.vars.dynamic_case_path}"],
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 218,
                      body: "dynamic case path matched",
                    }],
                    terminal: true,
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const classRes = await fetch(`${baseUrl}/glob/b7/end`);
        assertEquals(classRes.status, 214);
        assertEquals(await classRes.text(), "path glob matched");

        const starRes = await fetch(`${baseUrl}/glob/one/tail`);
        assertEquals(starRes.status, 214);
        assertEquals(await starRes.text(), "path glob matched");

        const slashRes = await fetch(`${baseUrl}/glob/one/two/tail`);
        assertEquals(slashRes.status, 200);

        const classBangRes = await fetch(`${baseUrl}/class/!/end`);
        assertEquals(classBangRes.status, 214);
        assertEquals(await classBangRes.text(), "path glob matched");

        const classNegationRes = await fetch(`${baseUrl}/class/x/end`);
        assertEquals(classNegationRes.status, 200);

        const invalidClassRes = await fetch(`${baseUrl}/invalid/-/end`);
        assertEquals(invalidClassRes.status, 200);

        const escapedRes = await fetch(`${baseUrl}/escaped/%40/end`);
        assertEquals(escapedRes.status, 214);
        assertEquals(await escapedRes.text(), "path glob matched");

        const decodedRes = await fetch(`${baseUrl}/escaped/@/end`);
        assertEquals(decodedRes.status, 200);

        const spaceRes = await fetch(`${baseUrl}/space/%20/end`);
        assertEquals(spaceRes.status, 214);
        assertEquals(await spaceRes.text(), "path glob matched");

        const dynamicRes = await fetch(`${baseUrl}/dynamic/value/end`);
        assertEquals(dynamicRes.status, 215);
        assertEquals(await dynamicRes.text(), "dynamic path matched");

        const dynamicCaseRes = await fetch(`${baseUrl}/case/mixed/end`);
        assertEquals(dynamicCaseRes.status, 200);

        const trailRes = await fetch(`${baseUrl}/Trail/`);
        assertEquals(trailRes.status, 216);
        assertEquals(await trailRes.text(), "path regexp matched");
        assertEquals(trailRes.headers.get("x-path"), "/Trail/");
        assertEquals(trailRes.headers.get("x-trail"), "/Trail/");

        const emptyReRes = await fetch(`${baseUrl}/Empty-Re/value`);
        assertEquals(emptyReRes.status, 217);
        assertEquals(await emptyReRes.text(), "empty regexp matched");
        assertEquals(emptyReRes.headers.get("x-empty"), "");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name:
    "compiled Caddy protocol matcher follows HTTP version and gRPC content type",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ protocol: "grpc" }],
                    handle: [{
                      handler: "static_response",
                      status_code: 218,
                      body: "grpc",
                    }],
                    terminal: true,
                  },
                  {
                    match: [{ protocol: "http/1.1" }],
                    handle: [{
                      handler: "static_response",
                      status_code: 219,
                      body: "h1",
                    }],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const h1 = await fetch(`${baseUrl}/proto`);
        assertEquals(h1.status, 219);
        assertEquals(await h1.text(), "h1");

        const grpc = await fetch(`${baseUrl}/proto`, {
          headers: { "Content-Type": "application/grpc+proto" },
        });
        assertEquals(grpc.status, 218);
        assertEquals(await grpc.text(), "grpc");

        const grpcFirst = await rawHttpGetWithHeaderLines(
          baseUrl,
          "/proto",
          "localhost",
          [
            "Content-Type: application/grpc+proto",
            "Content-Type: text/plain",
          ],
        );
        assertEquals(grpcFirst.status, 218);
        assertEquals(grpcFirst.body, "grpc");

        const grpcSecond = await rawHttpGetWithHeaderLines(
          baseUrl,
          "/proto",
          "localhost",
          [
            "Content-Type: text/plain",
            "Content-Type: application/grpc+proto",
          ],
        );
        assertEquals(grpcSecond.status, 219);
        assertEquals(grpcSecond.body, "h1");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy regex matchers feed placeholder-expanded headers",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{
                      path_regexp: {
                        name: "item",
                        pattern: "^/items/([a-z0-9-]+)$",
                      },
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 220,
                      body: "path regex",
                      headers: {
                        "X-Item": ["{http.regexp.item.1}"],
                      },
                    }],
                    terminal: true,
                  },
                  {
                    match: [{
                      path_regexp: {
                        name: "letters",
                        pattern: "^/letters/a{2,}b$",
                      },
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 223,
                      body: "{http.regexp.letters.0}",
                    }],
                    terminal: true,
                  },
                  {
                    match: [{
                      path_regexp: {
                        name: "named",
                        pattern: "^/named/(?P<slug>[a-z]+)$",
                      },
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 224,
                      body:
                        "{http.regexp.named.slug}|{http.regexp.slug}|{http.regexp.named.1}",
                    }],
                    terminal: true,
                  },
                  {
                    match: [{
                      path_regexp: {
                        name: "optional",
                        pattern: "^/optional(?:/(?P<slug>[a-z]+))?$",
                      },
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 225,
                      body:
                        "{http.regexp.optional.slug}|{http.regexp.slug}|{http.regexp.optional.1}",
                    }],
                    terminal: true,
                  },
                  {
                    match: [{
                      header_regexp: {
                        "X-Token": {
                          name: "tok",
                          pattern: "^Bearer ([a-z0-9]+)$",
                        },
                      },
                    }],
                    handle: [{
                      handler: "static_response",
                      status_code: 221,
                      body: "header regex",
                      headers: {
                        "X-Token-Capture": ["{http.regexp.tok.1}"],
                      },
                    }],
                  },
                  {
                    match: [{ path: ["/vars"] }],
                    handle: [
                      {
                        handler: "vars",
                        feature: "release-42",
                      },
                      {
                        handler: "subroute",
                        routes: [{
                          match: [{
                            vars_regexp: {
                              feature: {
                                name: "feat-name",
                                pattern: "^release-([0-9]+)$",
                              },
                            },
                          }],
                          handle: [{
                            handler: "static_response",
                            status_code: 222,
                            body: "vars regex",
                            headers: {
                              "X-Feature-Number": [
                                "{http.regexp.feat-name.1}",
                              ],
                            },
                          }],
                        }],
                      },
                    ],
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const pathRes = await fetch(`${baseUrl}/items/abc-123`);
        assertEquals(pathRes.status, 220);
        assertEquals(pathRes.headers.get("x-item"), "abc-123");
        assertEquals(await pathRes.text(), "path regex");

        const quantifierRes = await fetch(`${baseUrl}/letters/aaab`);
        assertEquals(quantifierRes.status, 223);
        assertEquals(await quantifierRes.text(), "/letters/aaab");

        const namedRes = await fetch(`${baseUrl}/named/slug`);
        assertEquals(namedRes.status, 224);
        assertEquals(await namedRes.text(), "slug|slug|slug");

        const optionalMissingRes = await fetch(`${baseUrl}/optional`);
        assertEquals(optionalMissingRes.status, 225);
        assertEquals(await optionalMissingRes.text(), "||");

        const optionalPresentRes = await fetch(`${baseUrl}/optional/slug`);
        assertEquals(optionalPresentRes.status, 225);
        assertEquals(await optionalPresentRes.text(), "slug|slug|slug");

        const headerRes = await fetch(`${baseUrl}/anything`, {
          headers: { "X-Token": "Bearer abc123" },
        });
        assertEquals(headerRes.status, 221);
        assertEquals(headerRes.headers.get("x-token-capture"), "abc123");
        assertEquals(await headerRes.text(), "header regex");

        const varsRes = await fetch(`${baseUrl}/vars`);
        assertEquals(varsRes.status, 222);
        assertEquals(varsRes.headers.get("x-feature-number"), "42");
        assertEquals(await varsRes.text(), "vars regex");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy placeholders expand request and response state",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/place/*"] }],
                  handle: [{
                    handler: "static_response",
                    status_code: 223,
                    body: "placeholders",
                    headers: {
                      "X-Host": ["{http.request.host}"],
                      "X-Port": ["{http.request.port}"],
                      "X-Hostport": ["{http.request.hostport}"],
                      "X-Host-Label": ["{http.request.host.labels.0}"],
                      "X-Local": ["{http.request.local}"],
                      "X-Local-Host": ["{http.request.local.host}"],
                      "X-Local-Port": ["{http.request.local.port}"],
                      "X-Duration": ["{http.request.duration}"],
                      "X-Duration-Ms": ["{http.request.duration_ms}"],
                      "X-Cookie-Session": ["{http.request.cookie.session}"],
                      "X-Cookie-Theme": ["{http.request.cookie.THEME}"],
                      "X-Cookie-Quoted": ["{http.request.cookie.quoted}"],
                      "X-Cookie-Missing": ["{http.request.cookie.missing}"],
                      "X-Remote-Host": ["{http.request.remote.host}"],
                      "X-Remote-Masked": ["{http.request.remote.host/24}"],
                      "X-Remote-Masked-Invalid": [
                        "{http.request.remote.host/999}",
                      ],
                      "X-Remote-Port": ["{http.request.remote.port}"],
                      "X-Uri-Escaped": ["{http.request.uri_escaped}"],
                      "X-Path-Escaped": ["{http.request.uri.path_escaped}"],
                      "X-Query-Escaped": ["{http.request.uri.query_escaped}"],
                      "X-Path-Part": [
                        "{http.request.uri.path.0}/{http.request.uri.path.1}/{http.request.uri.path.2}",
                      ],
                      "X-Proto": ["{http.request.proto}"],
                      "X-Proto-Name": ["{http.request.proto_name}"],
                      "X-UUID": ["{http.request.uuid}"],
                      "X-Content-Type-Seen": [
                        "{http.response.header.Content-Type}",
                      ],
                      "X-Shutting-Down": ["{http.shutting_down}"],
                      "X-Time-Until-Shutdown": ["{http.time_until_shutdown}"],
                    },
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/templ/*"] }],
                  handle: [
                    {
                      handler: "vars",
                      status: "224",
                    },
                    {
                      handler: "static_response",
                      status_code: "{http.vars.status}",
                      body: '{"part":"{http.request.uri.path.1}"}',
                    },
                  ],
                  terminal: true,
                }, {
                  match: [{ path: ["/templ-spaced-status"] }],
                  handle: [
                    {
                      handler: "vars",
                      status: " 224 ",
                    },
                    {
                      handler: "static_response",
                      status_code: "{http.vars.status}",
                      body: "invalid status",
                    },
                  ],
                  terminal: true,
                }, {
                  match: [{ method: ["HEAD"], path: ["/static-head-length"] }],
                  handle: [{
                    handler: "static_response",
                    body: "fixed bytes",
                    headers: {
                      "Content-Length": ["123"],
                    },
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/orig/*"] }],
                  handle: [{
                    handler: "rewrite",
                    uri: "/rewritten/{http.request.uri.path.1}?after=1",
                  }, {
                    handler: "static_response",
                    body: "originals",
                    headers: {
                      "X-Current-Method": ["{http.request.method}"],
                      "X-Original-Method": ["{http.request.orig_method}"],
                      "X-Current-Uri": ["{http.request.uri}"],
                      "X-Original-Uri": ["{http.request.orig_uri}"],
                      "X-Current-Path": ["{http.request.uri.path}"],
                      "X-Original-Path": ["{http.request.orig_uri.path}"],
                      "X-Original-Path-Part": [
                        "{http.request.orig_uri.path.0}/{http.request.orig_uri.path.1}",
                      ],
                      "X-Original-File": ["{http.request.orig_uri.path.file}"],
                      "X-Original-Dir": ["{http.request.orig_uri.path.dir}"],
                      "X-Original-Query": ["{http.request.orig_uri.query}"],
                      "X-Original-Prefixed-Query": [
                        "{http.request.orig_uri.prefixed_query}",
                      ],
                    },
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/relative-path"] }],
                  handle: [{
                    handler: "rewrite",
                    uri: "leaf.txt",
                  }, {
                    handler: "static_response",
                    body: "relative",
                    headers: {
                      "X-Relative-Path": ["{http.request.uri.path}"],
                      "X-Relative-File": ["{http.request.uri.path.file}"],
                      "X-Relative-Dir": ["{http.request.uri.path.dir}"],
                      "X-Relative-Base": [
                        "{http.request.uri.path.file.base}",
                      ],
                      "X-Relative-Ext": ["{http.request.uri.path.file.ext}"],
                    },
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/no-content-body"] }],
                  handle: [{
                    handler: "static_response",
                    status_code: 204,
                    body: "must not be sent",
                    headers: {
                      "Content-Type": ["text/custom"],
                    },
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/empty"] }],
                  handle: [{
                    handler: "static_response",
                    status_code: 204,
                  }],
                  terminal: true,
                }, {
                  match: [{ path: ["/close-override"] }],
                  handle: [{
                    handler: "static_response",
                    status_code: 204,
                    close: true,
                    headers: {
                      "Connection": ["keep-alive"],
                    },
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await rawHttpGet(
          baseUrl,
          "/place/one/two?x=raw",
          "Example.Test:4321",
          { "Cookie": 'Session=abc123; theme=dark; quoted="two words"' },
        );
        assertEquals(res.status, 223);
        assertEquals(res.body, "placeholders");
        assertEquals(res.headers["x-host"], "Example.Test");
        assertEquals(res.headers["x-port"], "4321");
        assertEquals(res.headers["x-hostport"], "Example.Test:4321");
        assertEquals(res.headers["x-host-label"], "test");
        assertEquals(res.headers["x-local-host"], "127.0.0.1");
        assertEquals(
          res.headers["x-local"],
          `127.0.0.1:${res.headers["x-local-port"]}`,
        );
        assertEquals(/^[0-9]+$/.test(res.headers["x-local-port"]), true);
        assertEquals(
          /^[0-9]+(\.[0-9]+)?(ns|µs|ms|s|m|h)/.test(
            res.headers["x-duration"],
          ),
          true,
        );
        assertEquals(Number(res.headers["x-duration-ms"]) >= 0, true);
        assertEquals(res.headers["x-cookie-session"], "abc123");
        assertEquals(res.headers["x-cookie-theme"], "dark");
        assertEquals(res.headers["x-cookie-quoted"], "two words");
        assertEquals(res.headers["x-cookie-missing"], "");
        assertEquals(res.headers["x-remote-host"], "127.0.0.1");
        assertEquals(res.headers["x-remote-masked"], "127.0.0.0/24");
        assertEquals(res.headers["x-remote-masked-invalid"], "127.0.0.1");
        assertEquals(/^[0-9]+$/.test(res.headers["x-remote-port"]), true);
        assertEquals(
          res.headers["x-uri-escaped"],
          "%2Fplace%2Fone%2Ftwo%3Fx%3Draw",
        );
        assertEquals(
          res.headers["x-path-escaped"],
          "%2Fplace%2Fone%2Ftwo",
        );
        assertEquals(res.headers["x-query-escaped"], "x%3Draw");
        assertEquals(res.headers["x-path-part"], "place/one/two");
        assertEquals(res.headers["x-proto"], "HTTP/1.1");
        assertEquals(res.headers["x-proto-name"], "HTTP/1.1");
        assertEquals(
          /^[0-9A-HJKMNP-TV-Z]{26}$/.test(res.headers["x-uuid"]),
          true,
        );
        assertEquals(
          res.headers["x-content-type-seen"],
          "",
        );
        assertEquals(res.headers["x-shutting-down"], "false");
        assertEquals(res.headers["x-time-until-shutdown"], "");

        const templRes = await fetch(`${baseUrl}/templ/value`);
        assertEquals(templRes.status, 224);
        assertEquals(templRes.headers.get("content-type"), "application/json");
        assertEquals(await templRes.text(), '{"part":"value"}');

        const templSpacedStatus = await fetch(`${baseUrl}/templ-spaced-status`);
        assertEquals(templSpacedStatus.status, 500);

        const staticHeadLength = await fetch(`${baseUrl}/static-head-length`, {
          method: "HEAD",
        });
        assertEquals(staticHeadLength.status, 200);
        assertEquals(staticHeadLength.headers.get("content-length"), "123");
        assertEquals(await staticHeadLength.text(), "");

        const orig = await rawHttpGet(
          baseUrl,
          "/orig/item.txt?before=1",
          "example.test",
        );
        assertEquals(orig.status, 200);
        assertEquals(orig.body, "originals");
        assertEquals(orig.headers["x-current-method"], "GET");
        assertEquals(orig.headers["x-original-method"], "GET");
        assertEquals(
          orig.headers["x-current-uri"],
          "/rewritten/item.txt?after=1",
        );
        assertEquals(orig.headers["x-original-uri"], "/orig/item.txt?before=1");
        assertEquals(orig.headers["x-current-path"], "/rewritten/item.txt");
        assertEquals(orig.headers["x-original-path"], "/orig/item.txt");
        assertEquals(orig.headers["x-original-path-part"], "orig/item.txt");
        assertEquals(orig.headers["x-original-file"], "item.txt");
        assertEquals(orig.headers["x-original-dir"], "/orig/");
        assertEquals(orig.headers["x-original-query"], "before=1");
        assertEquals(orig.headers["x-original-prefixed-query"], "?before=1");

        const relative = await rawHttpGet(
          baseUrl,
          "/relative-path",
          "example.test",
        );
        assertEquals(relative.status, 200);
        assertEquals(relative.body, "relative");
        assertEquals(relative.headers["x-relative-path"], "leaf.txt");
        assertEquals(relative.headers["x-relative-file"], "leaf.txt");
        assertEquals(relative.headers["x-relative-dir"], "");
        assertEquals(relative.headers["x-relative-base"], "leaf");
        assertEquals(relative.headers["x-relative-ext"], ".txt");

        const emptyRes = await fetch(`${baseUrl}/empty`);
        assertEquals(emptyRes.status, 204);
        assertEquals(emptyRes.headers.get("content-type"), null);

        const noContentBody = await fetch(`${baseUrl}/no-content-body`);
        assertEquals(noContentBody.status, 204);
        assertEquals(noContentBody.headers.get("content-type"), "text/custom");
        assertEquals(noContentBody.headers.get("content-length"), null);
        assertEquals(await noContentBody.text(), "");

        const closeOverride = await rawHttpGet(
          baseUrl,
          "/close-override",
          "example.test",
        );
        assertEquals(closeOverride.status, 204);
        assertEquals(closeOverride.headers["connection"], "keep-alive");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy TLS placeholders expand connection state",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/tls-placeholders"] }],
                    handle: [{
                      handler: "static_response",
                      status_code: 225,
                      body: "tls placeholders",
                      headers: {
                        "X-TLS-Proto": ["{http.request.tls.proto}"],
                        "X-TLS-Proto-Mutual": [
                          "{http.request.tls.proto_mutual}",
                        ],
                        "X-TLS-Server-Name": [
                          "{http.request.tls.server_name}",
                        ],
                        "X-TLS-Version": ["{http.request.tls.version}"],
                        "X-TLS-Cipher-Suite": [
                          "{http.request.tls.cipher_suite}",
                        ],
                        "X-TLS-Resumed": ["{http.request.tls.resumed}"],
                      },
                    }],
                    terminal: true,
                  },
                  {
                    match: [{ path: ["/h2-hop-headers"] }],
                    handle: [{
                      handler: "static_response",
                      status_code: 226,
                      body: "h2 hop headers",
                      headers: {
                        "Connection": ["keep-alive"],
                        "Keep-Alive": ["timeout=5"],
                      },
                    }],
                    terminal: true,
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      const cert = await generateSelfSignedCert();
      try {
        await withZeroserveTls(
          tarPath,
          cert.certPath,
          cert.keyPath,
          async (httpUrl, httpsUrl) => {
            const plain = await fetch(`${httpUrl}/tls-placeholders`);
            assertEquals(plain.status, 225);
            assertEquals(plain.headers.get("x-tls-proto"), "");
            assertEquals(plain.headers.get("x-tls-proto-mutual"), "");
            assertEquals(plain.headers.get("x-tls-server-name"), "");
            assertEquals(plain.headers.get("x-tls-version"), "");
            assertEquals(plain.headers.get("x-tls-cipher-suite"), "");
            assertEquals(plain.headers.get("x-tls-resumed"), "");

            const caCert = await Deno.readTextFile(cert.certPath);
            const client = Deno.createHttpClient({ caCerts: [caCert] });
            try {
              const tls = await fetch(`${httpsUrl}/tls-placeholders`, {
                client,
              });
              assertEquals(tls.status, 225);
              assertEquals(tls.headers.get("x-tls-proto-mutual"), "true");
              assertEquals(tls.headers.get("x-tls-version"), "tls1.3");
              assert(
                tls.headers.get("x-tls-cipher-suite")?.startsWith("TLS_"),
              );
              assertEquals(tls.headers.get("x-tls-resumed"), "false");

              const h2Hop = await fetch(`${httpsUrl}/h2-hop-headers`, {
                client,
              });
              assertEquals(h2Hop.status, 226);
              assertEquals(h2Hop.headers.get("connection"), null);
              assertEquals(h2Hop.headers.get("keep-alive"), null);
              assertEquals(await h2Hop.text(), "h2 hop headers");
            } finally {
              client.close();
            }
          },
        );
      } finally {
        await cert.cleanup();
      }
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy map handler resolves lazily",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{ path: ["/map/*"] }],
                  handle: [
                    {
                      handler: "map",
                      source: "{http.request.uri.path}",
                      destinations: ["{mapped}", "{second}"],
                      mappings: [
                        {
                          input: "/rewritten",
                          outputs: ["lazy-{http.request.uri.path}", "exact"],
                        },
                        {
                          input_regexp: "^/regex/([a-z]+)$",
                          outputs: ["rx-$1", null],
                        },
                      ],
                      defaults: ["default", "{http.request.uri.path.1}"],
                    },
                    {
                      handler: "rewrite",
                      uri: "/rewritten",
                    },
                    {
                      handler: "static_response",
                      body: "{mapped}|{second}",
                    },
                  ],
                  terminal: true,
                }, {
                  match: [{ path: ["/regex/*"] }],
                  handle: [
                    {
                      handler: "map",
                      source: "{http.request.uri.path}",
                      destinations: ["{mapped}", "{second}"],
                      mappings: [{
                        input_regexp: "^/regex/([a-z]+)$",
                        outputs: ["rx-$1", null],
                      }],
                      defaults: ["default", "fallback"],
                    },
                    {
                      handler: "static_response",
                      body: "{mapped}|{second}",
                    },
                  ],
                  terminal: true,
                }, {
                  match: [{ path: ["/named-map/*"] }],
                  handle: [
                    {
                      handler: "map",
                      source: "{http.request.uri.path}",
                      destinations: ["{mapped}"],
                      mappings: [{
                        input_regexp: "^/named-map/(?P<slug>[a-z]+)$",
                        outputs: ["named-$slug"],
                      }],
                      defaults: ["default"],
                    },
                    {
                      handler: "static_response",
                      body: "{mapped}",
                    },
                  ],
                  terminal: true,
                }, {
                  match: [{ path: ["/regex-token/*"] }],
                  handle: [
                    {
                      handler: "map",
                      source: "{http.request.uri.path}",
                      destinations: ["{mapped}"],
                      mappings: [{
                        input_regexp: "^/regex-token/([a-z]+)$",
                        outputs: ["rx-$1x|${1}x|$$1"],
                      }],
                    },
                    {
                      handler: "static_response",
                      body: "{mapped}",
                    },
                  ],
                  terminal: true,
                }, {
                  match: [{ path: ["/regex-placeholder/*"] }],
                  handle: [
                    {
                      handler: "map",
                      source: "{http.request.uri.path}",
                      destinations: ["{mapped}"],
                      mappings: [{
                        input_regexp: "^/regex-placeholder/([a-z]+)$",
                        outputs: ["rx-{http.request.uri.path}-$1"],
                      }],
                    },
                    {
                      handler: "static_response",
                      body: "{mapped}",
                    },
                  ],
                  terminal: true,
                }, {
                  match: [{ path: ["/empty-source-map"] }],
                  handle: [
                    {
                      handler: "map",
                      destinations: ["{mapped}"],
                      mappings: [{
                        input: "",
                        outputs: ["empty-{http.request.uri.path}"],
                      }],
                      defaults: ["default"],
                    },
                    {
                      handler: "rewrite",
                      uri: "/after-empty-source-map",
                    },
                    {
                      handler: "static_response",
                      body: "{mapped}",
                    },
                  ],
                  terminal: true,
                }, {
                  match: [{ path: ["/typed-map"] }],
                  handle: [
                    {
                      handler: "map",
                      source: "{http.request.uri.path}",
                      destinations: ["{arr}", "{obj}", "{flag}", "{count}"],
                      mappings: [{
                        input: "/typed-map",
                        outputs: [["a", "b"], { k: 1 }, true, 7],
                      }],
                    },
                    {
                      handler: "static_response",
                      body: "{arr}|{obj}|{flag}|{count}",
                    },
                  ],
                  terminal: true,
                }, {
                  match: [{ path: ["/loose-destination"] }],
                  handle: [
                    {
                      handler: "map",
                      source: "{http.request.uri.path}",
                      destinations: ["{mapped"],
                      mappings: [{
                        input: "/loose-destination",
                        outputs: ["loose-ok"],
                      }],
                    },
                    {
                      handler: "static_response",
                      body: "{mapped}",
                    },
                  ],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const lazyRes = await fetch(`${baseUrl}/map/original`);
        assertEquals(lazyRes.status, 200);
        assertEquals(await lazyRes.text(), "lazy-/rewritten|exact");

        const regexRes = await fetch(`${baseUrl}/regex/abc`);
        assertEquals(regexRes.status, 200);
        assertEquals(await regexRes.text(), "rx-abc|fallback");

        const namedRegexRes = await fetch(`${baseUrl}/named-map/slug`);
        assertEquals(namedRegexRes.status, 200);
        assertEquals(await namedRegexRes.text(), "named-slug");

        const regexTokenRes = await fetch(`${baseUrl}/regex-token/abc`);
        assertEquals(regexTokenRes.status, 200);
        assertEquals(await regexTokenRes.text(), "rx-|abcx|$1");

        const regexPlaceholderRes = await fetch(
          `${baseUrl}/regex-placeholder/abc`,
        );
        assertEquals(regexPlaceholderRes.status, 200);
        assertEquals(
          await regexPlaceholderRes.text(),
          "rx-{http.request.uri.path}-abc",
        );

        const emptySourceRes = await fetch(`${baseUrl}/empty-source-map`);
        assertEquals(emptySourceRes.status, 200);
        assertEquals(
          await emptySourceRes.text(),
          "empty-/after-empty-source-map",
        );

        const typedMapRes = await fetch(`${baseUrl}/typed-map`);
        assertEquals(typedMapRes.status, 200);
        assertEquals(await typedMapRes.text(), "[a b]|map[k:1]|true|7");

        const looseDestinationRes = await fetch(
          `${baseUrl}/loose-destination`,
        );
        assertEquals(looseDestinationRes.status, 200);
        assertEquals(await looseDestinationRes.text(), "loose-ok");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy invoke handler runs named routes",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                named_routes: {
                  shared: {
                    match: [{ path: ["/invoke/hit"] }],
                    handle: [{
                      handler: "headers",
                      response: {
                        deferred: true,
                        set: {
                          "X-Invoked": ["yes"],
                        },
                      },
                    }],
                  },
                  terminal_shared: {
                    match: [{ path: ["/invoke/terminal"] }],
                    handle: [{
                      handler: "static_response",
                      status_code: 209,
                      body: "terminal",
                    }],
                    terminal: true,
                  },
                },
                routes: [{
                  match: [{ path: ["/invoke/*"] }],
                  handle: [
                    {
                      handler: "invoke",
                      name: "shared",
                    },
                    {
                      handler: "invoke",
                      name: "terminal_shared",
                    },
                    {
                      handler: "static_response",
                      status_code: 208,
                      body: "after",
                    },
                  ],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const hit = await fetch(`${baseUrl}/invoke/hit`);
        assertEquals(hit.status, 208);
        assertEquals(hit.headers.get("x-invoked"), "yes");
        assertEquals(await hit.text(), "after");

        const miss = await fetch(`${baseUrl}/invoke/miss`);
        assertEquals(miss.status, 208);
        assertEquals(miss.headers.get("x-invoked"), null);
        assertEquals(await miss.text(), "after");

        const terminal = await fetch(`${baseUrl}/invoke/terminal`);
        assertEquals(terminal.status, 209);
        assertEquals(await terminal.text(), "terminal");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy file matcher sets file placeholders",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    const fsRoot = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "public", "app"), { recursive: true });
      await Deno.mkdir(join(siteDir, "public", "assets"), { recursive: true });
      await Deno.mkdir(join(siteDir, "public", "sites", "tenant-a"), {
        recursive: true,
      });
      await Deno.mkdir(join(fsRoot, "tenant-a"), { recursive: true });
      await Deno.writeTextFile(
        join(siteDir, "public", "app", "index.html"),
        "app",
      );
      await Deno.writeTextFile(join(siteDir, "public", "app.php"), "php");
      await Deno.writeTextFile(
        join(siteDir, "public", "literal{http.vars.ext}"),
        "literal split",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "assets", "app.123.css"),
        "css",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "literal[abc].txt"),
        "literal bracket",
      );
      await Deno.writeTextFile(join(siteDir, "public", "empty.txt"), "");
      await Deno.writeTextFile(join(siteDir, "public", "one-byte.txt"), "x");
      await Deno.writeTextFile(
        join(siteDir, "public", "literala.txt"),
        "glob-expanded bracket",
      );
      await Deno.writeTextFile(
        join(siteDir, "public", "sites", "tenant-a", "index.html"),
        "tenant",
      );
      await Deno.writeTextFile(
        join(fsRoot, "tenant-a", "index.html"),
        "fs tenant",
      );
      await Deno.writeTextFile(
        join(siteDir, "root-relative.txt"),
        "root relative",
      );
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      await Deno.utime(
        join(siteDir, "public", "one-byte.txt"),
        new Date("2019-02-03T04:05:06Z"),
        new Date("2019-02-03T04:05:06Z"),
      );
      await Deno.utime(
        join(siteDir, "public", "app"),
        new Date("2021-02-03T04:05:06Z"),
        new Date("2021-02-03T04:05:06Z"),
      );

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "vars",
                    root: "public",
                  }],
                }, {
                  match: [{
                    path: ["/asset"],
                    file: {
                      try_files: ["/assets/app.[0-9][0-9][0-9].css"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    body:
                      "{http.matchers.file.relative}|{http.matchers.file.type}|{http.matchers.file.remainder}",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/root-glob"],
                    file: {
                      root: "public/sites/*",
                      try_files: ["/index.html"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 221,
                    body: "root glob matched",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/absolute-root-glob"],
                    file: {
                      root: join(fsRoot, "tenant-*"),
                      try_files: ["/index.html"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 222,
                    body:
                      "{http.matchers.file.relative}|{http.matchers.file.absolute}|{http.matchers.file.type}",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/slash-root-fs"],
                    file: {
                      root: "/",
                      try_files: [join(fsRoot, "tenant-a", "index.html")],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 228,
                    body:
                      "{http.matchers.file.relative}|{http.matchers.file.absolute}|{http.matchers.file.type}",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/default-fs"],
                    file: {
                      fs: "default",
                      root: fsRoot,
                      try_files: ["/tenant-a/index.html"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 229,
                    body:
                      "{http.matchers.file.relative}|{http.matchers.file.absolute}|{http.matchers.file.type}",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/status-fallback"],
                    file: {
                      try_files: ["/definitely-missing.txt", "=410"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 204,
                    body: "should not run",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/size-policy-status-literal"],
                    file: {
                      try_policy: "largest_size",
                      try_files: ["=410"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 204,
                    body: "should not run",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/empty-try-files"],
                    file: {
                      try_policy: "first_exist_fallback",
                      try_files: [],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 204,
                    body: "should not run",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/root-relative.txt"],
                    file: {
                      root: ".",
                      try_files: ["{http.request.uri.path}"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    body:
                      "{http.matchers.file.relative}|{http.matchers.file.type}|{http.matchers.file.remainder}",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/literal*"],
                    file: {
                      try_files: ["{http.request.uri.path}"],
                      split_path: ["{http.vars.ext}"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    body:
                      "{http.matchers.file.relative}|{http.matchers.file.type}|{http.matchers.file.remainder}",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/largest-zero-only"],
                    file: {
                      try_policy: "largest_size",
                      try_files: ["/empty.txt"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 225,
                    body: "largest zero matched",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/smallest-zero-sentinel"],
                    file: {
                      try_policy: "smallest_size",
                      try_files: ["/empty.txt", "/one-byte.txt"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 226,
                    body: "{http.matchers.file.relative}",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    path: ["/newest-directory"],
                    file: {
                      try_policy: "most_recently_modified",
                      try_files: ["/one-byte.txt", "/app"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 227,
                    body:
                      "{http.matchers.file.relative}|{http.matchers.file.type}",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    file: {
                      try_files: [
                        "{http.request.uri.path}",
                        "{http.request.uri.path}/index.html",
                      ],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    body:
                      "{http.matchers.file.relative}|{http.matchers.file.type}|{http.matchers.file.remainder}",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    file: {
                      try_files: ["{http.request.uri.path}"],
                      split_path: [".php"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    body:
                      "{http.matchers.file.relative}|{http.matchers.file.type}|{http.matchers.file.remainder}",
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const indexRes = await fetch(`${baseUrl}/app`);
        assertEquals(indexRes.status, 200);
        assertEquals(await indexRes.text(), "/app/index.html|file|");

        const globRes = await fetch(`${baseUrl}/asset`);
        assertEquals(globRes.status, 200);
        assertEquals(await globRes.text(), "/assets/app.123.css|file|");

        const rootGlobRes = await fetch(`${baseUrl}/root-glob`);
        assertEquals(rootGlobRes.status, 221);
        assertEquals(await rootGlobRes.text(), "root glob matched");

        const absoluteRootGlobRes = await fetch(
          `${baseUrl}/absolute-root-glob`,
        );
        assertEquals(absoluteRootGlobRes.status, 200);
        assertEquals(await absoluteRootGlobRes.text(), "");

        const slashRootFsRes = await fetch(`${baseUrl}/slash-root-fs`);
        assertEquals(slashRootFsRes.status, 200);
        assertEquals(await slashRootFsRes.text(), "");

        const defaultFsRes = await fetch(`${baseUrl}/default-fs`);
        assertEquals(defaultFsRes.status, 200);
        assertEquals(await defaultFsRes.text(), "");

        const statusFallbackRes = await fetch(`${baseUrl}/status-fallback`);
        assertEquals(statusFallbackRes.status, 410);
        assertEquals(await statusFallbackRes.text(), "");

        const sizePolicyStatusLiteral = await fetch(
          `${baseUrl}/size-policy-status-literal`,
        );
        assertEquals(sizePolicyStatusLiteral.status, 200);

        const largestZeroOnly = await fetch(`${baseUrl}/largest-zero-only`);
        assertEquals(largestZeroOnly.status, 200);
        assertEquals(await largestZeroOnly.text(), "");

        const smallestZeroSentinel = await fetch(
          `${baseUrl}/smallest-zero-sentinel`,
        );
        assertEquals(smallestZeroSentinel.status, 226);
        assertEquals(await smallestZeroSentinel.text(), "/one-byte.txt");

        const newestDirectory = await fetch(`${baseUrl}/newest-directory`);
        assertEquals(newestDirectory.status, 227);
        assertEquals(await newestDirectory.text(), "/app|directory");

        const emptyTryFilesRes = await fetch(`${baseUrl}/empty-try-files`);
        assertEquals(emptyTryFilesRes.status, 200);

        const rootRelativeRes = await fetch(`${baseUrl}/root-relative.txt`);
        assertEquals(rootRelativeRes.status, 200);
        assertEquals(await rootRelativeRes.text(), "root-relative.txt|file|");

        const phpRes = await fetch(`${baseUrl}/app.php/rest`);
        assertEquals(phpRes.status, 200);
        assertEquals(await phpRes.text(), "/app.php|file|/rest");

        const literalSplitRes = await rawHttpGet(
          baseUrl,
          "/literal{http.vars.ext}/tail",
          "127.0.0.1",
        );
        assertEquals(literalSplitRes.status, 200);
        assertEquals(
          literalSplitRes.body,
          "/literal{http.vars.ext}|file|/tail",
        );

        const literalGlobRes = await rawHttpGet(
          baseUrl,
          "/literal[abc].txt",
          "127.0.0.1",
        );
        assertEquals(literalGlobRes.status, 200);
        assertEquals(literalGlobRes.body, "/literal[abc].txt|file|");

        const missRes = await fetch(`${baseUrl}/missing`);
        assertEquals(missRes.status, 200);
      });
      await withZeroserve(tarPath, async (baseUrl) => {
        const absoluteRootGlobRes = await fetch(
          `${baseUrl}/absolute-root-glob`,
        );
        assertEquals(absoluteRootGlobRes.status, 222);
        assertEquals(
          await absoluteRootGlobRes.text(),
          `${join(fsRoot, "tenant-a", "index.html").replaceAll("\\", "/")}|${
            join(fsRoot, "tenant-a", "index.html").replaceAll("\\", "/")
          }|file`,
        );

        const slashRootFsRes = await fetch(`${baseUrl}/slash-root-fs`);
        assertEquals(slashRootFsRes.status, 228);
        assertEquals(
          await slashRootFsRes.text(),
          `${
            join(fsRoot, "tenant-a", "index.html").replaceAll("\\", "/")
              .replace(/^\//, "")
          }|${
            join(fsRoot, "tenant-a", "index.html").replaceAll("\\", "/")
          }|file`,
        );

        const defaultFsRes = await fetch(`${baseUrl}/default-fs`);
        assertEquals(defaultFsRes.status, 229);
        assertEquals(
          await defaultFsRes.text(),
          `/tenant-a/index.html|${
            join(fsRoot, "tenant-a", "index.html").replaceAll("\\", "/")
          }|file`,
        );
      }, ["--expose-filesystem"]);
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      await Deno.remove(fsRoot, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy file matcher status fallback enters error routes",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{
                    path: ["/status-fallback-error-route"],
                    file: {
                      try_files: ["/definitely-missing.txt", "=410"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    status_code: 204,
                    body: "should not run",
                  }],
                  terminal: true,
                }],
                errors: {
                  routes: [{
                    handle: [{
                      handler: "static_response",
                      body:
                        "handled {http.error.status_code} {http.error.status_text}",
                    }],
                    terminal: true,
                  }],
                },
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/status-fallback-error-route`);
        assertEquals(res.status, 410);
        assertEquals(await res.text(), "handled 410 Gone");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy rewrite URI expands file matcher placeholder",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.mkdir(join(siteDir, "public", "app"), { recursive: true });
      await Deno.writeTextFile(
        join(siteDir, "public", "app", "index.html"),
        "rewritten",
      );
      await Deno.writeTextFile(join(siteDir, "public", "%.html"), "percent");
      await Deno.writeTextFile(join(siteDir, "public", "?.html"), "question");
      await Deno.writeTextFile(
        join(siteDir, "public", "nested%2Ffile.html"),
        "encoded slash",
      );
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  match: [{
                    path: ["/match-percent"],
                    file: {
                      root: "public",
                      try_files: ["/%.html"],
                    },
                  }],
                  handle: [{
                    handler: "static_response",
                    body: "{http.matchers.file.relative}",
                  }],
                  terminal: true,
                }, {
                  match: [{
                    file: {
                      root: "public",
                      try_files: [
                        "{http.request.uri.path}",
                        "{http.request.uri.path}/index.html",
                      ],
                    },
                  }],
                  handle: [{
                    handler: "rewrite",
                    uri: "{http.matchers.file.relative}",
                  }, {
                    handler: "file_server",
                    root: "public",
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/app`);
        assertEquals(res.status, 200);
        assertEquals(await res.text(), "rewritten");

        const matchPercent = await fetch(`${baseUrl}/match-percent`);
        assertEquals(matchPercent.status, 200);
        assertEquals(await matchPercent.text(), "/%.html");

        const percent = await fetch(`${baseUrl}/%25.html`);
        assertEquals(percent.status, 200);
        assertEquals(await percent.text(), "percent");

        const question = await fetch(`${baseUrl}/%3F.html`);
        assertEquals(question.status, 200);
        assertEquals(await question.text(), "question");

        const encodedSlash = await fetch(`${baseUrl}/nested%252Ffile.html`);
        assertEquals(encodedSlash.status, 200);
        assertEquals(await encodedSlash.text(), "encoded slash");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name:
    "Caddy reverse_proxy response-only handle_response routes are rejected",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "reverse_proxy",
                    upstreams: [{ dial: "127.0.0.1:65535" }],
                    handle_response: [{
                      match: { status_code: [200] },
                      routes: [{
                        handle: [{
                          handler: "headers",
                          response: { set: { "X-Handled": ["yes"] } },
                        }, {
                          handler: "copy_response_headers",
                          include: ["X-Copy-Me"],
                        }],
                        terminal: true,
                      }],
                    }],
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      // Caddy response-only handle_response routes suppress the upstream body.
      // zeroserve does not implement response body suppression, so compilation
      // must fail instead of passing through the upstream body.
      assertEquals(compiled.success, false);
      assertEquals(
        new TextDecoder().decode(compiled.stderr).includes(
          "reverse_proxy.handle_response routes suppress upstream response bodies",
        ),
        true,
      );
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
  },
});

Deno.test({
  name: "compiled Caddy forward_auth continues with copied request headers",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backends = await startForwardAuthBackends();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      const caddyfile = `:80 {
  forward_auth ${backends.authDial} {
    uri /auth
    copy_headers Remote-User
  }
  reverse_proxy ${backends.appDial} {
    transport http {
      compression off
    }
  }
}`;
      const caddyConfigPath = join(siteDir, "Caddyfile");
      await Deno.writeTextFile(caddyConfigPath, caddyfile);

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/app`, {
          headers: { "Remote-User": "mallory" },
        });
        assertEquals(res.status, 200);
        const body = await res.json();
        assertEquals(body.path, "/app");
        assertEquals(body.remoteUser, "alice");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
      await backends.close();
    }
  },
});

Deno.test({
  name: "compiled Caddy forward_auth renames copied response headers",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backends = await startForwardAuthBackends();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      const caddyfile = `:80 {
  forward_auth ${backends.authDial} {
    uri /auth
    copy_headers {
      Remote-User>X-Auth-User
    }
  }
  reverse_proxy ${backends.appDial}
}`;
      const caddyConfigPath = join(siteDir, "Caddyfile");
      await Deno.writeTextFile(caddyConfigPath, caddyfile);

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/app`, {
          headers: { "X-Auth-User": "mallory" },
        });
        assertEquals(res.status, 200);
        const body = await res.json();
        assertEquals(body.path, "/app");
        assertEquals(body.remoteUser, null);
        assertEquals(body.xAuthUser, "alice");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
      await backends.close();
    }
  },
});

Deno.test({
  name: "compiled Caddy forward_auth preserves original request body",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backends = await startForwardAuthBackends();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      const caddyfile = `:80 {
  forward_auth ${backends.authDial} {
    uri /auth
    copy_headers Remote-User
  }
  reverse_proxy ${backends.appDial}
}`;
      const caddyConfigPath = join(siteDir, "Caddyfile");
      await Deno.writeTextFile(caddyConfigPath, caddyfile);

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/submit`, {
          method: "POST",
          body: "payload",
          headers: {
            "Content-Type": "text/plain",
            "Remote-User": "mallory",
          },
        });
        assertEquals(res.status, 200);
        const body = await res.json();
        assertEquals(body.method, "POST");
        assertEquals(body.path, "/submit");
        assertEquals(body.remoteUser, "alice");
        assertEquals(body.body, "payload");

        assertEquals(backends.authRequests(), [
          { method: "GET", path: "/auth", body: "" },
        ]);
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
      await backends.close();
    }
  },
});

Deno.test({
  name: "compiled Caddy forward_auth continues over h2c",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backends = await startForwardAuthBackends();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      const caddyfile = `:80 {
  forward_auth ${backends.authDial} {
    uri /auth
    copy_headers Remote-User
  }
  reverse_proxy ${backends.appDial}
}`;
      const caddyConfigPath = join(siteDir, "Caddyfile");
      await Deno.writeTextFile(caddyConfigPath, caddyfile);

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const url = new URL(baseUrl);
        const res = await h2cPost(
          url.hostname,
          Number(url.port),
          "/submit",
          "payload",
          {
            "accept-encoding": "identity",
            "content-type": "text/plain",
            "remote-user": "mallory",
          },
        );
        assertEquals(res.status, 200);
        const body = JSON.parse(res.body);
        assertEquals(body.method, "POST");
        assertEquals(body.path, "/submit");
        assertEquals(body.remoteUser, "alice");
        assertEquals(body.body, "payload");

        assertEquals(backends.authRequests(), [
          { method: "GET", path: "/auth", body: "" },
        ]);
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
      await backends.close();
    }
  },
});

Deno.test({
  name: "compiled Caddy forward_auth continues over h2 TLS",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backends = await startForwardAuthBackends();
    const siteDir = await Deno.makeTempDir();
    const cert = await generateSelfSignedCert();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");
      const caddyfile = `:80 {
  forward_auth ${backends.authDial} {
    uri /auth
    copy_headers Remote-User
  }
  reverse_proxy ${backends.appDial}
}`;
      const caddyConfigPath = join(siteDir, "Caddyfile");
      await Deno.writeTextFile(caddyConfigPath, caddyfile);

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserveTls(
        tarPath,
        cert.certPath,
        cert.keyPath,
        async (_httpUrl, httpsUrl) => {
          const res = await h2PostTls(
            httpsUrl,
            "/submit",
            "payload",
            cert.certPath,
            { "Remote-User": "mallory" },
          );
          assertEquals(res.status, 200);
          const body = JSON.parse(res.body);
          assertEquals(body.method, "POST");
          assertEquals(body.path, "/submit");
          assertEquals(body.remoteUser, "alice");
          assertEquals(body.body, "payload");

          assertEquals(backends.authRequests(), [
            { method: "GET", path: "/auth", body: "" },
          ]);
        },
      );
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
      await cert.cleanup();
      await backends.close();
    }
  },
});

Deno.test({
  name:
    "compiled Caddy reverse_proxy response header matchers keep placeholders literal",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startRawTeapotBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "vars",
                    expected: "ready",
                  }, {
                    handler: "reverse_proxy",
                    upstreams: [{ dial: backend.dial }],
                    handle_response: [{
                      match: {
                        headers: {
                          "X-Placeholder-Match": ["{http.vars.expected}"],
                        },
                      },
                      status_code: 299,
                    }, {
                      match: {
                        headers: {
                          "X-Placeholder-Match": ["ready"],
                        },
                      },
                      status_code: 298,
                    }],
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await rawHttpGet(baseUrl, "/teapot", "localhost");
        assertEquals(res.status, 298);
        assertEquals(res.body, "upstream body");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
      await backend.close();
    }
  },
});

Deno.test({
  name:
    "Caddy reverse_proxy handle_response routes that rewrite bodies are rejected",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "reverse_proxy",
                    upstreams: [{ dial: backend.dial }],
                    handle_response: [{
                      match: { status_code: [418] },
                      routes: [{
                        match: [{ path: ["/not-teapot"] }],
                        handle: [{
                          handler: "static_response",
                          status_code: 208,
                          body: "wrong route",
                        }],
                        terminal: true,
                      }, {
                        match: [{ path: ["/teapot"] }],
                        handle: [{
                          handler: "copy_response_headers",
                          include: ["X-Copy-Me"],
                        }, {
                          handler: "headers",
                          response: {
                            deferred: true,
                            set: {
                              "X-Handled": ["yes"],
                            },
                          },
                        }, {
                          handler: "static_response",
                          headers: {
                            "Content-Type": ["text/custom"],
                          },
                          status_code: 209,
                          body: '{"handled":{http.reverse_proxy.status_code}}',
                        }],
                        terminal: true,
                      }],
                    }],
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      assertEquals(compiled.success, false);
      assertEquals(
        new TextDecoder().decode(compiled.stderr).includes(
          "reverse_proxy.handle_response routes replace response bodies",
        ),
        true,
      );
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      await backend.close();
    }
  },
});

Deno.test({
  name: "compiled Caddy reverse_proxy empty handle_response continues request",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startRawTeapotBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "reverse_proxy",
                    upstreams: [{ dial: backend.dial }],
                    handle_response: [{
                      match: { status_code: [418] },
                    }],
                  }, {
                    handler: "static_response",
                    status_code: 209,
                    body: "continued",
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await rawHttpGet(baseUrl, "/teapot", "localhost");
        assertEquals(res.status, 209);
        assertEquals(res.body, "continued");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
      await backend.close();
    }
  },
});

Deno.test({
  name:
    "compiled Caddy reverse_proxy handle_response status takes priority over routes",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [
                  {
                    match: [{ path: ["/no-content-proxy"] }],
                    handle: [{
                      handler: "reverse_proxy",
                      upstreams: [{ dial: backend.dial }],
                      rewrite: {
                        uri: "/teapot",
                      },
                      handle_response: [{
                        match: { status_code: [418] },
                        status_code: 204,
                      }],
                    }],
                    terminal: true,
                  },
                  {
                    handle: [{
                      handler: "reverse_proxy",
                      upstreams: [{ dial: backend.dial }],
                      handle_response: [{
                        match: { status_code: [418] },
                        status_code: 777,
                        routes: [{
                          handle: [{
                            handler: "static_response",
                            status_code: 208,
                            body: "wrong route",
                          }],
                        }],
                      }],
                    }],
                    terminal: true,
                  },
                ],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await rawHttpGet(baseUrl, "/teapot", "localhost");
        assertEquals(res.status, 777);
        assertEquals(res.headers["x-copy-me"], "copied");
        assertEquals(res.body, "upstream body");

        const noContent = await rawHttpGet(
          baseUrl,
          "/no-content-proxy",
          "localhost",
        );
        assertEquals(noContent.status, 204);
        assertEquals(noContent.headers["content-length"], undefined);
        assertEquals(noContent.body, "");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
      await backend.close();
    }
  },
});

Deno.test({
  name:
    "compiled Caddy reverse_proxy handle_response status zero preserves upstream status",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "reverse_proxy",
                    upstreams: [{ dial: backend.dial }],
                    handle_response: [{
                      match: { status_code: [418] },
                      status_code: 0,
                    }, {
                      match: { status_code: [418] },
                      status_code: 299,
                    }],
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/teapot`);
        assertEquals(res.status, 418);
        assertEquals(await res.text(), "upstream body");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
      await backend.close();
    }
  },
});

Deno.test({
  name:
    "compiled Caddy reverse_proxy handle_response invalid placeholder status returns 500",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "fallback");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "vars",
                    proxy_status: "not-a-status",
                  }, {
                    handler: "reverse_proxy",
                    upstreams: [{ dial: backend.dial }],
                    handle_response: [{
                      match: { status_code: [418] },
                      status_code: "{http.vars.proxy_status}",
                    }],
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/teapot`);
        assertEquals(res.status, 500);
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
      await backend.close();
    }
  },
});

Deno.test({
  name: "compiled Caddy file_server filesystem is gated by expose-filesystem",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    const fsRoot = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "tar fallback");
      await Deno.writeTextFile(join(fsRoot, "disk.txt"), "from filesystem");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "file_server",
                    fs: "file",
                    root: fsRoot,
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/disk.txt`);
        assertEquals(res.status, 404);
      });

      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/disk.txt`);
        assertEquals(res.status, 200);
        assertEquals(await res.text(), "from filesystem");
      }, ["--expose-filesystem"]);
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      await Deno.remove(fsRoot, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name:
    "compiled Caddy basic_auth protects routes and exposes user placeholder",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "unused");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "authentication",
                    providers: {
                      http_basic: {
                        hash: { algorithm: "bcrypt" },
                        realm: "Admin Area",
                        accounts: [{
                          username: "alice",
                          password:
                            "$2a$14$gqs5yvNgSqb/ksrUoam91ewSE1TjpYIgCuaiuZH395DQEPsiCVIei",
                        }, {
                          username: "bob",
                          password: btoa(
                            "$2a$14$gqs5yvNgSqb/ksrUoam91ewSE1TjpYIgCuaiuZH395DQEPsiCVIei",
                          ),
                        }],
                      },
                    },
                  }, {
                    handler: "static_response",
                    body: "hello {http.auth.user.id}",
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const missing = await fetch(`${baseUrl}/`);
        assertEquals(missing.status, 401);
        assertEquals(
          missing.headers.get("www-authenticate"),
          'Basic realm="Admin Area"',
        );

        const wrong = await fetch(`${baseUrl}/`, {
          headers: {
            Authorization: `Basic ${btoa("alice:wrong")}`,
          },
        });
        assertEquals(wrong.status, 401);

        const ok = await fetch(`${baseUrl}/`, {
          headers: {
            Authorization: `Basic ${btoa("alice:secret")}`,
          },
        });
        assertEquals(ok.status, 200);
        assertEquals(await ok.text(), "hello alice");

        const base64Hash = await fetch(`${baseUrl}/`, {
          headers: {
            Authorization: `Basic ${btoa("bob:secret")}`,
          },
        });
        assertEquals(base64Hash.status, 200);
        assertEquals(await base64Hash.text(), "hello bob");

        const validFirst = await rawHttpGetWithHeaderLines(
          baseUrl,
          "/",
          "localhost",
          [
            `Authorization: Basic ${btoa("alice:secret")}`,
            `Authorization: Basic ${btoa("alice:wrong")}`,
          ],
        );
        assertEquals(validFirst.status, 200);
        assertEquals(validFirst.body, "hello alice");

        const validSecond = await rawHttpGetWithHeaderLines(
          baseUrl,
          "/",
          "localhost",
          [
            `Authorization: Basic ${btoa("alice:wrong")}`,
            `Authorization: Basic ${btoa("alice:secret")}`,
          ],
        );
        assertEquals(validSecond.status, 401);
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name:
    "compiled Caddy basic_auth argon2id protects routes and exposes user placeholder",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "unused");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                routes: [{
                  handle: [{
                    handler: "authentication",
                    providers: {
                      http_basic: {
                        hash: { algorithm: "argon2id" },
                        realm: "Argon Area",
                        accounts: [{
                          username: "alice",
                          password:
                            "$argon2id$v=19$m=47104,t=1,p=1$P2nzckEdTZ3bxCiBCkRTyA$xQL3Z32eo5jKl7u5tcIsnEKObYiyNZQQf5/4sAau6Pg",
                        }],
                      },
                    },
                  }, {
                    handler: "static_response",
                    body: "argon {http.auth.user.id}",
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const missing = await fetch(`${baseUrl}/`);
        assertEquals(missing.status, 401);
        assertEquals(
          missing.headers.get("www-authenticate"),
          'Basic realm="Argon Area"',
        );

        const wrong = await fetch(`${baseUrl}/`, {
          headers: {
            Authorization: `Basic ${btoa("alice:wrong")}`,
          },
        });
        assertEquals(wrong.status, 401);

        const ok = await fetch(`${baseUrl}/`, {
          headers: {
            Authorization: `Basic ${btoa("alice:antitiming")}`,
          },
        });
        assertEquals(ok.status, 200);
        assertEquals(await ok.text(), "argon alice");
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test({
  name: "compiled Caddy basic_auth exposes provider errors to error routes",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    let tarPath: string | null = null;
    try {
      await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
        recursive: true,
      });
      await Deno.writeTextFile(join(siteDir, "index.html"), "unused");

      const caddyConfig = {
        apps: {
          http: {
            servers: {
              srv0: {
                errors: {
                  routes: [{
                    handle: [{
                      handler: "static_response",
                      status_code: "{http.error.status_code}",
                      body: "{http.auth.http_basic.error}",
                    }],
                    terminal: true,
                  }],
                },
                routes: [{
                  handle: [{
                    handler: "authentication",
                    providers: {
                      http_basic: {
                        accounts: [{
                          username: "alice",
                          password: "$not-a-valid-bcrypt-hash",
                        }],
                      },
                    },
                  }, {
                    handler: "static_response",
                    body: "unreachable",
                  }],
                  terminal: true,
                }],
              },
            },
          },
        },
      };
      const caddyConfigPath = join(siteDir, "caddy.json");
      await Deno.writeTextFile(caddyConfigPath, JSON.stringify(caddyConfig));

      const zeroservePath = await getZeroservePath();
      const compiled = await new Deno.Command(zeroservePath, {
        args: ["--caddy-compile", caddyConfigPath],
        cwd: repoRoot,
        stdout: "piped",
        stderr: "piped",
      }).output();
      if (!compiled.success) {
        throw new Error(new TextDecoder().decode(compiled.stderr));
      }
      await Deno.writeFile(
        join(siteDir, ".zeroserve", "scripts", "caddy.c"),
        compiled.stdout,
      );

      tarPath = await packSite(siteDir);
      await withZeroserve(tarPath, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/`, {
          headers: {
            Authorization: `Basic ${btoa("alice:secret")}`,
          },
        });
        assertEquals(res.status, 401);
        assertEquals(
          res.headers.get("www-authenticate"),
          'Basic realm="restricted"',
        );
        const body = await res.text();
        assert(body.length > 0);
        assert(!body.includes("http.auth.http_basic.error"));
      });
    } finally {
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      if (tarPath) {
        await Deno.remove(tarPath).catch(() => {});
      }
    }
  },
});

Deno.test("caddy-compile adapts Caddyfile file logging", async () => {
  const logPath = "/tmp/zeroserve-caddy-access-compile.log";
  const c = await compileCaddyfileForLogging(`
:8080 {
  log access {
    output file ${logPath}
  }
  respond "ok" 201
}
`);
  assert(c.includes("zs.caddy.access_log.file"));
  assert(c.includes(logPath));
});

Deno.test({
  name: "compiled Caddy file logging writes only with expose filesystem",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const logPath = await Deno.makeTempFile();
    await Deno.remove(logPath);
    try {
      await withCompiledLoggingSite(
        logPath,
        ["--expose-filesystem"],
        async (baseUrl) => {
          const res = await fetch(`${baseUrl}/logged`);
          assertEquals(res.status, 201);
          await res.body?.cancel();
          const log = await waitForLog(logPath);
          assert(log.includes('"status":201'), log);
          assert(log.includes('"method":"GET"'), log);
          assert(log.includes('"uri":"/logged"'), log);
        },
      );

      await Deno.remove(logPath).catch(() => {});
      await withCompiledLoggingSite(logPath, [], async (baseUrl) => {
        const res = await fetch(`${baseUrl}/not-exposed`);
        assertEquals(res.status, 201);
        await res.body?.cancel();
        await new Promise((resolve) => setTimeout(resolve, 250));
        let exists = true;
        try {
          await Deno.stat(logPath);
        } catch {
          exists = false;
        }
        assertEquals(exists, false);
      });
    } finally {
      await Deno.remove(logPath).catch(() => {});
    }
  },
});

Deno.test({
  name: "compiled Caddy file logging covers static and proxy responses",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const backend = await startBackend();
    const logPath = await Deno.makeTempFile();
    await Deno.remove(logPath);
    try {
      await withCompiledLoggingJson(
        {
          logging: {
            logs: {
              default: {
                writer: {
                  output: "file",
                  filename: logPath,
                },
              },
            },
          },
          apps: {
            http: {
              servers: {
                srv: {
                  routes: [{
                    match: [{ path: ["/proxy*"] }],
                    handle: [{
                      handler: "reverse_proxy",
                      upstreams: [{ dial: backend.dial }],
                    }],
                  }],
                },
              },
            },
          },
        },
        logPath,
        { "asset.txt": "static body" },
        ["--expose-filesystem"],
        async (baseUrl) => {
          let res = await fetch(`${baseUrl}/asset.txt`);
          assertEquals(res.status, 200);
          await res.body?.cancel();

          res = await fetch(`${baseUrl}/proxy`);
          assertEquals(res.status, 200);
          await res.body?.cancel();

          const log = await waitForLogEntries(logPath, 2);
          assert(log.includes('"status":200'), log);
          assert(log.includes('"uri":"/asset.txt"'), log);
          assert(log.includes('"status":200'), log);
          assert(log.includes('"uri":"/proxy"'), log);
        },
      );
    } finally {
      await backend.close();
      await Deno.remove(logPath).catch(() => {});
    }
  },
});

Deno.test({
  name: "runtime Caddy file logging covers fallback responses",
  ignore: !canRunScripts,
  sanitizeResources: false,
  sanitizeOps: false,
  async fn() {
    const logPath = await Deno.makeTempFile();
    await Deno.remove(logPath);
    try {
      await withManualLoggingScript(
        logPath,
        ["--expose-filesystem"],
        async (baseUrl) => {
          let res = await fetch(`${baseUrl}/missing`);
          assertEquals(res.status, 404);
          await res.body?.cancel();

          res = await fetch(`${baseUrl}/missing`, { method: "POST" });
          assertEquals(res.status, 405);
          await res.body?.cancel();

          const log = await waitForLogEntries(logPath, 2);
          assert(log.includes('"status":404'), log);
          assert(log.includes('"uri":"/missing"'), log);
          assert(log.includes('"status":405'), log);
        },
      );
    } finally {
      await Deno.remove(logPath).catch(() => {});
    }
  },
});

async function compileCaddyfileForLogging(caddyfile: string): Promise<string> {
  const siteDir = await Deno.makeTempDir();
  try {
    const caddyfilePath = join(siteDir, "Caddyfile");
    await Deno.writeTextFile(caddyfilePath, caddyfile);
    const zeroservePath = await getZeroservePath();
    const compiled = await new Deno.Command(zeroservePath, {
      args: ["--caddy-compile", caddyfilePath],
      cwd: repoRoot,
      stdout: "piped",
      stderr: "piped",
    }).output();
    if (!compiled.success) {
      throw new Error(new TextDecoder().decode(compiled.stderr));
    }
    return new TextDecoder().decode(compiled.stdout);
  } finally {
    await Deno.remove(siteDir, { recursive: true }).catch(() => {});
  }
}

async function withCompiledLoggingSite(
  logPath: string,
  extraArgs: string[],
  fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
  await withCompiledLoggingCaddyfile(
    `
:8080 {
  log access {
    output file ${logPath}
  }
  respond "ok" 201
}
`,
    logPath,
    {},
    extraArgs,
    fn,
  );
}

async function withCompiledLoggingCaddyfile(
  caddyfile: string,
  logPath: string,
  files: Record<string, string>,
  extraArgs: string[],
  fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const siteDir = await Deno.makeTempDir();
  let tarPath: string | null = null;
  try {
    await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
      recursive: true,
    });
    const c = await compileCaddyfileForLogging(caddyfile);
    await Deno.writeTextFile(
      join(siteDir, ".zeroserve", "scripts", "caddy.c"),
      c,
    );
    for (const [name, contents] of Object.entries(files)) {
      await Deno.writeTextFile(join(siteDir, name), contents);
    }
    tarPath = await packSite(siteDir);
    await withZeroserve(tarPath, fn, extraArgs);
  } finally {
    await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    if (tarPath !== null) {
      await Deno.remove(tarPath).catch(() => {});
    }
  }
}

async function withCompiledLoggingJson(
  caddyJson: unknown,
  logPath: string,
  files: Record<string, string>,
  extraArgs: string[],
  fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const siteDir = await Deno.makeTempDir();
  let tarPath: string | null = null;
  try {
    await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
      recursive: true,
    });
    const caddyJsonPath = join(siteDir, "caddy.json");
    await Deno.writeTextFile(caddyJsonPath, JSON.stringify(caddyJson));
    const zeroservePath = await getZeroservePath();
    const compiled = await new Deno.Command(zeroservePath, {
      args: ["--caddy-compile", caddyJsonPath],
      cwd: repoRoot,
      stdout: "piped",
      stderr: "piped",
    }).output();
    if (!compiled.success) {
      throw new Error(new TextDecoder().decode(compiled.stderr));
    }
    await Deno.writeFile(
      join(siteDir, ".zeroserve", "scripts", "caddy.c"),
      compiled.stdout,
    );
    for (const [name, contents] of Object.entries(files)) {
      await Deno.writeTextFile(join(siteDir, name), contents);
    }
    tarPath = await packSite(siteDir);
    await withZeroserve(tarPath, fn, extraArgs);
  } finally {
    await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    if (tarPath !== null) {
      await Deno.remove(tarPath).catch(() => {});
    }
    await Deno.remove(logPath).catch(() => {});
  }
}

async function withManualLoggingScript(
  logPath: string,
  extraArgs: string[],
  fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const siteDir = await Deno.makeTempDir();
  let tarPath: string | null = null;
  try {
    await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
      recursive: true,
    });
    await Deno.writeTextFile(
      join(siteDir, ".zeroserve", "scripts", "log.c"),
      `#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  zs_meta_set(ZS_STR("zs.caddy.access_log.name"), ZS_STR("default"));
  zs_meta_set(ZS_STR("zs.caddy.access_log.file"), ZS_STR("${logPath}"));
  return 0;
}
`,
    );
    tarPath = await packSite(siteDir);
    await withZeroserve(tarPath, fn, extraArgs);
  } finally {
    await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    if (tarPath !== null) {
      await Deno.remove(tarPath).catch(() => {});
    }
  }
}

async function waitForLog(path: string): Promise<string> {
  return await waitForLogEntries(path, 1);
}

async function waitForLogEntries(path: string, count: number): Promise<string> {
  const deadline = Date.now() + 10000;
  let last = "";
  while (Date.now() < deadline) {
    try {
      last = await Deno.readTextFile(path);
      const lines = last.trim().split("\n").filter((line) => line.length > 0);
      if (lines.length >= count) {
        return last;
      }
    } catch {
      // File logging is asynchronous; retry until the dedicated logger writes.
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return last;
}
