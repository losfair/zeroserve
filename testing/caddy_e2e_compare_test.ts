import { assertEquals } from "@std/assert";
import { dirname, join } from "@std/path";
import {
  generateSelfSignedCert,
  getFreePort,
  getZeroservePath,
  hasBpfToolchain,
  packSite,
  repoRoot,
  spawnZeroserve,
  stopProcess,
  waitForServer,
  withZeroserve,
} from "./test_utils.ts";

const decoder = new TextDecoder();
const canRunScripts = await hasBpfToolchain();
// The Caddy binary to compare against. Override with CADDY_BIN to pin a
// specific build (CI pins a known-good commit; see .github/workflows/ci.yml).
const caddyBin = Deno.env.get("CADDY_BIN") ?? "caddy";
const canRunCaddy = await hasCommand(caddyBin);
const caddyTlsRef = Deno.env.get("CADDY_BIN") ?? "/home/user/caddy";
const canRunCaddyTls = await hasCaddyRunner(caddyTlsRef);

type Probe = {
  path: string;
  method?: string;
  headers?: Record<string, string>;
  body?: BodyInit;
  redirect?: RequestRedirect;
  rawHost?: string;
  compareHeaders?: string[];
  compareBody?: boolean;
  expectedStatus?: number;
  expectedBody?: string;
  expectedHeaders?: Record<string, string | null>;
  normalizeBrowseJson?: boolean;
  // Compare only the number of browse entries, not which ones. `file_limit`
  // truncates "in directory order" (per Caddy), and Caddy reads from disk while
  // zeroserve reads from the packed tarball, so the two backends legitimately
  // pick different subsets; only the count is deterministic across them.
  normalizeBrowseCount?: boolean;
};

type ObservedResponse = {
  status: number;
  body: string;
  headers: Record<string, string | null>;
};

type GeneratedCase = {
  name: string;
  files: Record<string, string | Uint8Array>;
  prelude?: string;
  site?: string | ((ctx: { upstreamPort: number }) => string);
  fullCaddyfile?:
    | string
    | ((ctx: { caddyPort: number; upstreamPort: number }) => string);
  probes:
    | Probe[]
    | ((ctx: { caddyPort: number; upstreamPort: number }) => Probe[]);
  upstream?: boolean;
  expectedCompileWarnings?: string[];
};

Deno.test({
  name: "e2e: generated Caddyfiles match stock Caddy for supported behavior",
  ignore: !canRunScripts || !canRunCaddy,
  async fn() {
    await compareGeneratedCaddyfile({
      name: "static responses and response headers",
      files: {},
      site: `
  header /ok X-Route ok
  respond /ok "ok" 201
  respond "fallback" 404
`,
      probes: [
        {
          path: "/ok",
          compareHeaders: ["x-route"],
          expectedStatus: 201,
          expectedBody: "ok",
          expectedHeaders: {
            "x-route": "ok",
          },
        },
        {
          path: "/missing",
          expectedStatus: 404,
          expectedBody: "fallback",
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "Caddy push handler ignored fixture",
      files: {},
      site: `
  push {
    GET /app.js
    HEAD /style.css
    /image.png
    headers {
      X-Push yes
      +X-Trace trace
      -X-Drop
    }
  }
  respond "ok" 200
`,
      probes: [
        {
          path: "/",
          expectedStatus: 200,
          expectedBody: "ok",
        },
      ],
      expectedCompileWarnings: [
        "ignoring push handler",
      ],
    });

    await compareGeneratedCaddyfile({
      name: "Caddy observability handlers ignored fixture",
      files: {},
      site: `
  log_append /admin* <route admin
  tracing {
    span request-{http.request.method}
    span_attributes {
      route {http.request.uri.path}
      tenant example
    }
  }
  respond "observed" 202
`,
      probes: [
        {
          path: "/admin/panel",
          expectedStatus: 202,
          expectedBody: "observed",
        },
        {
          path: "/public",
          expectedStatus: 202,
          expectedBody: "observed",
        },
      ],
      expectedCompileWarnings: [
        "ignoring log_append handler",
        "ignoring tracing handler",
      ],
    });

    // Adapted from caddyserver/caddy issue #4924 (60k+ stars). Localizes the
    // server address while preserving the supported behavior: a `not header`
    // matcher conditionally sets a request header from `{remote_host}`, then a
    // response observes the mutated request header.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: caddyserver/caddy conditional request header",
      files: {},
      site: `
  @no_forwarded_for not header X-Forwarded-For *
  request_header @no_forwarded_for X-Forwarded-For {remote_host}

  respond {header.X-Forwarded-For} 200
`,
      probes: [
        {
          path: "/",
          expectedStatus: 200,
          expectedBody: "127.0.0.1",
        },
        {
          path: "/",
          headers: {
            "X-Forwarded-For": "203.0.113.9",
          },
          expectedStatus: 200,
          expectedBody: "203.0.113.9",
        },
      ],
    });

    // Adapted from caddyserver/caddy issue #3890 (60k+ stars). Localizes the
    // root and upstream while preserving the supported static-miss routing
    // pattern: `@notStatic { not file }` proxies requests only when no packed
    // static file matches, otherwise `file_server` serves the file.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: caddyserver/caddy static miss proxy",
      files: {
        "static/index.css": "body { color: green; }\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  root * static

  @notStatic {
    not file
  }

  reverse_proxy @notStatic 127.0.0.1:${upstreamPort}
  file_server
`,
      probes: [
        {
          path: "/index.css",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "body { color: green; }\n",
          expectedHeaders: {
            "x-backend-token": null,
          },
        },
        {
          path: "/dashboard",
          rawHost: "localhost",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/dashboard:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
      ],
    });

    // Adapted from caddyserver/website reverse_proxy docs (official Caddy docs
    // repo). Keeps `compression off` accepted and verifies client-provided
    // Accept-Encoding still reaches the upstream.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: caddyserver/website proxy compression off",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  reverse_proxy 127.0.0.1:${upstreamPort} {
    transport http {
      compression off
    }
  }
`,
      probes: [
        {
          path: "/dashboard",
          rawHost: "localhost",
          compareHeaders: ["x-backend-token", "x-seen-accept-encoding"],
          expectedStatus: 200,
          expectedBody: "/dashboard:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-accept-encoding": "",
          },
        },
        {
          path: "/explicit",
          rawHost: "localhost",
          headers: { "Accept-Encoding": "br" },
          compareHeaders: ["x-backend-token", "x-seen-accept-encoding"],
          expectedStatus: 200,
          expectedBody: "/explicit:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-accept-encoding": "br",
          },
        },
      ],
    });

    // Adapted from caddyserver/caddy issue #4026 (60k+ stars). Localizes the
    // upstream while preserving Caddy's surprising but supported behavior: a
    // site with only a path-scoped reverse_proxy proxies matching paths, while
    // unmatched paths fall through to Caddy's empty 200 response.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: caddyserver/caddy unmatched proxy route",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  reverse_proxy /api/* 127.0.0.1:${upstreamPort}
`,
      probes: [
        {
          path: "/api/users",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/api/users:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/something_else/",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "",
          expectedHeaders: {
            "x-backend-token": null,
          },
        },
      ],
    });

    // Adapted from caddyserver/caddy issue #4457 (60k+ stars). Localizes the
    // upstream while preserving the supported behavior: `header_up -Origin`
    // and `header_up -Referer` remove request headers only for the scoped
    // reverse_proxy; a sibling proxy route still forwards those headers.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: caddyserver/caddy header_up deletes",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  reverse_proxy /stripped/* 127.0.0.1:${upstreamPort} {
    header_up -Origin
    header_up -Referer
  }

  reverse_proxy /forwarded/* 127.0.0.1:${upstreamPort}
`,
      probes: [
        {
          path: "/stripped/resource",
          headers: {
            Origin: "https://app.example",
            Referer: "https://app.example/page",
          },
          compareHeaders: [
            "x-backend-token",
            "x-seen-origin",
            "x-seen-referer",
          ],
          expectedStatus: 200,
          expectedBody: "/stripped/resource:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-origin": "",
            "x-seen-referer": "",
          },
        },
        {
          path: "/forwarded/resource",
          headers: {
            Origin: "https://app.example",
            Referer: "https://app.example/page",
          },
          compareHeaders: [
            "x-backend-token",
            "x-seen-origin",
            "x-seen-referer",
          ],
          expectedStatus: 200,
          expectedBody: "/forwarded/resource:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-origin": "https://app.example",
            "x-seen-referer": "https://app.example/page",
          },
        },
      ],
    });

    // Adapted from caddyserver/caddy issue #4430 (60k+ stars). Localizes the
    // upstream while preserving the supported behavior: `header_down` rewrites
    // an upstream Set-Cookie domain using the original request Host.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: caddyserver/caddy header_down cookie rewrite",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  reverse_proxy 127.0.0.1:${upstreamPort} {
    header_down Set-Cookie "Domain=backend.example" "Domain={host}"
  }
`,
      probes: [
        {
          path: "/cookie",
          rawHost: "app.example",
          compareHeaders: ["set-cookie", "x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/cookie:",
          expectedHeaders: {
            "set-cookie": "sid=abc; Domain=app.example; Path=/",
            "x-backend-token": "backend",
          },
        },
      ],
    });

    // Adapted from caddyserver/caddy issue #6349 (60k+ stars). Localizes the
    // trusted proxy ranges to loopback while preserving the supported behavior:
    // `client_ip` uses configured trusted proxy headers instead of the direct
    // remote address, and falls back when no trusted header is present.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: caddyserver/caddy trusted client_ip matcher",
      files: {},
      fullCaddyfile: ({ caddyPort }) => `
{
  admin off
  auto_https off
  servers {
    trusted_proxies static 127.0.0.1/32
    client_ip_headers X-Forwarded-For X-Real-IP
  }
}

:${caddyPort} {
  @allowed client_ip 203.0.113.0/24
  respond @allowed "allowed" 200
  respond "blocked" 403
}
`,
      probes: [
        {
          path: "/client-ip",
          headers: { "X-Forwarded-For": "203.0.113.9" },
          expectedStatus: 200,
          expectedBody: "allowed",
        },
        {
          path: "/client-ip",
          headers: { "X-Real-IP": "203.0.113.10" },
          expectedStatus: 200,
          expectedBody: "allowed",
        },
        {
          path: "/client-ip",
          expectedStatus: 403,
          expectedBody: "blocked",
        },
      ],
    });

    // Adapted from caddyserver/caddy issue #3675 (60k+ stars). Localizes the
    // file root while preserving the supported behavior: `handle_path` strips
    // the matched prefix before a nested `file_server` resolves files under its
    // configured root.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: caddyserver/caddy handle_path file root",
      files: {
        "static/img/image.png": "png-data",
      },
      site: `
  handle_path /static/* {
    file_server {
      root ./static
    }
  }

  respond "fallback" 404
`,
      probes: [
        {
          path: "/static/img/image.png",
          expectedStatus: 200,
          expectedBody: "png-data",
        },
        {
          path: "/img/image.png",
          expectedStatus: 404,
          expectedBody: "fallback",
        },
      ],
    });

    // Adapted from caddyserver/website Caddyfile (official Caddy website repo,
    // 200+ stars). Localizes the root and upstream while preserving the
    // supported extension fallback, docs rewrite matcher, redirects, encode,
    // file_server, and API reverse_proxy behavior. The source templates block is
    // intentionally outside this fixture because generated response-body
    // templating is an explicit zeroserve exclusion.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: caddyserver/website docs routing",
      files: {
        "src/index.html":
          "<!doctype html><title>Caddy</title><main>home</main>",
        "src/guide.html":
          "<!doctype html><title>Caddy Guide</title><main>guide</main>",
        "src/docs/index.html":
          "<!doctype html><title>Caddy Docs</title><main>docs app</main>",
        "src/docs/reference.md": "# Reference\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  root * src

  file_server
  encode zstd gzip

  try_files {path}.html {path}

  @notDirectDocsMarkdown {
    path /docs/*
    not path *.md
  }
  rewrite @notDirectDocsMarkdown /docs/index.html

  redir /docs/caddyfile/directives/basicauth /docs/caddyfile/directives/basic_auth 308
  redir /docs/caddyfile/directives/skip_log /docs/caddyfile/directives/log_skip 308

  reverse_proxy /api/* 127.0.0.1:${upstreamPort}
`,
      probes: [
        {
          path: "/guide",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Caddy Guide</title><main>guide</main>",
        },
        {
          path: "/docs/getting-started",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Caddy Docs</title><main>docs app</main>",
        },
        {
          path: "/docs/reference.md",
          expectedStatus: 200,
          expectedBody: "# Reference\n",
        },
        {
          path: "/docs/caddyfile/directives/basicauth",
          redirect: "manual",
          compareHeaders: ["location"],
          expectedStatus: 308,
          expectedBody: "",
          expectedHeaders: {
            location: "/docs/caddyfile/directives/basic_auth",
          },
        },
        {
          path: "/api/config",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/api/config:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
      ],
    });

    // Adapted from TryGhost/Ghost docker/dev-gateway/Caddyfile (50k+ stars).
    // Localizes the dev and backend upstreams while preserving the supported
    // behavior: nested asset handles, strip-prefix rewrites, upstream Host
    // header mutation, API proxy headers, a failed optional dev-server proxy,
    // and handle_errors fallback to the backend service. Passive health tuning
    // from the source is intentionally outside this localized fixture because
    // zeroserve does not model upstream health-check state.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: TryGhost/Ghost dev gateway routing",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  handle /ghost/assets/* {
    uri strip_prefix /ghost/assets

    @lexical path /koenig-lexical/*
    handle @lexical {
      uri strip_prefix /koenig-lexical
      reverse_proxy 127.0.0.1:9 {
        header_up Host {http.reverse_proxy.upstream.hostport}
        header_up X-Forwarded-Host {host}
      }
    }

    handle {
      rewrite * /__admin-dev__/assets{path}
      reverse_proxy 127.0.0.1:${upstreamPort} {
        header_up Host {http.reverse_proxy.upstream.hostport}
        header_up X-Forwarded-Host {host}
      }
    }
  }

  handle /ghost/api/* {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up Host {host}
      header_up X-Real-IP {remote_host}
      header_up X-Forwarded-For {remote_host}
      header_up X-Forwarded-Proto https
    }
  }

  handle {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle_errors {
    @lexical_fallback path /ghost/assets/koenig-lexical/*
    handle @lexical_fallback {
      rewrite * {http.request.orig_uri.path}
      reverse_proxy 127.0.0.1:${upstreamPort} {
        header_up Host {host}
        header_up X-Forwarded-Proto https
      }
    }

    respond "{err.status_code} {err.status_text}"
  }
`,
      probes: [
        {
          path: "/ghost/assets/portal/app.js",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/__admin-dev__/assets/portal/app.js:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/ghost/assets/koenig-lexical/app.js",
          compareHeaders: ["x-backend-token", "x-seen-forwarded-proto"],
          expectedStatus: 200,
          expectedBody: "/ghost/assets/koenig-lexical/app.js:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-proto": "https",
          },
        },
        {
          path: "/ghost/api/admin/site",
          compareHeaders: [
            "x-backend-token",
            "x-seen-forwarded-proto",
            "x-seen-real-ip",
          ],
          expectedStatus: 200,
          expectedBody: "/ghost/api/admin/site:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-proto": "https",
            "x-seen-real-ip": "127.0.0.1",
          },
        },
      ],
    });

    // Adapted from element-hq/synapse docs/reverse_proxy.md Caddy v2 example
    // (4k+ stars). Localizes the site and upstream while preserving the
    // supported Matrix delegation headers/respond bodies and path-specific
    // reverse_proxy routes.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: element-hq/synapse Matrix delegation",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  header /.well-known/matrix/* Content-Type application/json
  header /.well-known/matrix/* Access-Control-Allow-Origin *
  respond /.well-known/matrix/server \`{"m.server": "matrix.example.com:443"}\`
  respond /.well-known/matrix/client \`{"m.homeserver":{"base_url":"https://matrix.example.com"},"m.identity_server":{"base_url":"https://identity.example.com"}}\`

  reverse_proxy /_matrix/* 127.0.0.1:${upstreamPort}
  reverse_proxy /_synapse/client/* 127.0.0.1:${upstreamPort}
`,
      probes: [
        {
          path: "/.well-known/matrix/server",
          compareHeaders: ["content-type", "access-control-allow-origin"],
          expectedStatus: 200,
          expectedBody: `{"m.server": "matrix.example.com:443"}`,
          expectedHeaders: {
            "content-type": "application/json",
            "access-control-allow-origin": "*",
          },
        },
        {
          path: "/.well-known/matrix/client",
          compareHeaders: ["content-type", "access-control-allow-origin"],
          expectedStatus: 200,
          expectedBody:
            `{"m.homeserver":{"base_url":"https://matrix.example.com"},"m.identity_server":{"base_url":"https://identity.example.com"}}`,
          expectedHeaders: {
            "content-type": "application/json",
            "access-control-allow-origin": "*",
          },
        },
        {
          path: "/_matrix/client/versions",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/_matrix/client/versions:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/_synapse/client/password_reset",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/_synapse/client/password_reset:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
      ],
    });

    // Adapted from a mastodon/mastodon GitHub discussion Caddy config
    // (50k+ stars). Localizes the site root and upstreams while preserving
    // supported local-file matching, path-regexp cache headers, static serving,
    // streaming route selection, fallback proxy header mutation, and ignored
    // reverse_proxy transport keepalive tuning.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: mastodon/mastodon static and streaming proxy",
      files: {
        "public/packs/app.js": "console.log('mastodon');\n",
        "public/sw.js": "self.addEventListener('install', () => {});\n",
        "public/500.html":
          "<!doctype html><title>Mastodon Error</title><main>error</main>",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  @local {
    file
    not path /
  }
  @streaming {
    path /api/v1/streaming/
  }
  @cache_control {
    path_regexp ^/(emoji|packs|/system/accounts/avatars|/system/media_attachments/files)
  }

  root * public
  encode zstd gzip

  handle_errors {
    rewrite 500.html
    file_server
  }

  header {
    Strict-Transport-Security "max-age=31536000"
  }
  header /sw.js Cache-Control "public, max-age=0"
  header @cache_control Cache-Control "public, max-age=31536000, immutable"

  handle @local {
    file_server
  }

  reverse_proxy @streaming 127.0.0.1:${upstreamPort} {
    transport http {
      keepalive 5s
      keepalive_idle_conns 10
    }
  }

  reverse_proxy 127.0.0.1:${upstreamPort} {
    header_up X-Forwarded-Port 443
    header_up X-Forwarded-Proto https
    transport http {
      keepalive 5s
      keepalive_idle_conns 10
    }
  }
`,
      probes: [
        {
          path: "/packs/app.js",
          compareHeaders: ["cache-control", "strict-transport-security"],
          expectedStatus: 200,
          expectedBody: "console.log('mastodon');\n",
          expectedHeaders: {
            "cache-control": "public, max-age=31536000, immutable",
            "strict-transport-security": "max-age=31536000",
          },
        },
        {
          path: "/sw.js",
          compareHeaders: ["cache-control", "strict-transport-security"],
          expectedStatus: 200,
          expectedBody: "self.addEventListener('install', () => {});\n",
          expectedHeaders: {
            "cache-control": "public, max-age=0",
            "strict-transport-security": "max-age=31536000",
          },
        },
        {
          path: "/api/v1/streaming/",
          compareHeaders: ["x-backend-token", "x-seen-forwarded-proto"],
          expectedStatus: 200,
          expectedBody: "/api/v1/streaming/:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-proto": "http",
          },
        },
        {
          path: "/web/home",
          compareHeaders: ["x-backend-token", "x-seen-forwarded-proto"],
          expectedStatus: 200,
          expectedBody: "/web/home:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-proto": "https",
          },
        },
      ],
    });

    // Adapted from an immich-app/immich issue Caddyfile (100k+ stars).
    // Localizes container upstreams while preserving the supported
    // handle_path API/machine-learning proxy split and fallback web proxy.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: immich-app/immich service proxy split",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  handle_path /api/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle_path /ml/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
`,
      probes: [
        {
          path: "/api/asset/thumbnail",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/asset/thumbnail:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/ml/clip/encode-image",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/clip/encode-image:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/photos/album",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/photos/album:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
      ],
    });

    // Adapted from nextcloud/all-in-one Containers/apache/Caddyfile
    // (9k+ stars). Localizes upstreams and removes TLS/ACME/global runtime
    // configuration while preserving supported route-specific proxying,
    // strip-prefix rewrites, header_up mutation, fallback proxying, and
    // well-known redirects.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: nextcloud/all-in-one routed app proxy",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  header {
    Strict-Transport-Security max-age=31536000;
    -X-Powered-By
    -Via
  }

  route /browser/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  route /push/* {
    uri strip_prefix /push
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  route /eurooffice/* {
    uri strip_prefix /eurooffice
    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up X-Forwarded-Prefix /eurooffice
    }
  }

  route {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  redir /.well-known/carddav /remote.php/dav/ 301
  redir /.well-known/caldav /remote.php/dav/ 301
`,
      probes: [
        {
          path: "/browser/app.js",
          compareHeaders: ["x-backend-token", "strict-transport-security"],
          expectedStatus: 200,
          expectedBody: "/browser/app.js:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "strict-transport-security": "max-age=31536000;",
          },
        },
        {
          path: "/push/v1/notify",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/v1/notify:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/eurooffice/wopi/files/1",
          compareHeaders: ["x-backend-token", "x-seen-forwarded-prefix"],
          expectedStatus: 200,
          expectedBody: "/wopi/files/1:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-prefix": "/eurooffice",
          },
        },
        {
          path: "/remote.php/webdav",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/remote.php/webdav:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/.well-known/carddav",
          redirect: "manual",
          compareHeaders: ["location"],
          expectedStatus: 301,
          expectedBody: "",
          expectedHeaders: {
            location: "/remote.php/dav/",
          },
        },
      ],
    });

    // Adapted from a directus/directus discussion Caddyfile (30k+ stars).
    // Localizes the root while preserving supported static app behavior:
    // global file_server serving files after path-scoped handle/try_files
    // rewrites and an admin trailing-slash redirect.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: directus/directus admin static fallback",
      files: {
        "public/index.html":
          "<!doctype html><title>Directus</title><main>home</main>",
        "public/admin/index.html":
          "<!doctype html><title>Directus Admin</title><main>admin</main>",
        "public/admin/app.js": "console.log('directus-admin');\n",
        "public/thumbnail/index.php": "thumbnail fallback\n",
      },
      site: `
  root * public
  file_server

  redir /admin /admin/

  handle /admin/* {
    try_files {path} {path}/ /admin/index.html?{query}
  }

  handle /thumbnail/* {
    try_files {path} {path}/ /thumbnail/index.php?{query}
  }
`,
      probes: [
        {
          path: "/",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Directus</title><main>home</main>",
        },
        {
          path: "/admin",
          redirect: "manual",
          compareHeaders: ["location"],
          expectedStatus: 302,
          expectedBody: "",
          expectedHeaders: {
            location: "/admin/",
          },
        },
        {
          path: "/admin/app.js",
          expectedStatus: 200,
          expectedBody: "console.log('directus-admin');\n",
        },
        {
          path: "/admin/settings/profile?tab=users",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Directus Admin</title><main>admin</main>",
        },
        {
          path: "/thumbnail/small?key=value",
          expectedStatus: 200,
          expectedBody: "thumbnail fallback\n",
        },
      ],
    });

    // Adapted from rivet-dev/rivet frontend/Caddyfile.ladle
    // (5k+ stars). Localizes the port and root path while preserving the
    // supported SPA, header, try_files, encode, and file_server behavior.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: rivet-dev/rivet SPA static server",
      files: {
        "index.html": "<!doctype html><title>Rivet</title><main>app shell</main>",
        "app.js": "console.log('rivet');\n",
      },
      site: `
  handle /health {
    respond "healthy" 200
  }

  handle {
    root * .
    encode gzip

    header {
      X-Frame-Options "SAMEORIGIN"
      X-Content-Type-Options "nosniff"
      X-XSS-Protection "1; mode=block"
    }

    @static {
      path *.js *.css *.png *.jpg *.jpeg *.gif *.ico *.svg *.woff *.woff2 *.ttf *.eot
    }
    header @static Cache-Control "public, max-age=31536000, immutable"

    @html {
      path *.html
    }
    header @html Cache-Control "no-store, no-cache, must-revalidate"

    try_files {path} /index.html
    file_server
  }
`,
      probes: [
        {
          path: "/health",
          expectedStatus: 200,
          expectedBody: "healthy",
        },
        {
          path: "/",
          compareHeaders: [
            "x-frame-options",
            "x-content-type-options",
            "x-xss-protection",
          ],
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Rivet</title><main>app shell</main>",
          expectedHeaders: {
            "x-frame-options": "SAMEORIGIN",
            "x-content-type-options": "nosniff",
            "x-xss-protection": "1; mode=block",
          },
        },
        {
          path: "/missing/route",
          compareHeaders: [
            "x-frame-options",
            "x-content-type-options",
            "x-xss-protection",
          ],
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Rivet</title><main>app shell</main>",
          expectedHeaders: {
            "x-frame-options": "SAMEORIGIN",
            "x-content-type-options": "nosniff",
            "x-xss-protection": "1; mode=block",
          },
        },
        {
          path: "/app.js",
          compareHeaders: ["cache-control"],
          expectedStatus: 200,
          expectedBody: "console.log('rivet');\n",
          expectedHeaders: {
            "cache-control": "public, max-age=31536000, immutable",
          },
        },
        {
          path: "/index.html",
          compareHeaders: ["cache-control"],
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Rivet</title><main>app shell</main>",
          expectedHeaders: {
            "cache-control": "no-store, no-cache, must-revalidate",
          },
        },
      ],
    });

    // Adapted from 0xfurai/peekaping Caddyfile (1k+ stars). Localizes the
    // upstream and web root while preserving exact API/socket proxy handles,
    // shared-root static serving, exact env.js no-cache headers, broad static
    // asset cache headers, SPA fallback, and the source access-log block.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: 0xfurai/peekaping gateway static SPA",
      files: {
        "web/index.html":
          "<!doctype html><title>Peekaping</title><main>spa</main>",
        "web/env.js": "window.__PEEKAPING__ = true;\n",
        "web/assets/app.mjs": "console.log('peekaping');\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  handle /api/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle /socket.io/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  root * web

  handle /env.js {
    header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"
    file_server
  }

  @static path *.js *.css *.mjs *.woff *.woff2 *.svg *.png *.jpg *.jpeg *.gif *.ico
  handle @static {
    header Cache-Control "public, max-age=31536000, immutable"
    file_server
  }

  handle {
    try_files {path} {path}/ /index.html
    file_server
  }

  log {
    output stdout
    format append {
      fields {
        svc peekaping:gateway
      }
      wrap json {
        time_format iso8601
        message_key msg
      }
    }
    level info
  }
`,
      probes: [
        {
          path: "/api/monitors",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/api/monitors:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/socket.io/?EIO=4&transport=polling",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/socket.io/:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/env.js",
          compareHeaders: ["cache-control"],
          expectedStatus: 200,
          expectedBody: "window.__PEEKAPING__ = true;\n",
          expectedHeaders: {
            "cache-control":
              "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
          },
        },
        {
          path: "/assets/app.mjs",
          compareHeaders: ["cache-control"],
          expectedStatus: 200,
          expectedBody: "console.log('peekaping');\n",
          expectedHeaders: {
            "cache-control": "public, max-age=31536000, immutable",
          },
        },
        {
          path: "/settings/notifications",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Peekaping</title><main>spa</main>",
        },
      ],
    });

    // Adapted from remnawave/panel Caddyfile (4k+ stars). Localizes the port
    // and static roots while preserving ignored global runtime/server options,
    // host-header gating, non-main-domain redirect, external/permanent docs
    // redirects, exact landing route, strip-prefix landing assets, docs
    // fallback, encode, and security headers.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: remnawave/panel host-gated docs",
      files: {
        "landing/index.html":
          "<!doctype html><title>Remnawave</title><main>landing</main>",
        "landing-assets/app.js": "console.log('landing');\n",
        "docs/index.html":
          "<!doctype html><title>Remnawave Docs</title><main>docs</main>",
      },
      fullCaddyfile: ({ caddyPort }) => `
{
  admin off
  persist_config off
  auto_https off
  servers {
    trusted_proxies static private_ranges 100.0.0.0/8
  }
}

:${caddyPort} {
  handle /health {
    respond "OK" 200
  }

  @notMainDomain {
    not header Host docs.rw
  }
  handle @notMainDomain {
    redir https://docs.rw{uri} permanent
  }

  @mainDomain {
    header Host docs.rw
  }
  handle @mainDomain {
    redir /prime* https://t.me/xrocket?start=sb_E6HxjZHitIM98el permanent
    redir /blog/learn /docs/learn/quick-start permanent
    redir /blog/learn/quick-start /docs/learn/quick-start permanent
    redir /apps /docs/clients permanent
    redir /clients /docs/clients permanent
    redir /donate /docs/donate permanent

    handle / {
      root * landing
      encode gzip
      file_server
      try_files {path} /index.html

      header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "1; mode=block"
      }
    }

    handle_path /landing-assets/* {
      root * landing-assets
      encode gzip
      file_server
      try_files {path} /index.html

      header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "1; mode=block"
      }
    }

    handle {
      root * docs
      encode gzip
      file_server
      try_files {path} /index.html

      header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "1; mode=block"
      }
    }
  }
}
`,
      probes: [
        {
          path: "/health",
          rawHost: "other.example",
          expectedStatus: 200,
          expectedBody: "OK",
        },
        {
          path: "/docs/clients",
          rawHost: "other.example",
          compareHeaders: ["location"],
          compareBody: false,
          expectedStatus: 301,
          expectedBody: "",
          expectedHeaders: {
            location: "https://docs.rw/docs/clients",
          },
        },
        {
          path: "/",
          rawHost: "docs.rw",
          compareHeaders: [
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
          ],
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Remnawave</title><main>landing</main>",
          expectedHeaders: {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "x-xss-protection": "1; mode=block",
          },
        },
        {
          path: "/landing-assets/app.js",
          rawHost: "docs.rw",
          compareHeaders: ["x-content-type-options", "x-frame-options"],
          expectedStatus: 200,
          expectedBody: "console.log('landing');\n",
          expectedHeaders: {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
          },
        },
        {
          path: "/clients",
          rawHost: "docs.rw",
          compareHeaders: ["location"],
          compareBody: false,
          expectedStatus: 301,
          expectedBody: "",
          expectedHeaders: {
            location: "/docs/clients",
          },
        },
        {
          path: "/prime/abc",
          rawHost: "docs.rw",
          compareHeaders: ["location"],
          compareBody: false,
          expectedStatus: 301,
          expectedBody: "",
          expectedHeaders: {
            location: "https://t.me/xrocket?start=sb_E6HxjZHitIM98el",
          },
        },
        {
          path: "/docs/clients/",
          rawHost: "docs.rw",
          compareHeaders: ["x-content-type-options", "x-frame-options"],
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Remnawave Docs</title><main>docs</main>",
          expectedHeaders: {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
          },
        },
        {
          path: "/docs/missing/deep",
          rawHost: "docs.rw",
          compareHeaders: ["x-content-type-options", "x-frame-options"],
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Remnawave Docs</title><main>docs</main>",
          expectedHeaders: {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
          },
        },
      ],
    });

    // Adapted from renmu123/biliLive-tools docker/fullstack-Caddyfile
    // (1k+ stars). Localizes the port, upstream, and root path while preserving
    // the supported handle_path proxy and SPA file fallback behavior.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: renmu123/biliLive-tools API proxy and SPA",
      files: {
        "index.html": "<!doctype html><title>biliLive</title><main>spa</main>",
        "asset.txt": "static asset\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  handle_path /api* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle {
    root * .
    file_server
    encode gzip
    try_files {path} /index.html
  }
`,
      probes: [
        {
          path: "/api/status",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/status:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/asset.txt",
          expectedStatus: 200,
          expectedBody: "static asset\n",
        },
        {
          path: "/client/route",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>biliLive</title><main>spa</main>",
        },
      ],
    });

    // Adapted from chatpire/chatgpt-web-share Caddyfile (4k+ stars).
    // Localizes the port, upstream, and frontend root while preserving the
    // active supported behavior: handle_path API proxying and SPA static
    // fallback. The source puts file_server before root/try_files inside the
    // handle block; the probes assert stock Caddy's actual sorted behavior.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: chatpire/chatgpt-web-share API and SPA",
      files: {
        "dist/index.html":
          "<!doctype html><title>Chat Share</title><main>spa</main>",
        "dist/assets/app.js": "console.log('chat-share');\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  handle_path /api/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle /* {
    file_server
    root * dist
    try_files {path} /index.html
  }
`,
      probes: [
        {
          path: "/api/session",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/session:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/assets/app.js",
          expectedStatus: 200,
          expectedBody: "console.log('chat-share');\n",
        },
        {
          path: "/",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Chat Share</title><main>spa</main>",
        },
        {
          path: "/chat/session/42",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Chat Share</title><main>spa</main>",
        },
      ],
    });

    // Adapted from lensesio/fast-data-dev Caddyfile (2k+ stars). Localizes
    // ports and roots while preserving the supported behavior: handle_path API
    // reverse proxying, path-specific cache headers, a default file_server, and
    // path-matched browse file_server directives.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: lensesio/fast-data-dev API and browse paths",
      files: {
        "www/index.html":
          "<!doctype html><title>Fast Data Dev</title><main>home</main>",
        "www/coyote-tests/results": "results\n",
        "www/coyote-tests/index.html": "<!doctype html><title>Coyote</title>",
        "www/certs/root.pem": "cert\n",
        "www/logs/app.log": "log\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  handle_path /api/schema-registry/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle_path /api/kafka-connect/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  root * www

  header /coyote-tests/results Cache-Control "no-store"
  header /coyote-tests/index.html Cache-Control "no-store"

  file_server
  file_server /certs/* browse
  file_server /logs/* browse
`,
      probes: [
        {
          path: "/api/schema-registry/subjects",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/subjects:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/api/kafka-connect/connectors",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/connectors:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Fast Data Dev</title><main>home</main>",
        },
        {
          path: "/coyote-tests/results",
          compareHeaders: ["cache-control"],
          expectedStatus: 200,
          expectedBody: "results\n",
          expectedHeaders: {
            "cache-control": "no-store",
          },
        },
        {
          path: "/certs/",
          headers: { Accept: "application/json" },
          compareHeaders: ["content-type"],
          expectedStatus: 200,
          expectedBody: JSON.stringify(["root.pem:5"]),
          normalizeBrowseJson: true,
        },
        {
          path: "/logs/",
          headers: { Accept: "application/json" },
          compareHeaders: ["content-type"],
          expectedStatus: 200,
          expectedBody: JSON.stringify(["app.log:4"]),
          normalizeBrowseJson: true,
        },
      ],
    });

    // Adapted from openziti/zrok etc/caddy/multiple_upstream.Caddyfile
    // (4k+ stars). Localizes the template bind address and external upstream
    // while preserving the supported behavior: site bind, handle_path prefix
    // stripping, header_up Host and request-header placeholders, browse static
    // files, and fallback reverse proxying.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: openziti/zrok multiple upstream routing",
      files: {
        "static/index.html": "<!doctype html><title>zrok static</title>",
        "static/files/readme.txt": "readme\n",
        "static/share.txt": "share\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  bind 127.0.0.1

  handle_path /zrok/* {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up Host zrok.io
    }
  }

  handle_path /zrok-static/* {
    root * static
    file_server browse
  }

  reverse_proxy /* 127.0.0.1:${upstreamPort} {
    header_up Host localhost:${upstreamPort}
    header_up X-Real-IP {http.request.header.x-forwarded-for}
  }
`,
      probes: ({ upstreamPort }): Probe[] => [
        {
          path: "/zrok/docs",
          compareHeaders: ["x-backend-token", "x-seen-host"],
          expectedStatus: 200,
          expectedBody: "/docs:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-host": "zrok.io",
          },
        },
        {
          path: "/zrok-static/",
          compareHeaders: ["content-type"],
          expectedStatus: 200,
          expectedBody: "<!doctype html><title>zrok static</title>",
        },
        {
          path: "/zrok-static/files/",
          headers: { Accept: "application/json" },
          compareHeaders: ["content-type"],
          expectedStatus: 200,
          expectedBody: JSON.stringify(["readme.txt:7"]),
          normalizeBrowseJson: true,
        },
        {
          path: "/fallback",
          headers: { "X-Forwarded-For": "203.0.113.9" },
          compareHeaders: [
            "x-backend-token",
            "x-seen-host",
            "x-seen-real-ip",
          ],
          expectedStatus: 200,
          expectedBody: "/fallback:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-host": `localhost:${upstreamPort}`,
            "x-seen-real-ip": "203.0.113.9",
          },
        },
      ],
    });

    // Adapted from chibisafe/chibisafe Caddyfile (2k+ stars). Localizes the
    // uploads root and upstreams while preserving the supported route shape:
    // `file_server pass_thru` serves existing uploads before named API/docs
    // proxies and a default frontend proxy, with upstream Host and request
    // header placeholder propagation.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: chibisafe upload pass-thru proxy",
      files: {
        "uploads/image.png": "uploaded image\n",
      },
      upstream: true,
      fullCaddyfile: ({ caddyPort, upstreamPort }) => `
{
  admin off
  auto_https off
  servers {
    trusted_proxies static private_ranges
    client_ip_headers X-Forwarded-For X-Real-IP
  }
}

:${caddyPort} {
  route {
    file_server * {
      root uploads
      pass_thru
    }

    @api path /api/*
    reverse_proxy @api 127.0.0.1:${upstreamPort} {
      header_up Host {http.reverse_proxy.upstream.hostport}
      header_up X-Real-IP {http.request.header.X-Real-IP}
    }

    @docs path /docs*
    reverse_proxy @docs 127.0.0.1:${upstreamPort} {
      header_up Host {http.reverse_proxy.upstream.hostport}
      header_up X-Real-IP {http.request.header.X-Real-IP}
    }

    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up Host {http.reverse_proxy.upstream.hostport}
      header_up X-Real-IP {http.request.header.X-Real-IP}
    }
  }
}
`,
      probes: ({ upstreamPort }): Probe[] => [
        {
          path: "/image.png",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "uploaded image\n",
          expectedHeaders: {
            "x-backend-token": null,
          },
        },
        {
          path: "/api/albums",
          headers: { "X-Real-IP": "203.0.113.7" },
          compareHeaders: [
            "x-backend-token",
            "x-seen-host",
            "x-seen-real-ip",
          ],
          expectedStatus: 200,
          expectedBody: "/api/albums:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-host": `127.0.0.1:${upstreamPort}`,
            "x-seen-real-ip": "203.0.113.7",
          },
        },
        {
          path: "/docs/install",
          headers: { "X-Real-IP": "203.0.113.8" },
          compareHeaders: [
            "x-backend-token",
            "x-seen-host",
            "x-seen-real-ip",
          ],
          expectedStatus: 200,
          expectedBody: "/docs/install:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-host": `127.0.0.1:${upstreamPort}`,
            "x-seen-real-ip": "203.0.113.8",
          },
        },
        {
          path: "/gallery",
          headers: { "X-Real-IP": "203.0.113.9" },
          compareHeaders: [
            "x-backend-token",
            "x-seen-host",
            "x-seen-real-ip",
          ],
          expectedStatus: 200,
          expectedBody: "/gallery:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-host": `127.0.0.1:${upstreamPort}`,
            "x-seen-real-ip": "203.0.113.9",
          },
        },
      ],
    });

    // Adapted from appsmithorg/appsmith deploy/docker/fs/opt/appsmith/
    // caddy-reconfigure.mjs (38k+ stars). Localizes generated paths and omits
    // unsupported runtime surfaces such as rate_limit, metrics, admin sockets,
    // TLS/ACME, and Caddy branding header cleanup while preserving supported
    // behavior: request-ID expression matchers/header normalization, /info
    // rewrite-to-file serving, disable_canonical_uris, and loading-page
    // fallback via try_files.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: appsmith request id and info fallback",
      files: {
        "appsmith/info.json": `{"version":"local","commitSha":"abc123"}`,
        "www/index.html": "<!doctype html><title>Appsmith</title>",
        "www/loading.html": "<!doctype html><title>Loading</title>",
      },
      site: `
  encode zstd gzip

  request_header -X-Appsmith-Request-Id

  @valid-request-id expression {header.X-Request-Id}.matches("(?i)^[0-9A-F]{8}-[0-9A-F]{4}-[4][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$")
  header @valid-request-id X-Request-Id {header.X-Request-Id}
  @invalid-request-id expression !{header.X-Request-Id}.matches("(?i)^[0-9A-F]{8}-[0-9A-F]{4}-[4][0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$")
  header @invalid-request-id X-Request-Id invalid_request_id
  request_header @invalid-request-id X-Request-Id invalid_request_id

  handle /info {
    root * appsmith
    rewrite * /info.json
    file_server {
      disable_canonical_uris
    }
  }

  handle {
    root * www
    try_files /loading.html /index.html
    file_server {
      disable_canonical_uris
    }
  }
`,
      probes: [
        {
          path: "/info",
          headers: {
            "X-Request-Id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
          },
          compareHeaders: ["x-request-id"],
          expectedStatus: 200,
          expectedBody: `{"version":"local","commitSha":"abc123"}`,
          expectedHeaders: {
            "x-request-id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
          },
        },
        {
          path: "/info",
          headers: {
            "X-Request-Id": "not-a-v4-uuid",
          },
          compareHeaders: ["x-request-id"],
          expectedStatus: 200,
          expectedBody: `{"version":"local","commitSha":"abc123"}`,
          expectedHeaders: {
            "x-request-id": "invalid_request_id",
          },
        },
        {
          path: "/deep/client/route",
          compareHeaders: ["x-request-id"],
          expectedStatus: 200,
          expectedBody: "<!doctype html><title>Loading</title>",
          expectedHeaders: {
            "x-request-id": "invalid_request_id",
          },
        },
      ],
    });

    // Adapted from ai-robots-txt/ai.robots.txt Caddyfile (3k+ stars). The
    // source publishes a named `header_regexp User-Agent` AI-bot matcher; this
    // localizes the response and file serving while preserving the supported
    // matcher behavior with representative alternatives from the denylist.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: ai-robots-txt user-agent matcher",
      files: {
        "robots.txt": "User-agent: *\nDisallow:\n",
      },
      site: `
  @aibots {
    header_regexp User-Agent "(AddSearchBot|AI2Bot|ClaudeBot|GPTBot|Google-Extended|PerplexityBot)"
  }

  respond @aibots "blocked" 403

  root * .
  file_server
`,
      probes: [
        {
          path: "/robots.txt",
          headers: { "User-Agent": "GPTBot/1.0" },
          expectedStatus: 403,
          expectedBody: "blocked",
        },
        {
          path: "/robots.txt",
          headers: { "User-Agent": "Mozilla/5.0" },
          expectedStatus: 200,
          expectedBody: "User-agent: *\nDisallow:\n",
        },
      ],
    });

    // Adapted from Pagefind/pagefind docs/Caddyfile (5k+ stars). Localizes
    // the docs root and omits repo-local redirect imports while preserving the
    // supported behavior: regexp-capture rewrites, trailing-slash redirects,
    // Markdown negotiation by Accept header, cache headers for hashed/unhashed
    // assets, and file-server error handling. The localized matcher avoids
    // using a regexp capture in a sibling file matcher because Caddy evaluates
    // matcher maps in Go map order.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: Pagefind docs static negotiation",
      files: {
        "docs/404.html": "<!doctype html><title>missing</title>",
        "docs/guide/index.html": "<!doctype html><title>Guide</title>",
        "docs/guide/index.md": "# Guide\n",
        "docs/pagefind/search.pf_index": "index\n",
        "docs/assets/site.0123456789abcdef0123.js": "console.log('hash');\n",
        "docs/assets/site.js": "console.log('plain');\n",
      },
      site: `
  root * docs

  @noTrailingSlash {
    not path */
    not path *.*
    file {path}/index.html
  }
  redir @noTrailingSlash {path}/ 301

  handle_errors {
    rewrite * /404.html
    file_server
  }

  @wantsMarkdown {
    header Accept *text/markdown*
    not path *.*
    path_regexp mdpath ^(.+?)/?$
  }
  handle @wantsMarkdown {
    rewrite * {re.mdpath.1}/index.md
    header Content-Type "text/markdown; charset=utf-8"
    file_server
  }

  @pagefindHashed path *.pf_fragment *.pf_index *.pagefind
  header @pagefindHashed Cache-Control "public, max-age=31536000, immutable"

  @fingerprinted path_regexp fingerprinted \\.([0-9a-f]{20,})\\.
  header @fingerprinted Cache-Control "public, max-age=31536000, immutable"

  @staticUnhashed {
    path *.css *.js *.svg *.png *.ico *.woff2
    not path_regexp \\.([0-9a-f]{20,})\\.
  }
  header @staticUnhashed Cache-Control "public, max-age=3600, must-revalidate"

  @html path *.html */
  header @html Cache-Control "public, max-age=0, must-revalidate"

  file_server
`,
      probes: [
        {
          path: "/guide",
          redirect: "manual",
          compareHeaders: ["location"],
          expectedStatus: 301,
          expectedHeaders: {
            location: "/guide/",
          },
        },
        {
          path: "/guide/",
          headers: { Accept: "text/markdown" },
          compareHeaders: ["content-type"],
          expectedStatus: 200,
          expectedBody: "# Guide\n",
          expectedHeaders: {
            "content-type": "text/markdown; charset=utf-8",
          },
        },
        {
          path: "/guide/",
          headers: { Accept: "text/html" },
          compareHeaders: ["cache-control"],
          expectedStatus: 200,
          expectedBody: "<!doctype html><title>Guide</title>",
          expectedHeaders: {
            "cache-control": "public, max-age=0, must-revalidate",
          },
        },
        {
          path: "/pagefind/search.pf_index",
          compareHeaders: ["cache-control"],
          expectedStatus: 200,
          expectedBody: "index\n",
          expectedHeaders: {
            "cache-control": "public, max-age=31536000, immutable",
          },
        },
        {
          path: "/assets/site.0123456789abcdef0123.js",
          compareHeaders: ["cache-control"],
          expectedStatus: 200,
          expectedBody: "console.log('hash');\n",
          expectedHeaders: {
            "cache-control": "public, max-age=31536000, immutable",
          },
        },
        {
          path: "/assets/site.js",
          compareHeaders: ["cache-control"],
          expectedStatus: 200,
          expectedBody: "console.log('plain');\n",
          expectedHeaders: {
            "cache-control": "public, max-age=3600, must-revalidate",
          },
        },
        {
          path: "/missing",
          expectedStatus: 404,
          expectedBody: "<!doctype html><title>missing</title>",
        },
      ],
    });

    // Adapted from bonfire-networks/bonfire-app config/deploy/Caddyfile2-https
    // (900+ stars). Localizes the upload root and backend while preserving the
    // supported behavior: route-scoped static uploads, a catch-all reverse proxy,
    // gzip encode, a no-op access log directive, and a status-specific
    // `handle_errors` fallback for upstream connection failures.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: bonfire-app upload route and 502 fallback",
      files: {
        "frontend/data/uploads/avatar.png": "avatar\n",
      },
      site: `
  route /data/uploads/* {
    root * frontend
    try_files {path}
    file_server
  }

  route * {
    reverse_proxy 127.0.0.1:9
  }

  encode gzip
  log
  handle_errors {
    @502 expression \`{http.error.status_code} == 502\`
    handle @502 {
      respond 503 {
        body "Hello, unfortunately this instance seems to be down. Please try again in a few minutes!"
        close
      }
    }
  }
`,
      probes: [
        {
          path: "/data/uploads/avatar.png",
          expectedStatus: 200,
          expectedBody: "avatar\n",
        },
        {
          path: "/dashboard",
          expectedStatus: 503,
          expectedBody:
            "Hello, unfortunately this instance seems to be down. Please try again in a few minutes!",
        },
      ],
    });

    // Adapted from rybbit-io/rybbit Caddyfile (12k+ stars). Localizes the
    // domain, upstreams, and request-body limit while preserving the supported
    // behavior: encode, request_body max_size, an API handle proxy, and a
    // fallback client proxy handle.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: rybbit-io/rybbit request body proxy split",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  encode zstd gzip

  request_body max_size 8
  handle /api/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
`,
      probes: [
        {
          path: "/api/status",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/api/status:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/dashboard",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/dashboard:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          method: "POST",
          path: "/api/track",
          body: "12345678",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/api/track:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          method: "POST",
          path: "/api/track",
          body: "123456789",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/api/track:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
      ],
    });

    // Adapted from overhangio/tutor tutor/templates/apps/caddy/Caddyfile
    // (1k+ stars). Localizes the Jinja template, site names, and upstream while
    // preserving the shared proxy snippet, favicon regexp rewrite, scoped
    // request_body handle_path branches, encode, and header_up propagation. The
    // upload probe asserts stock Caddy's actual route flow: a request-body-only
    // handle_path branch can run before a later reverse_proxy route.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: overhangio/tutor request-body proxy flow",
      files: {},
      upstream: true,
      fullCaddyfile: ({ caddyPort, upstreamPort }) => `
{
  admin off
  auto_https off
}

(proxy) {
  encode gzip
  reverse_proxy 127.0.0.1:${upstreamPort} {
    header_up X-Forwarded-Port 80
  }
}

:${caddyPort} {
  @favicon_matcher {
    path_regexp ^/favicon.ico$
  }
  rewrite @favicon_matcher /theming/asset/images/favicon.ico

  handle_path /api/profile_images/*/*/upload {
    request_body {
      max_size 8
    }
  }

  import proxy

  handle_path /* {
    request_body {
      max_size 4
    }
  }
}
`,
      probes: [
        {
          path: "/favicon.ico",
          compareHeaders: ["x-backend-token", "x-seen-forwarded-port"],
          expectedStatus: 200,
          expectedBody: "/theming/asset/images/favicon.ico:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-port": "80",
          },
        },
        {
          method: "POST",
          path: "/api/profile_images/alice/avatar/upload",
          body: "12345678",
          compareHeaders: ["x-backend-token", "x-seen-forwarded-port"],
          expectedStatus: 200,
          expectedBody: "/api/profile_images/alice/avatar/upload:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-port": "80",
          },
        },
        {
          method: "POST",
          path: "/api/courseware/submit",
          body: "1234",
          compareHeaders: ["x-backend-token", "x-seen-forwarded-port"],
          expectedStatus: 200,
          expectedBody: "/api/courseware/submit:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-port": "80",
          },
        },
      ],
    });

    // Adapted from dairoot/ChatGPT-Mirror Caddyfile (1k+ stars). Localizes the
    // listen address, upstreams, and frontend root while preserving supported
    // vars/header matcher behavior, admin redirect and SPA fallback, path
    // stripping, and reverse_proxy header propagation.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: dairoot/ChatGPT-Mirror vars proxy",
      files: {
        "frontend/dist/index.html":
          "<!doctype html><title>Chat Mirror</title><main>admin</main>",
        "frontend/dist/assets/app.js": "console.log('mirror');\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  vars hscheme {http.request.scheme}
  @has_proto_header header X-Forwarded-Proto *
  vars @has_proto_header hscheme {http.request.header.X-Forwarded-Proto}

  handle_path /admin {
    redir * /admin/ permanent
  }

  handle /admin/* {
    uri strip_prefix /admin
    file_server
    root * frontend/dist
    try_files {path} /index.html
  }

  handle /0x/* {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up X-Forwarded-For {http.request.header.X-Forwarded-For}
      header_up X-Forwarded-Proto {vars.hscheme}
    }
  }

  handle /* {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up X-Forwarded-For {http.request.header.X-Forwarded-For}
      header_up X-Forwarded-Proto {vars.hscheme}
    }
  }
`,
      probes: [
        {
          path: "/admin",
          redirect: "manual",
          compareHeaders: ["location"],
          expectedStatus: 301,
          expectedBody: "",
          expectedHeaders: {
            location: "/admin/",
          },
        },
        {
          path: "/admin/",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Chat Mirror</title><main>admin</main>",
        },
        {
          path: "/admin/assets/app.js",
          expectedStatus: 200,
          expectedBody: "console.log('mirror');\n",
        },
        {
          path: "/admin/settings/profile",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Chat Mirror</title><main>admin</main>",
        },
        {
          path: "/0x/session",
          compareHeaders: ["x-backend-token", "x-seen-forwarded-proto"],
          expectedStatus: 200,
          expectedBody: "/0x/session:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-proto": "http",
          },
        },
        {
          path: "/v1/chat",
          headers: {
            "X-Forwarded-For": "198.51.100.9",
            "X-Forwarded-Proto": "https",
          },
          compareHeaders: [
            "x-backend-token",
            "x-seen-forwarded-for",
            "x-seen-forwarded-proto",
          ],
          expectedStatus: 200,
          expectedBody: "/v1/chat:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-for": "198.51.100.9",
            "x-seen-forwarded-proto": "https",
          },
        },
      ],
    });

    // Adapted from m3ue/m3u-editor Caddyfile (700+ stars). Localizes the
    // upstreams and root while preserving the supported HTTP behavior: security
    // headers, health response, streaming proxy prefix stripping with ignored
    // transport timeout tuning, app WebSocket path proxying as ordinary HTTP
    // reverse_proxy routes, dotfile denial, encode, and static file serving.
    // The source PHP FastCGI runtime branch is intentionally outside this
    // fixture.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: m3ue/m3u-editor proxy and static front",
      files: {
        "public/index.html":
          "<!doctype html><title>M3U Editor</title><main>home</main>",
        "public/assets/app.js": "console.log('m3u-editor');\n",
        "public/m3u-proxy-stream-monitor": "stream monitor\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  root * public
  encode gzip zstd

  header {
    X-Frame-Options "SAMEORIGIN"
    X-Content-Type-Options "nosniff"
    X-XSS-Protection "1; mode=block"
    -Server
  }

  @health {
    path /health
  }
  handle @health {
    respond "healthy" 200
  }

  @m3u_proxy {
    path /m3u-proxy/*
  }
  handle @m3u_proxy {
    uri strip_prefix /m3u-proxy
    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up Host {host}
      header_up X-Real-IP {remote_host}
      header_up X-Forwarded-For {remote_host}
      header_up X-Forwarded-Proto {scheme}
      flush_interval -1
      transport http {
        read_timeout 300s
        write_timeout 300s
        dial_timeout 10s
      }
    }
  }

  @websocket_app {
    path /app /app/*
  }
  handle @websocket_app {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up Host {host}
      header_up X-Real-IP {remote_host}
      header_up X-Forwarded-For {remote_host}
      header_up X-Forwarded-Proto {scheme}
    }
  }

  @websocket_apps {
    path /apps /apps/*
  }
  handle @websocket_apps {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up Host {host}
      header_up X-Real-IP {remote_host}
      header_up X-Forwarded-For {remote_host}
      header_up X-Forwarded-Proto {scheme}
    }
  }

  @dotfiles {
    path /.*
    not path /.well-known/*
  }
  handle @dotfiles {
    respond 403
  }

  file_server
`,
      probes: [
        {
          path: "/health",
          compareHeaders: [
            "x-frame-options",
            "x-content-type-options",
            "x-xss-protection",
          ],
          expectedStatus: 200,
          expectedBody: "healthy",
          expectedHeaders: {
            "x-frame-options": "SAMEORIGIN",
            "x-content-type-options": "nosniff",
            "x-xss-protection": "1; mode=block",
          },
        },
        {
          path: "/m3u-proxy/playlist.m3u",
          compareHeaders: [
            "x-backend-token",
            "x-seen-real-ip",
            "x-seen-forwarded-for",
            "x-seen-forwarded-proto",
          ],
          expectedStatus: 200,
          expectedBody: "/playlist.m3u:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-real-ip": "127.0.0.1",
            "x-seen-forwarded-for": "127.0.0.1",
            "x-seen-forwarded-proto": "http",
          },
        },
        {
          path: "/app/socket",
          compareHeaders: ["x-backend-token", "x-seen-forwarded-proto"],
          expectedStatus: 200,
          expectedBody: "/app/socket:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-proto": "http",
          },
        },
        {
          path: "/apps/reverb",
          compareHeaders: ["x-backend-token", "x-seen-forwarded-proto"],
          expectedStatus: 200,
          expectedBody: "/apps/reverb:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-proto": "http",
          },
        },
        {
          path: "/m3u-proxy-stream-monitor",
          compareHeaders: ["x-content-type-options"],
          expectedStatus: 200,
          expectedBody: "stream monitor\n",
          expectedHeaders: {
            "x-content-type-options": "nosniff",
          },
        },
        {
          path: "/assets/app.js",
          compareHeaders: ["x-frame-options"],
          expectedStatus: 200,
          expectedBody: "console.log('m3u-editor');\n",
          expectedHeaders: {
            "x-frame-options": "SAMEORIGIN",
          },
        },
        {
          path: "/.env",
          expectedStatus: 403,
          expectedBody: "",
        },
      ],
      expectedCompileWarnings: [
        "ignoring reverse_proxy field \"flush_interval\"",
        "ignoring reverse_proxy.transport.read_timeout",
        "ignoring reverse_proxy.transport.write_timeout",
        "ignoring reverse_proxy.transport.dial_timeout",
      ],
    });

    // Adapted from kossakovsky/n8n-install Caddyfile (800+ stars). Localizes
    // the protected welcome dashboard HTTP block while preserving the supported
    // basic_auth, root, file_server, and try_files SPA fallback behavior. The
    // source places file_server before try_files; the probes assert stock
    // Caddy's actual directive ordering after adaptation. TLS imports and the
    // larger service-proxy matrix are intentionally outside this fixture.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: kossakovsky/n8n-install protected welcome",
      files: {
        "welcome/index.html":
          "<!doctype html><title>n8n Install</title><main>welcome</main>",
        "welcome/assets/app.js": "console.log('welcome');\n",
      },
      site: `
  basic_auth {
    alice $2a$14$gqs5yvNgSqb/ksrUoam91ewSE1TjpYIgCuaiuZH395DQEPsiCVIei
  }
  root * welcome
  file_server
  try_files {path} /index.html
`,
      probes: [
        {
          path: "/",
          compareHeaders: ["www-authenticate"],
          expectedStatus: 401,
          expectedBody: "",
          expectedHeaders: {
            "www-authenticate": `Basic realm="restricted"`,
          },
        },
        {
          path: "/",
          headers: {
            Authorization: `Basic ${btoa("alice:secret")}`,
          },
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>n8n Install</title><main>welcome</main>",
        },
        {
          path: "/assets/app.js",
          headers: {
            Authorization: `Basic ${btoa("alice:secret")}`,
          },
          expectedStatus: 200,
          expectedBody: "console.log('welcome');\n",
        },
        {
          path: "/dashboard/tools",
          headers: {
            Authorization: `Basic ${btoa("alice:secret")}`,
          },
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>n8n Install</title><main>welcome</main>",
        },
      ],
    });

    // Adapted from coleam00/local-ai-packaged Caddyfile (3k+ stars).
    // Localizes domains and upstreams while preserving the active multi-service
    // host-based reverse_proxy routing shape used for n8n, Open WebUI, Flowise,
    // Langfuse, Supabase, and Neo4j.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: coleam00/local-ai-packaged host proxy fanout",
      files: {},
      upstream: true,
      fullCaddyfile: ({ caddyPort, upstreamPort }) => `
{
  admin off
  auto_https off
}

http://n8n.localhost:${caddyPort} {
  reverse_proxy 127.0.0.1:${upstreamPort}
}

http://webui.localhost:${caddyPort} {
  reverse_proxy 127.0.0.1:${upstreamPort}
}

http://flowise.localhost:${caddyPort} {
  reverse_proxy 127.0.0.1:${upstreamPort}
}

http://langfuse.localhost:${caddyPort} {
  reverse_proxy 127.0.0.1:${upstreamPort}
}

http://supabase.localhost:${caddyPort} {
  reverse_proxy 127.0.0.1:${upstreamPort}
}

http://neo4j.localhost:${caddyPort} {
  reverse_proxy 127.0.0.1:${upstreamPort}
}
`,
      probes: ({ caddyPort }): Probe[] => [
        {
          path: "/workflow/1",
          rawHost: `n8n.localhost:${caddyPort}`,
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/workflow/1:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/chat",
          rawHost: `webui.localhost:${caddyPort}`,
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/chat:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/canvas",
          rawHost: `flowise.localhost:${caddyPort}`,
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/canvas:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/analytics",
          rawHost: `langfuse.localhost:${caddyPort}`,
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/analytics:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/rest/v1/projects",
          rawHost: `supabase.localhost:${caddyPort}`,
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/rest/v1/projects:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/browser",
          rawHost: `neo4j.localhost:${caddyPort}`,
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/browser:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/workflow/1",
          rawHost: `unknown.localhost:${caddyPort}`,
          expectedStatus: 200,
        },
      ],
    });

    // Adapted from gravitl/netmaker docker/Caddyfile-pro (11k+ stars).
    // Localizes HTTPS hostnames and container upstreams while preserving the
    // supported multi-host proxy fanout, security response headers, and the
    // broker WebSocket-style request-header matcher's no-upgrade behavior. The
    // commented h2c GRPC branch from the source is intentionally outside this
    // fixture.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: gravitl/netmaker multi-host proxy headers",
      files: {},
      upstream: true,
      fullCaddyfile: ({ caddyPort, upstreamPort }) => `
{
  admin off
  auto_https off
}

http://dashboard.netmaker.localhost:${caddyPort} {
  header {
    Access-Control-Allow-Origin *.netmaker.localhost
    Strict-Transport-Security "max-age=31536000;"
    X-XSS-Protection "1; mode=block"
    X-Frame-Options "SAMEORIGIN"
    X-Robots-Tag "none"
    X-Content-Type-Options "nosniff"
    Referrer-Policy "strict-origin-when-cross-origin"
    Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' js.intercomcdn.com widget.intercom.io app.posthog.com *.gitbook.com *.gitbook.io learn.netmaker.io raw.githubusercontent.com; style-src 'self' 'unsafe-inline' fonts.googleapis.com *.gitbook.com *.gitbook.io learn.netmaker.io; font-src 'self' fonts.gstatic.com; img-src 'self' data: about: https:; media-src 'self' media.netmaker.io; connect-src 'self' data: https://api.netmaker.localhost app.posthog.com api.accounts.netmaker.io js.intercomcdn.com api-iam.intercom.io api.github.com nominatim.openstreetmap.org *.cartocdn.com; worker-src 'self' blob:; frame-src 'self' accounts.google.com github.com login.microsoftonline.com *.okta.com learn.netmaker.io;"
    -Server
  }

  reverse_proxy 127.0.0.1:${upstreamPort}
}

http://netmaker-exporter.netmaker.localhost:${caddyPort} {
  reverse_proxy 127.0.0.1:${upstreamPort}
}

http://grafana.netmaker.localhost:${caddyPort} {
  header {
    X-Content-Type-Options "nosniff"
    Referrer-Policy "strict-origin-when-cross-origin"
  }

  reverse_proxy 127.0.0.1:${upstreamPort}
}

http://api.netmaker.localhost:${caddyPort} {
  header {
    X-Content-Type-Options "nosniff"
    Referrer-Policy "strict-origin-when-cross-origin"
  }

  reverse_proxy 127.0.0.1:${upstreamPort}
}

http://broker.netmaker.localhost:${caddyPort} {
  @ws {
    header Connection *Upgrade*
    header Upgrade websocket
  }
  reverse_proxy @ws 127.0.0.1:${upstreamPort}
}
`,
      probes: ({ caddyPort }): Probe[] => [
        {
          path: "/",
          rawHost: `dashboard.netmaker.localhost:${caddyPort}`,
          compareHeaders: [
            "access-control-allow-origin",
            "strict-transport-security",
            "x-xss-protection",
            "x-frame-options",
            "x-robots-tag",
            "x-content-type-options",
            "referrer-policy",
            "content-security-policy",
            "x-backend-token",
          ],
          expectedStatus: 200,
          expectedBody: "/:",
          expectedHeaders: {
            "access-control-allow-origin": "*.netmaker.localhost",
            "strict-transport-security": "max-age=31536000;",
            "x-xss-protection": "1; mode=block",
            "x-frame-options": "SAMEORIGIN",
            "x-robots-tag": "none",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "content-security-policy":
              "default-src 'self'; script-src 'self' 'unsafe-inline' js.intercomcdn.com widget.intercom.io app.posthog.com *.gitbook.com *.gitbook.io learn.netmaker.io raw.githubusercontent.com; style-src 'self' 'unsafe-inline' fonts.googleapis.com *.gitbook.com *.gitbook.io learn.netmaker.io; font-src 'self' fonts.gstatic.com; img-src 'self' data: about: https:; media-src 'self' media.netmaker.io; connect-src 'self' data: https://api.netmaker.localhost app.posthog.com api.accounts.netmaker.io js.intercomcdn.com api-iam.intercom.io api.github.com nominatim.openstreetmap.org *.cartocdn.com; worker-src 'self' blob:; frame-src 'self' accounts.google.com github.com login.microsoftonline.com *.okta.com learn.netmaker.io;",
            "x-backend-token": "backend",
          },
        },
        {
          path: "/metrics",
          rawHost: `netmaker-exporter.netmaker.localhost:${caddyPort}`,
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/metrics:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/login",
          rawHost: `grafana.netmaker.localhost:${caddyPort}`,
          compareHeaders: [
            "x-content-type-options",
            "referrer-policy",
            "x-backend-token",
          ],
          expectedStatus: 200,
          expectedBody: "/login:",
          expectedHeaders: {
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "x-backend-token": "backend",
          },
        },
        {
          path: "/api/nodes",
          rawHost: `api.netmaker.localhost:${caddyPort}`,
          compareHeaders: [
            "x-content-type-options",
            "referrer-policy",
            "x-backend-token",
          ],
          expectedStatus: 200,
          expectedBody: "/api/nodes:",
          expectedHeaders: {
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "x-backend-token": "backend",
          },
        },
        {
          path: "/mqtt",
          rawHost: `broker.netmaker.localhost:${caddyPort}`,
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "",
          expectedHeaders: {
            "x-backend-token": null,
          },
        },
      ],
    });

    // Adapted from MHSanaei/3x-ui wiki Caddy reverse-proxy example (40k+
    // stars). Localizes the upstream and omits TLS/panel auth details while
    // preserving the supported behavior: a route that proxies WebSocket-style
    // requests by header matcher, then returns 403 for non-upgrade requests.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: MHSanaei/3x-ui websocket-gated route",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  route /api/v1* {
    @websockets {
      header Connection *Upgrade*
      header Upgrade websocket
    }
    reverse_proxy @websockets 127.0.0.1:${upstreamPort}
    respond "Forbidden" 403
  }

  respond "Not found!" 404
`,
      probes: ({ caddyPort }): Probe[] => [
        {
          path: "/api/v1/tunnel",
          rawHost: `localhost:${caddyPort}`,
          headers: {
            Connection: "Upgrade",
            Upgrade: "websocket",
          },
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/api/v1/tunnel:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/api/v1/tunnel",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 403,
          expectedBody: "Forbidden",
          expectedHeaders: {
            "x-backend-token": null,
          },
        },
        {
          path: "/other",
          expectedStatus: 404,
          expectedBody: "Not found!",
        },
      ],
    });

    // Adapted from openmediavault/openmediavault wetty Caddyfile template
    // (6k+ stars). Localizes the listener and upstream while preserving the
    // supported reverse_proxy response-header deletion behavior. The optional
    // TLS file configuration from the source template is intentionally outside
    // this fixture.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: openmediavault wetty header_down deletes",
      files: {},
      upstream: true,
      fullCaddyfile: ({ caddyPort, upstreamPort }) => `
{
  admin off
  auto_https off
}

:${caddyPort} {
  reverse_proxy 127.0.0.1:${upstreamPort} {
    header_down -Content-Security-Policy
    header_down -Strict-Transport-Security
    header_down -Cross-Origin-Opener-Policy
    header_down -Cross-Origin-Resource-Policy
  }
}
`,
      probes: [
        {
          path: "/wetty/session",
          compareHeaders: [
            "x-backend-token",
            "content-security-policy",
            "strict-transport-security",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
          ],
          expectedStatus: 200,
          expectedBody: "/wetty/session:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "content-security-policy": null,
            "strict-transport-security": null,
            "cross-origin-opener-policy": null,
            "cross-origin-resource-policy": null,
          },
        },
      ],
    });

    // Adapted from coleam00/Archon Caddyfile.example (22k+ stars). Localizes
    // domain/env placeholders and keeps the supported behavior: public bypass
    // proxy routes, a `not path` protected matcher for basic auth, protected
    // app proxying, ignored SSE flush tuning, encode, and security headers.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: coleam00/Archon auth bypass proxy",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  handle /webhooks/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle /api/health {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  @protected not path /webhooks/* /api/health

  basicauth @protected {
    alice $2a$14$gqs5yvNgSqb/ksrUoam91ewSE1TjpYIgCuaiuZH395DQEPsiCVIei
  }

  handle {
    @sse path /api/stream/*

    reverse_proxy @sse 127.0.0.1:${upstreamPort} {
      flush_interval -1
    }

    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  header {
    X-Content-Type-Options nosniff
    X-Frame-Options DENY
    Referrer-Policy strict-origin-when-cross-origin
    Strict-Transport-Security "max-age=31536000; includeSubDomains"
    -Server
  }

  encode gzip zstd
`,
      probes: [
        {
          path: "/webhooks/incoming",
          compareHeaders: ["x-backend-token", "x-content-type-options"],
          expectedStatus: 200,
          expectedBody: "/webhooks/incoming:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-content-type-options": "nosniff",
          },
        },
        {
          path: "/api/health",
          compareHeaders: ["x-backend-token", "x-frame-options"],
          expectedStatus: 200,
          expectedBody: "/api/health:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-frame-options": "DENY",
          },
        },
        {
          path: "/api/stream/events",
          compareHeaders: ["www-authenticate", "x-backend-token"],
          expectedStatus: 401,
          expectedBody: "",
          expectedHeaders: {
            "www-authenticate": `Basic realm="restricted"`,
            "x-backend-token": null,
          },
        },
        {
          path: "/api/stream/events",
          headers: {
            Authorization: `Basic ${btoa("alice:wrong")}`,
          },
          compareHeaders: ["www-authenticate", "x-backend-token"],
          expectedStatus: 401,
          expectedBody: "",
          expectedHeaders: {
            "www-authenticate": `Basic realm="restricted"`,
            "x-backend-token": null,
          },
        },
        {
          path: "/api/stream/events",
          headers: {
            Authorization: `Basic ${btoa("alice:secret")}`,
          },
          compareHeaders: [
            "x-backend-token",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "strict-transport-security",
          ],
          expectedStatus: 200,
          expectedBody: "/api/stream/events:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
          },
        },
        {
          path: "/projects",
          headers: {
            Authorization: `Basic ${btoa("alice:secret")}`,
          },
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/projects:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
      ],
    });

    // Adapted from wahyd4/aria2-ariang-docker SecureCaddyfile (1k+ stars).
    // Localizes the domain, upstreams, root paths, and env placeholders while
    // preserving protected paths, redirs, proxy transport tuning, and file
    // serving behavior.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: wahyd4/aria2-ariang-docker protected proxy",
      files: {
        "index.html": "<!doctype html><title>AriaNg</title><main>ui</main>",
        "ro/report.txt": "readonly report\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  log {
    level INFO
    output stderr
  }

  @protected path / /index.html /css/* /js/* /ro /ro/* /jsonrpc

  basicauth @protected {
    alice $2a$14$gqs5yvNgSqb/ksrUoam91ewSE1TjpYIgCuaiuZH395DQEPsiCVIei
  }

  redir /ui / 301
  redir /ui/ / 301
  redir /rclone /rclone/ 301
  redir /files /files/ 301
  redir /ro /ro/ 301

  reverse_proxy /rpc 127.0.0.1:${upstreamPort} {
    transport http {
      read_timeout 300s
      write_timeout 300s
      dial_timeout 30s
      keepalive 90s
      keepalive_idle_conns 10
      max_conns_per_host 0
    }
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
  }

  route /ro/* {
    uri strip_prefix /ro
    root * ro
    file_server {
      browse
    }
  }

  route /ping {
    respond "app version: local"
  }

  root * .
  file_server
  encode gzip
`,
      probes: [
        {
          path: "/",
          compareHeaders: ["www-authenticate"],
          expectedStatus: 401,
          expectedBody: "",
          expectedHeaders: {
            "www-authenticate": `Basic realm="restricted"`,
          },
        },
        {
          path: "/",
          headers: {
            Authorization: `Basic ${btoa("alice:secret")}`,
          },
          expectedStatus: 200,
          expectedBody: "<!doctype html><title>AriaNg</title><main>ui</main>",
        },
        {
          path: "/ui",
          compareHeaders: ["location"],
          expectedStatus: 301,
          expectedBody: "",
          expectedHeaders: {
            location: "/",
          },
        },
        {
          path: "/rpc",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/rpc:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/ro/report.txt",
          headers: {
            Authorization: `Basic ${btoa("alice:secret")}`,
          },
          expectedStatus: 200,
          expectedBody: "readonly report\n",
        },
        {
          path: "/ping",
          expectedStatus: 200,
          expectedBody: "app version: local",
        },
      ],
      expectedCompileWarnings: [
        "ignoring reverse_proxy.transport.read_timeout",
        "ignoring reverse_proxy.transport.write_timeout",
        "ignoring reverse_proxy.transport.dial_timeout",
        "ignoring reverse_proxy.transport.keep_alive",
        "ignoring reverse_proxy.transport.max_conns_per_host",
      ],
    });

    // Adapted from wahyd4/aria2-ariang-docker Caddyfile (1k+ stars).
    // Localizes the domain, upstreams, root paths, and env placeholders while
    // preserving the unprotected AriaNg/RPC/File Browser/Rclone routing shape,
    // redirects, reverse_proxy transport timeout/keepalive tuning, strip-prefix
    // proxy routes, read-only file serving, encode, and static fallback.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: wahyd4/aria2-ariang-docker unprotected proxy",
      files: {
        "index.html": "<!doctype html><title>AriaNg</title><main>ui</main>",
        "ro/report.txt": "readonly report\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  log {
    level INFO
    output stderr
  }

  redir /ui / 301
  redir /ui/ / 301
  redir /rclone /rclone/ 301
  redir /files /files/ 301
  redir /ro /ro/ 301

  reverse_proxy /rpc 127.0.0.1:${upstreamPort} {
    transport http {
      read_timeout 300s
      write_timeout 300s
      dial_timeout 30s
      keepalive 90s
      keepalive_idle_conns 10
      max_conns_per_host 0
    }
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
  }

  reverse_proxy /jsonrpc 127.0.0.1:${upstreamPort} {
    transport http {
      read_timeout 300s
      write_timeout 300s
      dial_timeout 30s
      keepalive 90s
      keepalive_idle_conns 10
      max_conns_per_host 0
    }
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
  }

  route /rclone/* {
    uri strip_prefix /rclone
    reverse_proxy 127.0.0.1:${upstreamPort} {
      transport http {
        read_timeout 120s
        write_timeout 120s
        keepalive 60s
      }
    }
  }

  route /files/* {
    uri strip_prefix /files
    reverse_proxy 127.0.0.1:${upstreamPort} {
      transport http {
        read_timeout 120s
        write_timeout 120s
        keepalive 60s
      }
    }
  }

  route /ro/* {
    uri strip_prefix /ro
    root * ro
    file_server {
      browse
    }
  }

  route /ping {
    respond "app version: local"
  }

  root * .
  file_server
  encode gzip
`,
      probes: [
        {
          path: "/",
          expectedStatus: 200,
          expectedBody: "<!doctype html><title>AriaNg</title><main>ui</main>",
        },
        {
          path: "/ui",
          compareHeaders: ["location"],
          expectedStatus: 301,
          expectedBody: "",
          expectedHeaders: {
            location: "/",
          },
        },
        {
          path: "/rpc",
          compareHeaders: ["x-backend-token", "x-seen-real-ip"],
          expectedStatus: 200,
          expectedBody: "/rpc:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-real-ip": "127.0.0.1",
          },
        },
        {
          path: "/jsonrpc",
          compareHeaders: ["x-backend-token", "x-seen-real-ip"],
          expectedStatus: 200,
          expectedBody: "/jsonrpc:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-real-ip": "127.0.0.1",
          },
        },
        {
          path: "/rclone/status",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/status:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/files/browse",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/browse:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/ro/report.txt",
          expectedStatus: 200,
          expectedBody: "readonly report\n",
        },
        {
          path: "/ping",
          expectedStatus: 200,
          expectedBody: "app version: local",
        },
      ],
    });

    // Adapted from Freedium-cfd/web caddy/CaddyfileTemplate (1k+ stars).
    // Uses the runnable non-TLS site shape from the template, with template
    // placeholders rendered away and the upstream localized.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: Freedium-cfd/web snippet proxy",
      files: {},
      upstream: true,
      prelude: `
(common) {
  encode gzip
  header -Server
}

(freedium_web) {
  reverse_proxy 127.0.0.1:{args[0]} {
    import header_up
    import lb_try
  }
}

(header_up) {
  header_up Host {host}
  header_up X-Real-IP {remote_host}
  header_up X-Forwarded-For {remote_host}
  header_up X-Forwarded-Proto {scheme}
}

(lb_try) {
  lb_try_duration 30s
  lb_try_interval 1s
}
`,
      site: ({ upstreamPort }) => `
  import common
  import freedium_web ${upstreamPort}
`,
      probes: [
        {
          path: "/article",
          headers: { Host: "freedium.local" },
          compareHeaders: [
            "x-backend-token",
            "x-seen-forwarded-proto",
            "x-seen-real-ip",
          ],
          expectedStatus: 200,
          expectedBody: "/article:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-proto": "http",
            "x-seen-real-ip": "127.0.0.1",
          },
        },
      ],
      expectedCompileWarnings: [
        "ignoring reverse_proxy.load_balancing.try_duration",
        "ignoring reverse_proxy.load_balancing.try_interval",
      ],
    });

    // Adapted from FreshRSS/FreshRSS issue #6208 (popular repo, 15k+ stars).
    // Localizes the domain and upstream while preserving the subfolder redirect,
    // strip-prefix reverse proxy, and forwarded-prefix header propagation.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: FreshRSS subfolder proxy",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  redir /freshrss /freshrss/i/

  route /freshrss* {
    uri strip_prefix /freshrss
    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up Host {host}
      header_up X-Real-IP {remote_host}
      header_up X-Forwarded-Proto {scheme}
      header_up X-Forwarded-Host {host}
      header_up X-Forwarded-For {remote_host}
      header_up X-Forwarded-Prefix "/freshrss/"
    }
  }
`,
      probes: [
        {
          path: "/freshrss",
          compareHeaders: ["location", "x-backend-token"],
          expectedStatus: 302,
          expectedBody: "",
          expectedHeaders: {
            location: "/freshrss/i/",
            "x-backend-token": null,
          },
        },
        {
          path: "/freshrss/i/",
          rawHost: "reader.local",
          compareHeaders: [
            "x-backend-token",
            "x-seen-host",
            "x-seen-real-ip",
            "x-seen-forwarded-prefix",
            "x-seen-forwarded-proto",
            "x-seen-forwarded-host",
          ],
          expectedStatus: 200,
          expectedBody: "/i/:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-host": "reader.local",
            "x-seen-real-ip": "127.0.0.1",
            "x-seen-forwarded-prefix": "/freshrss/",
            "x-seen-forwarded-proto": "http",
            "x-seen-forwarded-host": "reader.local",
          },
        },
        {
          path: "/freshrss/api/greader.php",
          rawHost: "reader.local",
          compareHeaders: [
            "x-backend-token",
            "x-seen-forwarded-prefix",
            "x-seen-forwarded-host",
          ],
          expectedStatus: 200,
          expectedBody: "/api/greader.php:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-forwarded-prefix": "/freshrss/",
            "x-seen-forwarded-host": "reader.local",
          },
        },
      ],
    });

    // Adapted from go-gitea/gitea issue #22596 (popular repo, 56k+ stars).
    // Localizes the domain and upstream while preserving explicit real-IP and
    // forwarded-for header propagation through reverse_proxy.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: go-gitea/gitea real IP proxy headers",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  reverse_proxy 127.0.0.1:${upstreamPort} {
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
  }
`,
      probes: [
        {
          path: "/user/repo",
          headers: {
            "X-Real-IP": "203.0.113.8",
            "X-Forwarded-For": "203.0.113.9",
          },
          compareHeaders: [
            "x-backend-token",
            "x-seen-real-ip",
            "x-seen-forwarded-for",
          ],
          expectedStatus: 200,
          expectedBody: "/user/repo:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-real-ip": "127.0.0.1",
            "x-seen-forwarded-for": "127.0.0.1",
          },
        },
      ],
    });

    // Adapted from PostHog/posthog.com Caddy proxy docs (official PostHog
    // docs repo; main PostHog org repo has 34k+ stars). Localizes upstreams
    // while preserving CORS preflight handling, global CORS response headers,
    // path-specific proxy branches, and upstream CORS header deletion.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: PostHog CORS proxy routing",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  @options method OPTIONS
  handle @options {
    header Access-Control-Allow-Origin "https://app.local"
    header Access-Control-Allow-Methods "GET, POST, OPTIONS"
    header Access-Control-Allow-Headers "*"
    respond 204
  }

  header {
    Access-Control-Allow-Origin "https://app.local"
    Access-Control-Allow-Methods "GET, POST, OPTIONS"
    Access-Control-Allow-Headers "*"
  }

  handle /static/* {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up Host assets.local
      header_down -Access-Control-Allow-Origin
    }
  }
  handle /array/* {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up Host assets.local
      header_down -Access-Control-Allow-Origin
    }
  }
  handle {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      header_up Host events.local
      header_down -Access-Control-Allow-Origin
    }
  }
`,
      probes: [
        {
          path: "/capture",
          method: "OPTIONS",
          compareHeaders: [
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "x-backend-token",
          ],
          expectedStatus: 204,
          expectedBody: "",
          expectedHeaders: {
            "access-control-allow-origin": "https://app.local",
            "access-control-allow-methods": "GET, POST, OPTIONS",
            "access-control-allow-headers": "*",
            "x-backend-token": null,
          },
        },
        {
          path: "/static/session.js",
          compareHeaders: [
            "access-control-allow-origin",
            "x-backend-token",
            "x-seen-host",
          ],
          expectedStatus: 200,
          expectedBody: "/static/session.js:",
          expectedHeaders: {
            "access-control-allow-origin": "https://app.local",
            "x-backend-token": "backend",
            "x-seen-host": "assets.local",
          },
        },
        {
          path: "/e/",
          compareHeaders: [
            "access-control-allow-origin",
            "x-backend-token",
            "x-seen-host",
          ],
          expectedStatus: 200,
          expectedBody: "/e/:",
          expectedHeaders: {
            "access-control-allow-origin": "https://app.local",
            "x-backend-token": "backend",
            "x-seen-host": "events.local",
          },
        },
      ],
    });

    // Adapted from Mereithhh/vanblog CaddyfileTemplate (3k+ stars).
    // Localizes upstreams and the admin root while preserving the supported
    // HTTP routing shape: imported reverse_proxy options, many handle branches,
    // URI replacement aliases, API strip-prefix behavior, SPA admin fallback,
    // encode, and final frontend proxy fallback. TLS on-demand/global admin
    // behavior from the source template is intentionally outside this fixture.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: Mereithhh/vanblog multi-handle proxy",
      files: {
        "admin/index.html":
          "<!doctype html><title>VanBlog Admin</title><main>admin</main>",
        "admin/assets/app.js": "console.log('vanblog-admin');\n",
      },
      upstream: true,
      prelude: `
(h) {
  trusted_proxies private_ranges
}
`,
      site: ({ upstreamPort }) => `
  encode zstd gzip

  handle /ui* {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      import h
    }
  }
  handle /user* {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      import h
    }
  }
  handle /token* {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      import h
    }
  }
  handle /db* {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      import h
    }
  }
  handle /comment* {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      import h
    }
  }
  handle /oauth* {
    reverse_proxy 127.0.0.1:${upstreamPort} {
      import h
    }
  }
  handle /favicon* {
    uri replace /favicon /static/img/favicon
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle /static/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle /c/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle /custom/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle /feed.json {
    uri replace /feed.json /rss/feed.json
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle /feed.xml {
    uri replace /feed.xml /rss/feed.xml
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle /sitemap.xml {
    uri replace /sitemap.xml /sitemap/sitemap.xml
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle /atom.xml {
    uri replace /feed.xml /rss/atom.xml
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle /rss/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle /swagger* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle /api/comment {
    uri strip_prefix /api
    reverse_proxy 127.0.0.1:${upstreamPort} {
      import h
    }
  }
  handle /api/* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }
  handle_path /admin* {
    root * admin
    try_files {path} /index.html
    file_server
  }
  reverse_proxy 127.0.0.1:${upstreamPort}
`,
      probes: [
        {
          path: "/ui/settings",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/ui/settings:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/favicon.ico",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/static/img/favicon.ico:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/feed.json",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/rss/feed.json:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/atom.xml",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/atom.xml:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/api/comment",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/comment:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/api/comment/thread",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/api/comment/thread:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/admin/settings",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>VanBlog Admin</title><main>admin</main>",
        },
        {
          path: "/admin/assets/app.js",
          expectedStatus: 200,
          expectedBody: "console.log('vanblog-admin');\n",
        },
        {
          path: "/posts/first",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/posts/first:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
      ],
    });

    // Adapted from supabase/supabase docker/volumes/proxy/caddy/Caddyfile
    // (100k+ stars). Localizes the domain, credentials, and upstreams while
    // preserving public API path routing and authenticated fallback proxying.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: supabase/supabase proxy split",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  @supabase_api path /auth/v1/* /rest/v1/* /graphql/v1 /realtime/v1/* /storage/v1/* /functions/v1/* /mcp /sso/*

  handle @supabase_api {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle {
    basic_auth {
      alice $2a$14$gqs5yvNgSqb/ksrUoam91ewSE1TjpYIgCuaiuZH395DQEPsiCVIei
    }

    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  header -server
`,
      probes: [
        {
          path: "/auth/v1/token",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/auth/v1/token:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/graphql/v1",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/graphql/v1:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/project/default",
          compareHeaders: ["www-authenticate"],
          expectedStatus: 401,
          expectedBody: "",
          expectedHeaders: {
            "www-authenticate": `Basic realm="restricted"`,
          },
        },
        {
          path: "/project/default",
          headers: {
            Authorization: `Basic ${btoa("alice:secret")}`,
          },
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/project/default:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
      ],
    });

    // Adapted from inventree/InvenTree contrib/container/Caddyfile (7k+
    // stars). Localizes the site address, roots, and upstream while preserving
    // CORS snippet imports, request_body, static/media file serving,
    // forward_auth, and fallback proxying.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: inventree/InvenTree static media auth",
      files: {
        "static/app.js": "console.log('inventree');\n",
        "media/secret.txt": "protected media\n",
        "media/denied.txt": "hidden media\n",
      },
      upstream: true,
      prelude: `
(cors-headers) {
  header Allow GET,HEAD,OPTIONS
  header Access-Control-Allow-Origin *
  header Access-Control-Allow-Methods GET,HEAD,OPTIONS
  header Access-Control-Allow-Headers Authorization,Content-Type,User-Agent,traceparent

  @cors_preflight{args[0]} method OPTIONS

  handle @cors_preflight{args[0]} {
    respond "" 204
  }
}
`,
      site: ({ upstreamPort }) => `
  encode gzip

  request_body {
    max_size 100MB
  }

  handle_path /static/* {
    import cors-headers static

    root * static
    file_server
  }

  handle_path /media/* {
    import cors-headers media

    root * media
    file_server

    header Content-Disposition attachment

    forward_auth 127.0.0.1:${upstreamPort} {
      uri /auth/
    }
  }

  reverse_proxy 127.0.0.1:${upstreamPort}
`,
      probes: [
        {
          path: "/static/app.js",
          compareHeaders: [
            "allow",
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-allow-headers",
          ],
          expectedStatus: 200,
          expectedBody: "console.log('inventree');\n",
          expectedHeaders: {
            allow: "GET,HEAD,OPTIONS",
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "GET,HEAD,OPTIONS",
            "access-control-allow-headers":
              "Authorization,Content-Type,User-Agent,traceparent",
          },
        },
        {
          path: "/static/app.js",
          method: "OPTIONS",
          compareHeaders: [
            "allow",
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-allow-headers",
          ],
          expectedStatus: 204,
          expectedBody: "",
          expectedHeaders: {
            allow: "GET,HEAD,OPTIONS",
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "GET,HEAD,OPTIONS",
            "access-control-allow-headers":
              "Authorization,Content-Type,User-Agent,traceparent",
          },
        },
        {
          path: "/media/secret.txt",
          compareHeaders: [
            "content-disposition",
            "allow",
            "access-control-allow-origin",
          ],
          expectedStatus: 200,
          expectedBody: "protected media\n",
          expectedHeaders: {
            "content-disposition": "attachment",
            allow: "GET,HEAD,OPTIONS",
            "access-control-allow-origin": "*",
          },
        },
        {
          path: "/media/denied.txt",
          compareHeaders: ["content-disposition"],
          expectedStatus: 401,
          expectedBody: "denied",
          expectedHeaders: {
            "content-disposition": "attachment",
          },
        },
        {
          path: "/dashboard",
          expectedStatus: 200,
          expectedBody: "/dashboard:",
        },
      ],
    });

    // Adapted from baserow/baserow Caddyfile (4k+ stars). Localizes env
    // placeholders and keeps the supported media-serving behavior: handle_path
    // prefix stripping, a query matcher that sets a download filename from
    // `{query.dl}`, CORS headers, and file_server root configuration.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: baserow/baserow media download headers",
      files: {
        "media/report.csv": "id,name\n1,alpha\n",
        "media/image.png": new Uint8Array([137, 80, 78, 71, 13, 10]),
      },
      site: `
  handle_path /media/* {
    @downloads {
      query dl=*
    }

    header @downloads Content-Disposition "attachment; filename={query.dl}"
    header X-Content-Type-Options "nosniff"
    header Content-Security-Policy "sandbox; default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'"

    header {
      Access-Control-Allow-Origin http://localhost
      Access-Control-Allow-Methods "GET, HEAD, OPTIONS"
      Access-Control-Allow-Headers "*"
      Access-Control-Expose-Headers "Content-Length, Content-Type"
    }

    file_server {
      root media
    }
  }
`,
      probes: [
        {
          path: "/media/report.csv?dl=report.csv",
          compareHeaders: [
            "content-disposition",
            "x-content-type-options",
            "content-security-policy",
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-expose-headers",
          ],
          expectedStatus: 200,
          expectedBody: "id,name\n1,alpha\n",
          expectedHeaders: {
            "content-disposition": "attachment; filename=report.csv",
            "x-content-type-options": "nosniff",
            "content-security-policy":
              "sandbox; default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'",
            "access-control-allow-origin": "http://localhost",
            "access-control-allow-methods": "GET, HEAD, OPTIONS",
            "access-control-expose-headers": "Content-Length, Content-Type",
          },
        },
        {
          path: "/media/report.csv",
          compareHeaders: ["content-disposition", "x-content-type-options"],
          expectedStatus: 200,
          expectedBody: "id,name\n1,alpha\n",
          expectedHeaders: {
            "content-disposition": null,
            "x-content-type-options": "nosniff",
          },
        },
        {
          path: "/media/missing.csv?dl=missing.csv",
          compareHeaders: ["content-disposition"],
          expectedStatus: 404,
          expectedBody: "",
          expectedHeaders: {
            "content-disposition": "attachment; filename=missing.csv",
          },
        },
      ],
    });

    // Adapted from hoppscotch/hoppscotch aio-subpath-access.Caddyfile
    // (79k+ stars). Localizes the port, roots, and upstreams while preserving
    // subpath SPA serving, nested handle_path proxy routing, Host regexp
    // matcher parsing, and try_files fallback behavior. Stock Caddy does not
    // route the Host-regexp branch in these HTTP probes, so the expected
    // behavior below records the actual fallback proxy path.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: hoppscotch/hoppscotch subpath proxy SPA",
      files: {
        "selfhost-web/index.html":
          "<!doctype html><title>Hoppscotch</title><main>web</main>",
        "selfhost-web/app.js": "console.log('hoppscotch');\n",
        "sh-admin-subpath-access/index.html":
          "<!doctype html><title>Hoppscotch Admin</title><main>admin</main>",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  root * selfhost-web

  file_server

  handle_path /admin* {
    root * sh-admin-subpath-access

    file_server

    try_files {path} /
  }

  handle_path /backend* {
    @mock {
      header_regexp host Host ^[^.]+\\.mock\\..*$
    }

    handle @mock {
      rewrite * /mock{uri}

      reverse_proxy 127.0.0.1:${upstreamPort}
    }

    handle {
      reverse_proxy 127.0.0.1:${upstreamPort}
    }
  }

  handle_path /desktop-app-server* {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle {
    root * selfhost-web

    file_server

    try_files {path} /
  }
`,
      probes: [
        {
          path: "/",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Hoppscotch</title><main>web</main>",
        },
        {
          path: "/admin/",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Hoppscotch Admin</title><main>admin</main>",
        },
        {
          path: "/admin/missing/route",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Hoppscotch Admin</title><main>admin</main>",
        },
        {
          path: "/backend/status",
          headers: { Host: "api.hoppscotch.local" },
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/status:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/backend/status",
          headers: { Host: "team.mock.hoppscotch.local" },
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/status:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/desktop-app-server/sync",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/sync:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/client/route",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Hoppscotch</title><main>web</main>",
        },
      ],
    });

    // Adapted from acapela/monorepo Caddyfile (140+ stars). Localizes the
    // upstreams and frontend root while preserving overlapping handle_path
    // proxy routes, explicit rewrites, a regexp-cookie redirect, and SPA
    // fallback. The /api/backend/healthz probe asserts stock Caddy's route
    // ordering: the later exact handle_path must beat the broader
    // /api/backend/* route.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: acapela/monorepo ordered API rewrites",
      files: {
        "frontend/index.html":
          "<!doctype html><title>Acapela</title><main>app</main>",
        "frontend/assets/app.js": "console.log('acapela');\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  handle_path /graphql {
    rewrite * /v1/graphql
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle_path /api/backend/* {
    rewrite * /api{path}
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle_path /api/auth/* {
    rewrite * /api/auth/{path}
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle_path /api/backend/healthz {
    rewrite * /healthz
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle_path /attachments/* {
    rewrite * /attachments{path}
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle /sentry-tunnel {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  @return-to-app {
    path /app/return-to-app
    header_regexp login Cookie next-auth.session-token=(\\S+)
  }
  handle @return-to-app {
    redir "acapela://authorize/{re.login.1}"
  }

  handle_path /api/hooks/healthz {
    rewrite * /healthz
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle_path /api/backend/v1/linear/webhook {
    rewrite * /linear
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle_path /api/backend/v1/asana/webhook/* {
    rewrite * /asana{path}
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  handle {
    root * frontend
    file_server
    try_files {path} /index.html
  }
`,
      probes: [
        {
          path: "/graphql",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/v1/graphql:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/api/backend/users",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/api/users:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/api/backend/healthz",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/healthz:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/api/auth/session",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/api/auth//session:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/attachments/report.pdf",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/attachments/report.pdf:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/api/backend/v1/linear/webhook",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/linear:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/api/backend/v1/asana/webhook/task/42",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/asana/task/42:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/app/return-to-app",
          headers: { Cookie: "next-auth.session-token=session123" },
          redirect: "manual",
          compareHeaders: ["location"],
          expectedStatus: 302,
          expectedBody: "",
          expectedHeaders: {
            location: "acapela://authorize/session123",
          },
        },
        {
          path: "/assets/app.js",
          expectedStatus: 200,
          expectedBody: "console.log('acapela');\n",
        },
        {
          path: "/client/deep/link",
          expectedStatus: 200,
          expectedBody: "<!doctype html><title>Acapela</title><main>app</main>",
        },
      ],
    });

    // Adapted from community-scripts/ProxmoxVE install/headscale-install.sh
    // (28k+ stars), which writes a Caddyfile for Headscale. Localizes the
    // admin root and fallback upstream while preserving the admin redirect,
    // handle_path SPA fallback, encode, header, file_server, and fallback proxy
    // behavior.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: community-scripts/ProxmoxVE Headscale admin",
      files: {
        "headscale-admin/index.html":
          "<!doctype html><title>Headscale Admin</title><main>admin</main>",
        "headscale-admin/assets/app.js": "console.log('headscale-admin');\n",
      },
      upstream: true,
      site: ({ upstreamPort }) => `
  redir /admin /admin/

  handle_path /admin/* {
    root * headscale-admin
    encode gzip zstd

    header {
      X-Content-Type-Options nosniff
    }

    try_files {path} /index.html
    file_server
  }

  reverse_proxy 127.0.0.1:${upstreamPort}
`,
      probes: [
        {
          path: "/admin",
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
          expectedStatus: 302,
          expectedBody: "",
          expectedHeaders: {
            location: "/admin/",
          },
        },
        {
          path: "/admin/",
          compareHeaders: ["x-content-type-options"],
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Headscale Admin</title><main>admin</main>",
          expectedHeaders: {
            "x-content-type-options": "nosniff",
          },
        },
        {
          path: "/admin/assets/app.js",
          compareHeaders: ["x-content-type-options"],
          expectedStatus: 200,
          expectedBody: "console.log('headscale-admin');\n",
          expectedHeaders: {
            "x-content-type-options": "nosniff",
          },
        },
        {
          path: "/admin/settings/users",
          compareHeaders: ["x-content-type-options"],
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Headscale Admin</title><main>admin</main>",
          expectedHeaders: {
            "x-content-type-options": "nosniff",
          },
        },
        {
          path: "/api/v1/node",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/api/v1/node:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
      ],
    });

    // Adapted from authelia/authelia docs/content/integration/proxies/caddy.md
    // (28k+ stars). Localizes the portal, protected app, and upstreams while
    // preserving the supported Caddy integration shape: public auth portal
    // proxy, protected subpath, forward_auth URI with query parameters,
    // copied Remote-* headers, expanded request_header placeholder propagation,
    // and backend proxying.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: authelia/authelia forward auth",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  @authelia path /authelia /authelia/*
  handle @authelia {
    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  @nextcloud path /nextcloud /nextcloud/*
  handle @nextcloud {
    forward_auth 127.0.0.1:${upstreamPort} {
      uri /api/authz/forward-auth?authelia_url=http://example.test/authelia/
      copy_headers Remote-User Remote-Groups Remote-Email Remote-Name
    }

    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  @expanded path /expanded /expanded/*
  handle @expanded {
    forward_auth 127.0.0.1:${upstreamPort} {
      uri /api/authz/forward-auth?authelia_url=http://example.test/authelia/
    }

    request_header Remote-User {http.reverse_proxy.header.Remote-User}
    request_header Remote-Groups {http.reverse_proxy.header.Remote-Groups}
    request_header Remote-Email {http.reverse_proxy.header.Remote-Email}
    request_header Remote-Name {http.reverse_proxy.header.Remote-Name}

    reverse_proxy 127.0.0.1:${upstreamPort}
  }

  respond "outside" 404
`,
      probes: [
        {
          path: "/authelia/api/state",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/authelia/api/state:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/nextcloud/files/report.txt",
          compareHeaders: [
            "x-backend-token",
            "x-seen-remote-user",
            "x-seen-remote-groups",
            "x-seen-remote-email",
            "x-seen-remote-name",
          ],
          expectedStatus: 200,
          expectedBody: "/nextcloud/files/report.txt:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-remote-user": "alice",
            "x-seen-remote-groups": "admins,users",
            "x-seen-remote-email": "alice@example.test",
            "x-seen-remote-name": "Alice Example",
          },
        },
        {
          path: "/expanded/files/report.txt",
          compareHeaders: [
            "x-backend-token",
            "x-seen-remote-user",
            "x-seen-remote-groups",
            "x-seen-remote-email",
            "x-seen-remote-name",
          ],
          expectedStatus: 200,
          expectedBody: "/expanded/files/report.txt:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-remote-user": "alice",
            "x-seen-remote-groups": "admins,users",
            "x-seen-remote-email": "alice@example.test",
            "x-seen-remote-name": "Alice Example",
          },
        },
        {
          path: "/nextcloud/denied",
          expectedStatus: 401,
          expectedBody: "denied",
        },
        {
          path: "/outside",
          expectedStatus: 404,
          expectedBody: "outside",
        },
      ],
    });

    // Adapted from authelia/authelia docs/content/integration/proxies/caddy.md
    // (28k+ stars). Preserves the lower-level protected-endpoint pattern:
    // reverse_proxy rewrites the auth check to GET and a fixed URI. Caddy drops
    // the upstream request body for GET/HEAD proxy rewrites.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: authelia/authelia proxy rewrite auth check",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  reverse_proxy 127.0.0.1:${upstreamPort} {
    method GET
    rewrite "/api/authz/proxy-check?authelia_url=http://example.test/authelia/"
    header_up X-Forwarded-Method {method}
    header_up X-Forwarded-Uri {uri}
  }
`,
      probes: [
        {
          path: "/private/resource?from=client",
          method: "POST",
          body: "client request body",
          compareHeaders: [
            "x-backend-token",
            "x-seen-method",
            "x-seen-body-length",
            "x-seen-forwarded-method",
            "x-seen-forwarded-uri",
          ],
          expectedStatus: 200,
          expectedBody: "/api/authz/proxy-check:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-method": "GET",
            "x-seen-body-length": "0",
            "x-seen-forwarded-method": "POST",
            "x-seen-forwarded-uri": "/private/resource?from=client",
          },
        },
      ],
    });

    // Adapted from goauthentik/authentik
    // tests/e2e/proxy_forward_auth/caddy_single/Caddyfile (21k+ stars).
    // Localizes the outpost and app upstreams while preserving the supported
    // route-wrapped ordering: outpost path bypass, forward_auth to the outpost,
    // copied X-Authentik-* identity headers, private-range trusted proxy
    // handling, and the protected app proxy.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: goauthentik/authentik routed forward auth",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  route {
    reverse_proxy /outpost.goauthentik.io/* 127.0.0.1:${upstreamPort}

    forward_auth 127.0.0.1:${upstreamPort} {
      uri /outpost.goauthentik.io/auth/caddy
      copy_headers X-Authentik-Username X-Authentik-Groups X-Authentik-Email X-Authentik-Name X-Authentik-Uid
      trusted_proxies private_ranges
    }

    reverse_proxy 127.0.0.1:${upstreamPort}
  }
`,
      probes: [
        {
          path: "/outpost.goauthentik.io/ping",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/outpost.goauthentik.io/ping:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/app/dashboard",
          compareHeaders: [
            "x-backend-token",
            "x-seen-authentik-username",
            "x-seen-authentik-groups",
            "x-seen-authentik-email",
            "x-seen-authentik-name",
            "x-seen-authentik-uid",
          ],
          expectedStatus: 200,
          expectedBody: "/app/dashboard:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-authentik-username": "alice",
            "x-seen-authentik-groups": "admins,users",
            "x-seen-authentik-email": "alice@example.test",
            "x-seen-authentik-name": "Alice Example",
            "x-seen-authentik-uid": "user-123",
          },
        },
        {
          path: "/app/denied",
          expectedStatus: 401,
          expectedBody: "denied",
        },
      ],
    });

    // Adapted from windmill-labs/windmill Caddyfile (16k+ stars). Localizes
    // BASE_URL/upstreams and omits the custom layer4 plugin block while
    // preserving the intended supported HTTP route shape: multiple extra
    // gateway paths before the catch-all Windmill server proxy. The source
    // Caddyfile's shorthand parses as multiple upstreams in stock Caddy, so
    // this uses Caddy's equivalent named path matcher form. Test-only header_up
    // values make the selected route observable.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: windmill-labs/windmill gateway split",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  @extra path /ws/* /ws_mp/* /ws_debug/*
  reverse_proxy @extra 127.0.0.1:${upstreamPort} {
    header_up X-Upstream-Token extra
  }

  reverse_proxy /* 127.0.0.1:${upstreamPort} {
    header_up X-Upstream-Token default
  }
`,
      probes: [
        {
          path: "/ws/connect",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/ws/connect:extra",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/ws_mp/room",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/ws_mp/room:extra",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/ws_debug/session",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/ws_debug/session:extra",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/api/w/flow",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/api/w/flow:default",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/:default",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
      ],
    });

    // Adapted from railwayapp/railpack
    // core/providers/staticfile/Caddyfile.template (1k+ stars). Localizes the
    // static root and renders the template's index fallback while preserving
    // health response shape, security headers, hidden files, clean URLs,
    // directory indexes, SPA fallback, encode, and status-page error handling.
    // Stock Caddy's directive ordering lets the try_files fallback handle
    // /health in this rendered shape, so the probe records that actual index
    // response rather than the apparent respond body.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: railwayapp/railpack static template",
      files: {
        "public/index.html":
          "<!doctype html><title>Railpack</title><main>index</main>",
        "public/about.html":
          "<!doctype html><title>Railpack</title><main>about</main>",
        "public/docs/index.html":
          "<!doctype html><title>Railpack</title><main>docs</main>",
        "public/404.html":
          "<!doctype html><title>Railpack</title><main>not found</main>",
        "public/.env": "SECRET=hidden\n",
      },
      site: `
  respond /health 200

  header {
    X-XSS-Protection "1; mode=block"
    X-Content-Type-Options "nosniff"
    Referrer-Policy "strict-origin-when-cross-origin"
    Content-Security-Policy "default-src 'self'; img-src 'self' data: https: *; style-src 'self' 'unsafe-inline' https: *; script-src 'self' 'unsafe-inline' https: *; font-src 'self' data: https: *; connect-src 'self' https: *; media-src 'self' https: *; object-src 'none'; frame-src 'self' https: *;"
    -Server
  }

  root * public

  file_server {
    hide .git
    hide .env*
  }

  encode {
    gzip
    zstd
  }

  try_files {path} {path}.html {path}/index.html /index.html

  handle_errors {
    rewrite * /{err.status_code}.html
    file_server
  }
`,
      probes: [
        {
          path: "/health",
          compareHeaders: [
            "x-xss-protection",
            "x-content-type-options",
            "referrer-policy",
            "content-security-policy",
          ],
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Railpack</title><main>index</main>",
          expectedHeaders: {
            "x-xss-protection": "1; mode=block",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "content-security-policy":
              "default-src 'self'; img-src 'self' data: https: *; style-src 'self' 'unsafe-inline' https: *; script-src 'self' 'unsafe-inline' https: *; font-src 'self' data: https: *; connect-src 'self' https: *; media-src 'self' https: *; object-src 'none'; frame-src 'self' https: *;",
          },
        },
        {
          path: "/about",
          compareHeaders: ["x-content-type-options"],
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Railpack</title><main>about</main>",
          expectedHeaders: {
            "x-content-type-options": "nosniff",
          },
        },
        {
          path: "/docs",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Railpack</title><main>docs</main>",
        },
        {
          path: "/docs/",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Railpack</title><main>docs</main>",
        },
        {
          path: "/client/route",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Railpack</title><main>index</main>",
        },
        {
          path: "/.env",
          expectedStatus: 404,
          expectedBody:
            "<!doctype html><title>Railpack</title><main>not found</main>",
        },
      ],
    });

    // Adapted from remvze/moodist Caddyfile (3k+ stars). Localizes the root
    // while preserving the supported static app shape: file_server/root
    // directive ordering and a handle_errors route that serves the app shell
    // when file_server reports a missing route.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: remvze/moodist error fallback app shell",
      files: {
        "html/index.html":
          "<!doctype html><title>Moodist</title><main>app shell</main>",
        "html/assets/app.js": "console.log('moodist');\n",
      },
      site: `
  file_server
  root * html
  handle_errors {
    rewrite * /index.html
    file_server
  }
`,
      probes: [
        {
          path: "/",
          expectedStatus: 200,
          expectedBody:
            "<!doctype html><title>Moodist</title><main>app shell</main>",
        },
        {
          path: "/assets/app.js",
          expectedStatus: 200,
          expectedBody: "console.log('moodist');\n",
        },
        {
          path: "/ambient/mix",
          expectedStatus: 404,
          expectedBody:
            "<!doctype html><title>Moodist</title><main>app shell</main>",
        },
      ],
    });

    // Adapted from caddyserver/caddy issue #6422 (60k+ stars). Localizes the
    // SPA root while preserving the supported behavior: file-server misses enter
    // `handle_errors`, rewrite to the app shell, and `file_server { status 200 }`
    // serves that shell with an overridden status. The repeated probe catches
    // request-to-request consistency over the actual runtime path.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: caddyserver/caddy handle_errors status app shell",
      files: {
        "index.html": "<!doctype html><main>app shell</main>",
      },
      site: `
  root * .
  file_server

  handle_errors {
    rewrite * /
    file_server {
      status 200
    }
  }
`,
      probes: [
        {
          path: "/missing-page",
          compareHeaders: ["content-type"],
          expectedStatus: 200,
          expectedBody: "<!doctype html><main>app shell</main>",
        },
        {
          path: "/missing-page",
          compareHeaders: ["content-type"],
          expectedStatus: 200,
          expectedBody: "<!doctype html><main>app shell</main>",
        },
        {
          path: "/favicon.ico",
          compareHeaders: ["content-type"],
          expectedStatus: 200,
          expectedBody: "<!doctype html><main>app shell</main>",
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "URI strip-prefix rewrite before route matching",
      files: {},
      site: `
  uri /rewrite/* strip_prefix /rewrite
  respond /old "rewritten" 202
  respond "fallback" 404
`,
      probes: [
        {
          path: "/rewrite/old?from=test",
        },
        {
          path: "/rewrite/other",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/method_directive.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy method directive fixture",
      files: {},
      site: `
  method FOO
  respond "{http.request.method}|{http.request.orig_method}"
`,
      probes: [
        {
          path: "/method",
          expectedStatus: 200,
          expectedBody: "FOO|GET",
        },
        {
          path: "/method",
          method: "POST",
          expectedStatus: 200,
          expectedBody: "FOO|POST",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/rewrite_directive_permutations.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy rewrite explicit wildcard fixture",
      files: {},
      site: `
  rewrite * /a
  respond "{uri}"
`,
      probes: [
        {
          path: "/before?x=1",
          expectedStatus: 200,
          expectedBody: "/a?x=1",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/rewrite_directive_permutations.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy rewrite path matcher fixture",
      files: {},
      site: `
  rewrite /path /b
  respond "{uri}"
`,
      probes: [
        {
          path: "/path?x=1",
          expectedStatus: 200,
          expectedBody: "/b?x=1",
        },
        {
          path: "/other?x=1",
          expectedStatus: 200,
          expectedBody: "/other?x=1",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/rewrite_directive_permutations.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy rewrite named matcher fixture",
      files: {},
      site: `
  @named method GET
  rewrite @named /c
  respond "{uri}"
`,
      probes: [
        {
          path: "/before?x=1",
          expectedStatus: 200,
          expectedBody: "/c?x=1",
        },
        {
          path: "/before?x=1",
          method: "POST",
          expectedStatus: 200,
          expectedBody: "/before?x=1",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/rewrite_directive_permutations.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy rewrite implicit wildcard fixture",
      files: {},
      site: `
  rewrite /d
  respond "{uri}"
`,
      probes: [
        {
          path: "/before?x=1",
          expectedStatus: 200,
          expectedBody: "/d?x=1",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/root_directive_permutations.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy root directive permutations fixture",
      files: {},
      site: `
  route {
    root * /a
  }

  route {
    root /path /b
  }

  route {
    @named method GET
    root @named /c
  }

  route {
    root /d
  }

  respond "{http.vars.root}"
`,
      probes: [
        {
          path: "/other",
        },
        {
          path: "/path",
        },
        {
          path: "/path",
          method: "POST",
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/import_args_file.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file import args fixture",
      files: {
        "testdata/import_respond.txt":
          `respond /{args[0]} "'I am {args[1]}', hears {args[2]}"`,
      },
      site: `
  import testdata/import_respond.txt groot Groot Rocket
  import testdata/import_respond.txt you you "the confused man"
`,
      probes: [
        {
          path: "/groot",
          expectedStatus: 200,
          expectedBody: "'I am Groot', hears Rocket",
        },
        {
          path: "/you",
          expectedStatus: 200,
          expectedBody: "'I am you', hears the confused man",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_block_snippet.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy snippet block import fixture",
      files: {},
      prelude: `
(block_snippet) {
  header {
    {block}
  }
}
`,
      site: `
  import block_snippet {
    foo bar
  }
  respond "ok"
`,
      probes: [
        {
          path: "/snippet-block",
          compareHeaders: ["foo"],
          expectedStatus: 200,
          expectedBody: "ok",
          expectedHeaders: {
            foo: "bar",
          },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_block_snippet_args.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy direct snippet block import fixture",
      files: {},
      prelude: `
(direct_block_snippet) {
  {block}
}
`,
      site: `
  import direct_block_snippet {
    header foo bar
  }
  respond "ok"
`,
      probes: [
        {
          path: "/direct-snippet-block",
          compareHeaders: ["foo"],
          expectedStatus: 200,
          expectedBody: "ok",
          expectedHeaders: {
            foo: "bar",
          },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_block_snippet_non_replaced_block.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy unused snippet block placeholder fixture",
      files: {},
      prelude: `
(unused_block_snippet) {
  header {
    reverse_proxy localhost:3000
    {block}
  }
}
`,
      site: `
  import unused_block_snippet
  respond "ok"
`,
      probes: [
        {
          path: "/unused-snippet-block",
          compareHeaders: ["reverse-proxy"],
          expectedStatus: 200,
          expectedBody: "ok",
          expectedHeaders: {
            "reverse-proxy": null,
          },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_block_snippet_non_replaced_block_from_separate_file.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy unused imported-file snippet block placeholder fixture",
      files: {
        "snippet.conf": `
(snippet) {
  header {
    reverse_proxy localhost:3000
    {block}
  }
}
`,
      },
      prelude: `
import snippet.conf
`,
      site: `
  import snippet
  respond "ok"
`,
      probes: [
        {
          path: "/unused-file-snippet-block",
          compareHeaders: ["reverse-proxy"],
          expectedStatus: 200,
          expectedBody: "ok",
          expectedHeaders: {
            "reverse-proxy": null,
          },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_block_snippet_non_replaced_key_block.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy unused named snippet block placeholder fixture",
      files: {},
      prelude: `
(unused_named_block_snippet) {
  header {
    reverse_proxy localhost:3000
    {blocks.content_type}
  }
}
`,
      site: `
  import unused_named_block_snippet
  respond "ok"
`,
      probes: [
        {
          path: "/unused-named-snippet-block",
          compareHeaders: ["reverse-proxy"],
          expectedStatus: 200,
          expectedBody: "ok",
          expectedHeaders: {
            "reverse-proxy": null,
          },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_blocks_snippet.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy snippet named blocks import fixture",
      files: {},
      prelude: `
(blocks_snippet) {
  header {
    {blocks.foo}
  }
  header {
    {blocks.bar}
  }
}
`,
      site: `
  import blocks_snippet {
    foo {
      foo a
    }
    bar {
      bar b
    }
  }
  respond "ok"
`,
      probes: [
        {
          path: "/snippet-blocks",
          compareHeaders: ["foo", "bar"],
          expectedStatus: 200,
          expectedBody: "ok",
          expectedHeaders: {
            foo: "a",
            bar: "b",
          },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/import_blocks_snippet_nested.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy nested snippet named blocks import fixture",
      files: {},
      prelude: `
(nested_blocks_snippet) {
  header {
    {blocks.bar}
  }
  import nested_sub_snippet {
    bar {
      {blocks.foo}
    }
  }
}

(nested_sub_snippet) {
  header {
    {blocks.bar}
  }
}
`,
      site: `
  import nested_blocks_snippet {
    foo {
      foo a
    }
    bar {
      bar b
    }
  }
  respond "ok"
`,
      probes: [
        {
          path: "/snippet-nested-blocks",
          compareHeaders: ["foo", "bar"],
          expectedStatus: 200,
          expectedBody: "ok",
          expectedHeaders: {
            foo: "a",
            bar: "b",
          },
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/import_block_with_site_block.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy top-level site block import fixture",
      files: {},
      fullCaddyfile: ({ caddyPort }) =>
        `{
  admin off
  auto_https off
}

(site_import) {
  :{args[0]} {
    {block}
  }
}

import site_import ${caddyPort} {
  header X-Imported-Site yes
  respond "top-level import"
}
`,
      probes: [
        {
          path: "/top-level-import",
          compareHeaders: ["x-imported-site"],
          expectedStatus: 200,
          expectedBody: "top-level import",
          expectedHeaders: {
            "x-imported-site": "yes",
          },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/heredoc.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy heredoc fixture",
      files: {},
      site: `
  respond /heredoc <<EOF
    <html>
      <head><title>Foo</title>
      <body>Foo</body>
    </html>
    EOF 200
`,
      probes: [
        {
          path: "/heredoc",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/heredoc_extra_indentation.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy heredoc extra indentation fixture",
      files: {},
      site: `
  handle /heredoc-indent {
    respond <<END
        line1
        line2
  END
  }
`,
      probes: [
        {
          path: "/heredoc-indent",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/handle_path.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy handle_path fixture",
      files: {},
      site: `
  handle_path /api/v1/* {
    respond "API v1 {uri}"
  }
`,
      probes: [
        {
          path: "/api/v1/users?id=1",
        },
        {
          path: "/api/v2/users",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/handle_path_sorting.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy handle_path sorting fixture",
      files: {},
      site: `
  handle /api/* {
    respond "api {uri}"
  }

  handle_path /static/* {
    respond "static {uri}"
  }

  handle {
    respond "handle {uri}"
  }
`,
      probes: [
        {
          path: "/static/app.css?x=1",
        },
        {
          path: "/api/users",
        },
        {
          path: "/other",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/handle_nested_in_route.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy nested handle in route fixture",
      files: {},
      site: `
  route {
    handle /foo/* {
      respond "Foo"
    }
    handle {
      respond "Bar"
    }
  }
`,
      probes: [
        {
          path: "/foo/item",
        },
        {
          path: "/other",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/matchers_in_route.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy unused matchers in route fixture",
      files: {},
      site: `
  route {
    @matcher1 path /path1
    @matcher2 path /path2
  }
`,
      probes: [
        {
          path: "/path1",
        },
        {
          path: "/path2",
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/invoke_named_routes.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy invoke named routes fixture",
      files: {},
      prelude: `
&(first) {
  @first path /first
  vars @first first 1
  respond "first {http.vars.first}"
}

&(second) {
  respond "second"
}
`,
      site: `
  handle /first {
    invoke first
  }
  handle /second {
    invoke second
  }
  respond "no invoke"
`,
      probes: [
        {
          path: "/first",
        },
        {
          path: "/second",
        },
        {
          path: "/other",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/sort_directives_within_handle.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy nested handle directive sorting fixture",
      files: {},
      site: `
  @foo host foo.example.com
  handle @foo {
    handle_path /strip {
      respond "this should be first"
    }
    handle_path /strip* {
      respond "this should be second"
    }
    handle {
      respond "this should be last"
    }
  }
  handle {
    respond "this should be last"
  }
`,
      probes: [
        {
          path: "/strip",
          headers: { Host: "foo.example.com" },
        },
        {
          path: "/strip/more",
          headers: { Host: "foo.example.com" },
        },
        {
          path: "/other",
          headers: { Host: "foo.example.com" },
        },
        {
          path: "/strip",
          headers: { Host: "bar.example.com" },
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/site_block_sorting.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy site block sorting fixture",
      files: {},
      fullCaddyfile: ({ caddyPort }) =>
        `{
  admin off
  auto_https off
}

http://abcdef:${caddyPort} {
  respond "abcdef"
}

http://abcdefg:${caddyPort} {
  respond "abcdefg"
}

http://abc:${caddyPort} {
  respond "abc"
}

http://abcde:${caddyPort} {
  respond "abcde"
}

:${caddyPort}, http://ab:${caddyPort} {
  respond "port or ab"
}
`,
      probes: [
        {
          path: "/",
          headers: { Host: "abcdefg" },
        },
        {
          path: "/",
          headers: { Host: "abcdef" },
        },
        {
          path: "/",
          headers: { Host: "abcde" },
        },
        {
          path: "/",
          headers: { Host: "abc" },
        },
        {
          path: "/",
          headers: { Host: "ab" },
        },
        {
          path: "/",
          headers: { Host: "unknown" },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/sort_directives_with_any_matcher_first.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy matched response sorted before catch-all fixture",
      files: {},
      site: `
  respond 200

  @untrusted not remote_ip 10.1.1.0/24
  respond @untrusted 401
`,
      probes: [
        {
          path: "/sorted",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/not_block_merging.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy not block merging fixture",
      files: {},
      site: `
  @test {
    not {
      header Abc "123"
      header Bcd "123"
    }
  }
  respond @test 403
`,
      probes: [
        {
          path: "/not",
        },
        {
          path: "/not",
          headers: { Abc: "123" },
        },
        {
          path: "/not",
          headers: { Abc: "123", Bcd: "123" },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/uri_query_operations.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy uri query operations fixture",
      files: {},
      site: `
  uri query +foo bar
  uri query -baz
  uri query taz test
  uri query key=value example
  uri query changethis>changed
  uri query {
    findme value replacement
    +foo1 baz
  }

  respond "{query}"
`,
      probes: [
        {
          path: "/query?foo=orig&baz=remove&changethis=old&findme=value",
        },
        {
          path: "/query?findme=prevaluepost&other=1",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestUriReplace.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestUriReplace",
      files: {},
      site: `
  uri replace "\\}" %7D
  uri replace "\\{" %7B

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?test={%20content%20}",
          expectedStatus: 200,
          expectedBody: "test=%7B%20content%20%7D",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestUriOps.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestUriOps",
      files: {},
      site: `
  uri query +foo bar
  uri query -baz
  uri query taz test
  uri query key=value example
  uri query changethis>changed

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar0&baz=buz&taz=nottest&changethis=val",
          expectedStatus: 200,
          expectedBody:
            "changed=val&foo=bar0&foo=bar&key%3Dvalue=example&taz=test",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestSetThenAddQueryParams.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestSetThenAddQueryParams",
      files: {},
      site: `
  uri query foo bar
  uri query +foo baz

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint",
          expectedStatus: 200,
          expectedBody: "foo=bar&foo=baz",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestSetThenDeleteParams.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestSetThenDeleteParams",
      files: {},
      site: `
  uri query bar foo{query.foo}
  uri query -foo

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar",
          expectedStatus: 200,
          expectedBody: "bar=foobar",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestRenameAndOtherOps.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestRenameAndOtherOps",
      files: {},
      site: `
  uri query foo>bar
  uri query bar taz
  uri query +bar baz

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar",
          expectedStatus: 200,
          expectedBody: "bar=taz&bar=baz",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestReplaceOps.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestReplaceOps",
      files: {},
      site: `
  uri query foo bar baz

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar",
          expectedStatus: 200,
          expectedBody: "foo=baz",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestReplaceWithReplacementPlaceholder.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestReplaceWithReplacementPlaceholder",
      files: {},
      site: `
  uri query foo bar {query.placeholder}

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?placeholder=baz&foo=bar",
          expectedStatus: 200,
          expectedBody: "foo=baz&placeholder=baz",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestReplaceWithKeyPlaceholder.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestReplaceWithKeyPlaceholder",
      files: {},
      site: `
  uri query {query.placeholder} bar baz

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?placeholder=foo&foo=bar",
          expectedStatus: 200,
          expectedBody: "foo=baz&placeholder=foo",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestPartialReplacement.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestPartialReplacement",
      files: {},
      site: `
  uri query foo ar az

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar",
          expectedStatus: 200,
          expectedBody: "foo=baz",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestNonExistingSearch.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestNonExistingSearch",
      files: {},
      site: `
  uri query foo var baz

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar",
          expectedStatus: 200,
          expectedBody: "foo=bar",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestReplaceAllOps.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestReplaceAllOps",
      files: {},
      site: `
  uri query * bar baz

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar&baz=bar",
          expectedStatus: 200,
          expectedBody: "baz=baz&foo=baz",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestUriOpsBlock.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestUriOpsBlock",
      files: {},
      site: `
  uri query {
    +foo bar
    -baz
    taz test
  }

  respond "{query}"
`,
      probes: [
        {
          path: "/endpoint?foo=bar0&baz=buz&taz=nottest",
          expectedStatus: 200,
          expectedBody: "foo=bar0&foo=bar&taz=test",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/request_header.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy request_header fixture",
      files: {},
      site: `
  @matcher path /something*
  request_header @matcher Denis "Ritchie"

  request_header +Edsger "Dijkstra"
  request_header -Wolfram

  @images path /images/*
  request_header @images Cache-Control "public, max-age=3600, stale-while-revalidate=86400"

  respond "{http.request.header.Denis}|{http.request.header.Edsger}|{http.request.header.Wolfram}|{http.request.header.Cache-Control}"
`,
      probes: [
        {
          path: "/something",
          headers: { Wolfram: "Mathematica" },
          expectedStatus: 200,
          expectedBody: "Ritchie|Dijkstra||",
        },
        {
          path: "/images/logo.png",
          headers: { Wolfram: "Mathematica" },
          expectedStatus: 200,
          expectedBody:
            "|Dijkstra||public, max-age=3600, stale-while-revalidate=86400",
        },
        {
          path: "/other",
          headers: { Wolfram: "Mathematica" },
          expectedStatus: 200,
          expectedBody: "|Dijkstra||",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/header.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy header fixture",
      files: {},
      site: `
  header Denis "Ritchie"
  header +Edsger "Dijkstra"
  header ?John "von Neumann"
  header -Wolfram
  header {
    Grace: "Hopper"
    +Ray "Solomonoff"
    ?Tim "Berners-Lee"
    defer
  }
  @images path /images/*
  header @images {
    Cache-Control "public, max-age=3600, stale-while-revalidate=86400"
    match {
      status 200
    }
  }
  header {
    +Link "Foo"
    +Link "Bar"
    match status 200
  }
  header >Set Defer
  header >Replace Deferred Replacement

  respond "ok"
`,
      probes: [
        {
          path: "/other",
          compareHeaders: [
            "denis",
            "edsger",
            "john",
            "wolfram",
            "grace",
            "ray",
            "tim",
            "link",
            "set",
            "replace",
            "cache-control",
          ],
        },
        {
          path: "/images/logo.png",
          compareHeaders: [
            "denis",
            "edsger",
            "john",
            "wolfram",
            "grace",
            "ray",
            "tim",
            "link",
            "set",
            "replace",
            "cache-control",
          ],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/header_placeholder_search.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy header placeholder search fixture",
      files: {},
      site: `
  route {
    header Test-Static ":443"
    header Test-Dynamic ":{http.request.local.port}"
    header Test-Complex "port-{http.request.local.port}-end"
    header Test-Static ":443" "STATIC-WORKS"
    header Test-Dynamic ":{http.request.local.port}" "DYNAMIC-WORKS"
    header Test-Complex "port-{http.request.local.port}-end" "COMPLEX-{http.request.method}"
    respond "ok"
  }
`,
      probes: [
        {
          path: "/headers",
          compareHeaders: ["test-static", "test-dynamic", "test-complex"],
        },
        {
          path: "/headers",
          method: "POST",
          compareHeaders: ["test-static", "test-dynamic", "test-complex"],
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "try_files fallback with file_server",
      files: {
        "exact.txt": "exact bytes\n",
        "fallback.txt": "fallback bytes\n",
      },
      site: `
  root * .
  try_files {path} /fallback.txt
  file_server
`,
      probes: [
        {
          path: "/exact.txt",
          compareHeaders: ["content-type"],
        },
        {
          path: "/missing.txt",
          compareHeaders: ["content-type"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_pass_thru.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server pass_thru fixture",
      files: {
        "exact.txt": "exact bytes\n",
      },
      site: `
  root * .
  file_server {
    pass_thru
  }
  respond "fallback" 404
`,
      probes: [
        {
          path: "/exact.txt",
          compareHeaders: ["content-type"],
        },
        {
          path: "/missing.txt",
          compareHeaders: ["content-type"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_status.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server status fixture",
      files: {
        "nope.txt": "nope bytes\n",
        "custom-status.txt": "custom status bytes\n",
      },
      site: `
  root * .

  handle /nope* {
    file_server {
      status 403
    }
  }

  handle /custom-status* {
    file_server {
      status 299
    }
  }
`,
      probes: [
        {
          path: "/nope.txt",
          compareHeaders: ["content-type"],
        },
        {
          path: "/custom-status.txt",
          compareHeaders: ["content-type"],
        },
        {
          path: "/nope-missing.txt",
          compareHeaders: ["content-type"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_disable_canonical_uris.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server disable canonical URIs fixture",
      files: {
        "dir/index.html": "directory index\n",
      },
      site: `
  root * .
  file_server {
    disable_canonical_uris
  }
`,
      probes: [
        {
          path: "/dir",
          compareHeaders: ["content-type", "location"],
        },
        {
          path: "/dir/",
          compareHeaders: ["content-type", "location"],
        },
      ],
    });

    // Adapted from Caddy's modules/caddyhttp/fileserver/staticfiles_test.go::TestFileHidden.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server hide matching fixture",
      files: {
        "public/visible.txt": "visible\n",
        "public/secret.secret": "hidden basename glob\n",
        "public/private/nested.txt": "hidden descendant\n",
        "public/private-ish.txt": "visible near miss\n",
        "public/one/blocked.txt": "hidden path glob\n",
        "public/one/allowed.txt": "visible path glob near miss\n",
      },
      site: `
  root * .
  file_server {
    hide *.secret public/private public/*/blocked.txt
  }
`,
      probes: [
        {
          path: "/public/visible.txt",
          compareHeaders: ["content-type"],
        },
        {
          path: "/public/secret.secret",
        },
        {
          path: "/public/private/nested.txt",
        },
        {
          path: "/public/private-ish.txt",
          compareHeaders: ["content-type"],
        },
        {
          path: "/public/one/blocked.txt",
        },
        {
          path: "/public/one/allowed.txt",
          compareHeaders: ["content-type"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_etag_file_extensions.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server etag file extensions fixture",
      files: {
        "asset.txt": "etag body\n",
        "asset.txt.b3sum": "alpha-sidecar",
        "asset.txt.sha256": "beta-sidecar",
      },
      site: `
  root * .
  file_server {
    etag_file_extensions .b3sum .sha256
  }
`,
      probes: [
        {
          path: "/asset.txt",
          compareHeaders: ["content-type", "etag"],
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "Caddy file_server ETag preconditions fixture",
      files: {
        "asset.txt": "etag precondition body\n",
        "asset.txt.etag": "stable-sidecar",
      },
      site: `
  root * .
  file_server {
    etag_file_extensions .etag
  }
`,
      probes: [
        {
          path: "/asset.txt",
          headers: { "If-None-Match": `"stable-sidecar"` },
          compareHeaders: ["etag", "last-modified", "content-length"],
        },
        {
          path: "/asset.txt",
          headers: { "If-None-Match": `"other-sidecar"` },
          compareHeaders: ["etag", "last-modified", "content-length"],
        },
        {
          path: "/asset.txt",
          headers: { "If-Match": `"other-sidecar"` },
          compareHeaders: ["etag", "last-modified", "content-length"],
          compareBody: false,
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_precompressed.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server precompressed explicit order fixture",
      files: {
        "asset.txt": "plain body\n",
        "asset.txt.zst": new TextEncoder().encode("zstd sidecar"),
        "asset.txt.br": new TextEncoder().encode("br sidecar"),
        "asset.txt.gz": new TextEncoder().encode("gzip sidecar"),
      },
      site: `
  root * .
  file_server {
    precompressed zstd br gzip
  }
`,
      probes: [
        {
          path: "/asset.txt",
          headers: { "Accept-Encoding": "gzip, br, zstd" },
          compareHeaders: ["content-encoding", "content-type"],
          compareBody: false,
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_precompressed.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server precompressed default order fixture",
      files: {
        "asset.txt": "plain body\n",
        "asset.txt.zst": new TextEncoder().encode("zstd sidecar"),
        "asset.txt.br": new TextEncoder().encode("br sidecar"),
        "asset.txt.gz": new TextEncoder().encode("gzip sidecar"),
      },
      site: `
  root * .
  file_server {
    precompressed
  }
`,
      probes: [
        {
          path: "/asset.txt",
          headers: { "Accept-Encoding": "gzip, br, zstd" },
          compareHeaders: ["content-encoding", "content-type"],
          compareBody: false,
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_sort.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server browse sort fixture",
      files: {
        "public/small.txt": "a",
        "public/medium.txt": "abcd",
        "public/large.txt": "abcdefgh",
      },
      site: `
  root * public
  file_server {
    browse {
      sort size desc
    }
  }
`,
      probes: [
        {
          path: "/",
          headers: { Accept: "application/json" },
          compareHeaders: ["content-type"],
          normalizeBrowseJson: true,
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/file_server_file_limit.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy file_server browse file_limit fixture",
      files: {
        "public/a.txt": "a",
        "public/b.txt": "b",
        "public/c.txt": "c",
      },
      site: `
  root * public
  file_server {
    browse {
      file_limit 2
    }
  }
`,
      probes: [
        {
          path: "/",
          headers: { Accept: "application/json" },
          compareHeaders: ["content-type"],
          normalizeBrowseCount: true,
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/map_test.go::TestMap.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestMap",
      files: {},
      site: `
  map {http.request.method} {dest-1} {dest-2} {
    default unknown1 unknown2
    ~G(.)(.) G\${1}\${2}-called
    POST post-called foobar
  }

  respond /version 200 {
    body "hello from localhost {dest-1} {dest-2}"
  }
`,
      probes: [
        {
          path: "/version",
        },
        {
          path: "/version",
          method: "POST",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/map_test.go::TestMapRespondWithDefault.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestMapRespondWithDefault",
      files: {},
      site: `
  map {http.request.method} {dest-name} {
    default unknown
    GET get-called
  }

  respond /version 200 {
    body "hello from localhost {dest-name}"
  }
`,
      probes: [
        {
          path: "/version",
        },
        {
          path: "/version",
          method: "POST",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/map_and_vars_with_raw_types.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy map and vars raw types fixture",
      files: {},
      site: `
  map {host} {my_placeholder} {magic_number} {
    example.com true 3
    foo.example.com "string value"
    (.*)\\.example.com "\${1} subdomain" "5"
    ~.*\\.net$ - \`7\`
    ~.*\\.xyz$ 123.456 "false"
    default "unknown domain" \\\\""
  }

  vars foo bar
  vars {
    abc true
    def 1
    ghi 2.3
    jkl "mn op"
  }

  respond "{my_placeholder}|{magic_number}|{http.vars.foo}|{http.vars.abc}|{http.vars.def}|{http.vars.ghi}|{http.vars.jkl}"
`,
      probes: [
        {
          path: "/map",
          headers: { Host: "example.com" },
        },
        {
          path: "/map",
          headers: { Host: "foo.example.com" },
        },
        {
          path: "/map",
          headers: { Host: "bar.example.com" },
        },
        {
          path: "/map",
          headers: { Host: "thing.net" },
        },
        {
          path: "/map",
          headers: { Host: "thing.xyz" },
        },
        {
          path: "/map",
          headers: { Host: "other.test" },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/request_body.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy request_body max_size fixture",
      files: {},
      site: `
  request_body {
    max_size 8
  }
  respond "accepted"
`,
      probes: [
        {
          path: "/upload",
          method: "POST",
          body: "12345678",
        },
        {
          path: "/upload",
          method: "POST",
          body: "123456789",
          compareBody: false,
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "Caddy encode gzip and zstd fixture",
      files: {},
      site: `
  encode gzip zstd {
    minimum_length 1
    match {
      status 200
    }
  }
  header /notransform Cache-Control "no-transform"
  respond /encoded "compressible response"
  respond /zstd "zstd compressible response"
  respond /created "created response" 201
  respond /notransform "do not transform"
  respond /identity "identity response"
`,
      probes: [
        {
          path: "/encoded",
          rawHost: "localhost",
          headers: { "Accept-Encoding": "gzip" },
          compareHeaders: ["content-encoding", "vary"],
          compareBody: false,
          expectedStatus: 200,
          expectedBody: "",
          expectedHeaders: {
            "content-encoding": "gzip",
            vary: "Accept-Encoding",
          },
        },
        {
          path: "/zstd",
          rawHost: "localhost",
          headers: { "Accept-Encoding": "zstd" },
          compareHeaders: ["content-encoding", "vary"],
          compareBody: false,
          expectedStatus: 200,
          expectedBody: "",
          expectedHeaders: {
            "content-encoding": "zstd",
            vary: "Accept-Encoding",
          },
        },
        {
          path: "/created",
          rawHost: "localhost",
          headers: { "Accept-Encoding": "gzip" },
          compareHeaders: ["content-encoding", "vary"],
          expectedStatus: 201,
          expectedBody: "created response",
          expectedHeaders: {
            "content-encoding": null,
            vary: null,
          },
        },
        {
          path: "/notransform",
          rawHost: "localhost",
          headers: { "Accept-Encoding": "gzip" },
          compareHeaders: ["cache-control", "content-encoding", "vary"],
          expectedStatus: 200,
          expectedBody: "do not transform",
          expectedHeaders: {
            "cache-control": "no-transform",
            "content-encoding": null,
            vary: null,
          },
        },
        {
          path: "/identity",
          headers: { "Accept-Encoding": "identity" },
          compareHeaders: ["content-encoding", "vary"],
          expectedStatus: 200,
          expectedBody: "identity response",
          expectedHeaders: {
            "content-encoding": null,
            vary: null,
          },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/sort_vars_in_reverse.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy vars route sorting fixture",
      files: {},
      site: `
  vars /foobar foo last
  vars /foo foo middle-last
  vars /foo* foo middle-first
  vars * foo first
  respond "{http.vars.foo}"
`,
      probes: [
        {
          path: "/other",
          expectedStatus: 200,
          expectedBody: "first",
        },
        {
          path: "/foo/bar",
          expectedStatus: 200,
          expectedBody: "middle-first",
        },
        {
          path: "/foo",
          expectedStatus: 200,
          expectedBody: "middle-last",
        },
        {
          path: "/foobar",
          expectedStatus: 200,
          expectedBody: "last",
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "reverse proxy request and response headers",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  reverse_proxy /proxy-* 127.0.0.1:${upstreamPort} {
    header_up X-Upstream-Token compared
    header_down X-Downstream-Token proxied
  }
  respond "fallback" 404
`,
      probes: [
        {
          path: "/proxy-ok",
          compareHeaders: ["x-backend-token", "x-downstream-token"],
          expectedStatus: 404,
          expectedBody: "fallback",
          expectedHeaders: {
            "x-backend-token": null,
            "x-downstream-token": null,
          },
        },
        {
          path: "/proxy-created",
          compareHeaders: ["x-backend-token", "x-downstream-token"],
          expectedStatus: 404,
          expectedBody: "fallback",
          expectedHeaders: {
            "x-backend-token": null,
            "x-downstream-token": null,
          },
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "Caddy reverse_proxy connection failure without handle_errors",
      files: {},
      site: `
  reverse_proxy 127.0.0.1:9
`,
      probes: [
        {
          path: "/proxy-down",
          expectedStatus: 502,
          expectedBody: "",
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/reverse_proxy_handle_response.caddyfiletest,
    // limited to status replacement and response-header placeholders because
    // zeroserve intentionally does not implement Caddy response body replacement.
    await compareGeneratedCaddyfile({
      name: "Caddy reverse_proxy response matcher status fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  reverse_proxy /proxy-* 127.0.0.1:${upstreamPort} {
    @backend {
      status 2xx
      header X-Backend-Token backend
    }
    replace_status @backend 203
    header_down X-Upstream-Status {http.reverse_proxy.status_code}
    header_down X-Upstream-Token {http.reverse_proxy.header.X-Backend-Token}
  }
  respond "fallback" 404
`,
      probes: [
        {
          path: "/proxy-ok",
          compareHeaders: [
            "x-backend-token",
            "x-upstream-status",
            "x-upstream-token",
          ],
          expectedStatus: 404,
          expectedBody: "fallback",
          expectedHeaders: {
            "x-backend-token": null,
            "x-upstream-status": null,
            "x-upstream-token": null,
          },
        },
        {
          path: "/proxy-created",
          compareHeaders: [
            "x-backend-token",
            "x-upstream-status",
            "x-upstream-token",
          ],
          expectedStatus: 404,
          expectedBody: "fallback",
          expectedHeaders: {
            "x-backend-token": null,
            "x-upstream-status": null,
            "x-upstream-token": null,
          },
        },
        {
          path: "/other",
          compareHeaders: [
            "x-backend-token",
            "x-upstream-status",
            "x-upstream-token",
          ],
          expectedStatus: 404,
          expectedBody: "fallback",
          expectedHeaders: {
            "x-backend-token": null,
            "x-upstream-status": null,
            "x-upstream-token": null,
          },
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/reverse_proxy_upstream_placeholder.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy reverse_proxy upstream placeholder fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  map {host} {upstream} {
    alpha.example.test 127.0.0.1:${upstreamPort}
    default 127.0.0.1:${upstreamPort}
  }

  @proxied host alpha.example.test beta.example.test
  reverse_proxy @proxied {upstream} {
    header_up X-Upstream-Token placeholder
  }

  redir * http://fallback.example.test{uri}
`,
      probes: [
        {
          path: "/proxy-ok",
          headers: { Host: "alpha.example.test" },
          redirect: "manual",
          compareHeaders: ["x-backend-token", "location"],
          compareBody: false,
          expectedStatus: 302,
          expectedBody: "",
          expectedHeaders: {
            "x-backend-token": null,
            location: "http://fallback.example.test/proxy-ok",
          },
        },
        {
          path: "/proxy-created",
          headers: { Host: "beta.example.test" },
          redirect: "manual",
          compareHeaders: ["x-backend-token", "location"],
          compareBody: false,
          expectedStatus: 302,
          expectedBody: "",
          expectedHeaders: {
            "x-backend-token": null,
            location: "http://fallback.example.test/proxy-created",
          },
        },
        {
          path: "/proxy-ok",
          headers: { Host: "gamma.example.test" },
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
          expectedStatus: 302,
          expectedBody: "",
          expectedHeaders: {
            location: "http://fallback.example.test/proxy-ok",
          },
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/replaceable_upstream.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy reverse_proxy replaceable upstream fixture",
      files: {},
      upstream: true,
      site: () => `
  @targetUpstream {
    header_regexp target X-Upstream ^(.+)$
  }
  handle @targetUpstream {
    reverse_proxy {re.target.1}
  }
  handle {
    redir {scheme}://application.localhost
  }
`,
      probes: ({ upstreamPort }): Probe[] => [
        {
          path: "/proxy-ok",
          headers: { "X-Upstream": `127.0.0.1:${upstreamPort}` },
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/proxy-ok:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
        {
          path: "/proxy-ok",
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
          expectedStatus: 302,
          expectedBody: "",
          expectedHeaders: {
            location: "http://application.localhost",
          },
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "Caddy reverse_proxy transport tuning ignored fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  reverse_proxy 127.0.0.1:${upstreamPort} {
    transport http {
      read_timeout 10m
      write_timeout 10m
      dial_timeout 10m
      response_header_timeout 10m
      expect_continue_timeout 10m
      keepalive 2m
      keepalive_interval 30s
      keepalive_idle_conns 10
      keepalive_idle_conns_per_host 5
      max_conns_per_host 20
    }
  }
`,
      probes: [
        {
          path: "/proxy-ok",
          compareHeaders: ["x-backend-token"],
          expectedStatus: 200,
          expectedBody: "/proxy-ok:",
          expectedHeaders: {
            "x-backend-token": "backend",
          },
        },
      ],
      expectedCompileWarnings: [
        "ignoring reverse_proxy.transport.read_timeout",
        "ignoring reverse_proxy.transport.write_timeout",
        "ignoring reverse_proxy.transport.dial_timeout",
        "ignoring reverse_proxy.transport.response_header_timeout",
        "ignoring reverse_proxy.transport.expect_continue_timeout",
        "ignoring reverse_proxy.transport.keep_alive",
        "ignoring reverse_proxy.transport.max_conns_per_host",
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/replaceable_upstream_port.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy reverse_proxy placeholder port fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  @sandboxPort {
    header_regexp port Host ^port-([0-9]+)\\.sandbox\\.
  }
  handle @sandboxPort {
    reverse_proxy 127.0.0.1:{re.port.1}
  }
  handle {
    redir {scheme}://application.localhost
  }
`,
      probes: ({ upstreamPort }): Probe[] => [
        {
          path: "/proxy-ok",
          headers: { Host: `port-${upstreamPort}.sandbox.localhost` },
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
          expectedStatus: 302,
          expectedBody: "",
          expectedHeaders: {
            location: "http://application.localhost",
          },
        },
        {
          path: "/proxy-ok",
          headers: { Host: "application.localhost" },
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
          expectedStatus: 302,
          expectedBody: "",
          expectedHeaders: {
            location: "http://application.localhost",
          },
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/replaceable_upstream_partial_port.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy reverse_proxy partial placeholder port fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => {
        const port = String(upstreamPort);
        return `
  @sandboxPort {
    header_regexp port Host ^port-${port.slice(1)}\\.sandbox\\.
  }
  handle @sandboxPort {
    reverse_proxy 127.0.0.1:${port[0]}{re.port.0}
  }
  handle {
    redir {scheme}://application.localhost
  }
`;
      },
      probes: ({ upstreamPort }): Probe[] => [
        {
          path: "/proxy-ok",
          headers: {
            Host: `port-${String(upstreamPort).slice(1)}.sandbox.localhost`,
          },
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
          expectedStatus: 302,
          expectedBody: "",
          expectedHeaders: {
            location: "http://application.localhost",
          },
        },
        {
          path: "/proxy-ok",
          headers: { Host: "application.localhost" },
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
          expectedStatus: 302,
          expectedBody: "",
          expectedHeaders: {
            location: "http://application.localhost",
          },
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/forward_auth_copy_headers_strip.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy forward_auth copied headers fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  forward_auth 127.0.0.1:${upstreamPort} {
    uri /auth
    copy_headers X-User-Id X-Empty-Auth
  }
  reverse_proxy 127.0.0.1:${upstreamPort}
`,
      probes: [
        {
          path: "/allowed",
          compareHeaders: ["x-backend-token", "x-seen-user"],
          expectedStatus: 200,
          expectedBody: "/allowed:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-user": "alice",
          },
        },
        {
          path: "/denied",
          compareHeaders: ["x-backend-token", "x-seen-user"],
          expectedStatus: 401,
          expectedBody: "denied",
          expectedHeaders: {
            "x-backend-token": null,
            "x-seen-user": null,
          },
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/forward_auth_rename_headers.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy forward_auth renamed headers fixture",
      files: {},
      upstream: true,
      site: ({ upstreamPort }) => `
  forward_auth 127.0.0.1:${upstreamPort} {
    uri /auth
    copy_headers X-User-Id>X-Auth-User X-Role
  }
  reverse_proxy 127.0.0.1:${upstreamPort}
`,
      probes: [
        {
          path: "/allowed",
          compareHeaders: [
            "x-backend-token",
            "x-seen-auth-user",
            "x-seen-role",
          ],
          expectedStatus: 200,
          expectedBody: "/allowed:",
          expectedHeaders: {
            "x-backend-token": "backend",
            "x-seen-auth-user": "alice",
            "x-seen-role": "admin",
          },
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/intercept_test.go, limited to
    // header-only response hooks because zeroserve intentionally does not
    // rewrite response bodies for Caddy compatibility.
    await compareGeneratedCaddyfile({
      name: "Caddy intercept header response hook fixture",
      files: {},
      site: `
  respond /intercept "tea" 408
  header /intercept To-Intercept ok
  respond /no-intercept "no"

  intercept {
    @teapot status 408
    handle_response @teapot {
      header /intercept Intercepted {http.intercept.header.To-Intercept}
    }
  }
`,
      probes: [
        {
          path: "/intercept",
          compareHeaders: ["to-intercept", "intercepted"],
          expectedStatus: 408,
          expectedBody: "tea",
          expectedHeaders: {
            "to-intercept": "ok",
            intercepted: "ok",
          },
        },
        {
          path: "/no-intercept",
          compareHeaders: ["intercepted"],
          expectedStatus: 200,
          expectedBody: "no",
          expectedHeaders: {
            intercepted: null,
          },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/shorthand_parameterized_placeholders.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy shorthand parameterized placeholders fixture",
      files: {},
      site: `
  @match path_regexp ^/foo(.*)$
  respond @match "{re.1}"

  respond * "{header.content-type} {labels.0} {query.p} {path.0} {re.name.0}"
`,
      probes: [
        {
          path: "/foo-rest?p=value",
          headers: { "Content-Type": "text/plain", Host: "localhost" },
          expectedStatus: 200,
          expectedBody: "-rest",
        },
        {
          path: "/one/two?p=value",
          headers: {
            "Content-Type": "application/json",
            Host: "www.example.test",
          },
          expectedStatus: 200,
          expectedBody: "application/json 1 value one {http.regexp.name.0}",
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "basic auth challenge and user placeholder",
      files: {},
      site: `
  basic_auth /admin/* bcrypt "Admin Area" {
    alice $2a$14$gqs5yvNgSqb/ksrUoam91ewSE1TjpYIgCuaiuZH395DQEPsiCVIei
  }
  respond /admin/* "hello {http.auth.user.id}"
  respond "public"
`,
      probes: [
        {
          path: "/admin/panel",
          compareHeaders: ["www-authenticate"],
          expectedStatus: 401,
          expectedHeaders: {
            "www-authenticate": `Basic realm="Admin Area"`,
          },
        },
        {
          path: "/admin/panel",
          headers: {
            Authorization: `Basic ${btoa("alice:wrong")}`,
          },
          compareHeaders: ["www-authenticate"],
          expectedStatus: 401,
          expectedHeaders: {
            "www-authenticate": `Basic realm="Admin Area"`,
          },
        },
        {
          path: "/admin/panel",
          headers: {
            Authorization: `Basic ${btoa("alice:secret")}`,
          },
          compareHeaders: ["www-authenticate"],
          expectedStatus: 200,
          expectedBody: "hello alice",
          expectedHeaders: {
            "www-authenticate": null,
          },
        },
        {
          path: "/public",
          expectedStatus: 200,
          expectedBody: "public",
        },
      ],
    });

    // Uses Caddy's modules/caddyhttp/caddyauth/argon2id.go FakeHash fixture.
    await compareGeneratedCaddyfile({
      name: "Caddy basic_auth argon2id fixture",
      files: {},
      site: `
  basic_auth /argon/* argon2id "Argon Area" {
    alice $argon2id$v=19$m=47104,t=1,p=1$P2nzckEdTZ3bxCiBCkRTyA$xQL3Z32eo5jKl7u5tcIsnEKObYiyNZQQf5/4sAau6Pg
  }
  respond /argon/* "argon {http.auth.user.id}"
  respond "public"
`,
      probes: [
        {
          path: "/argon/panel",
          compareHeaders: ["www-authenticate"],
          expectedStatus: 401,
          expectedHeaders: {
            "www-authenticate": `Basic realm="Argon Area"`,
          },
        },
        {
          path: "/argon/panel",
          headers: {
            Authorization: `Basic ${btoa("alice:wrong")}`,
          },
          compareHeaders: ["www-authenticate"],
          expectedStatus: 401,
          expectedHeaders: {
            "www-authenticate": `Basic realm="Argon Area"`,
          },
        },
        {
          path: "/argon/panel",
          headers: {
            Authorization: `Basic ${btoa("alice:antitiming")}`,
          },
          compareHeaders: ["www-authenticate"],
          expectedStatus: 200,
          expectedBody: "argon alice",
          expectedHeaders: {
            "www-authenticate": null,
          },
        },
        {
          path: "/public",
          expectedStatus: 200,
          expectedBody: "public",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestRedirect.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestRedirect",
      files: {},
      site: `
  redir / /hello 301
  respond /hello 200 {
    body "hello from localhost"
  }
`,
      probes: [
        {
          path: "/",
          redirect: "manual",
          compareHeaders: ["location"],
          compareBody: false,
        },
        {
          path: "/",
          redirect: "follow",
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "redirect location and html body",
      files: {},
      site: `
  redir /go/* https://example.test{uri} permanent
  redir /html https://example.org/a?b=<tag> html
  respond "fallback"
`,
      probes: [
        {
          path: "/go/path?x=1",
          compareHeaders: ["location"],
        },
        {
          path: "/html",
          compareHeaders: ["content-type", "location"],
        },
        {
          path: "/other",
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/wildcard_pattern.caddyfiletest,
    // limited to HTTP host routing because TLS automation is outside zeroserve's eBPF surface.
    await compareGeneratedCaddyfile({
      name: "Caddy wildcard host routing fixture",
      files: {},
      fullCaddyfile: ({ caddyPort }) =>
        `{
  admin off
  auto_https off
}

http://*.example.test:${caddyPort} {
  @foo host foo.example.test
  handle @foo {
    respond "Foo!"
  }

  @bar host bar.example.test
  handle @bar {
    respond "Bar!"
  }

  handle {
    respond "Fallback" 404
  }
}
`,
      probes: [
        {
          path: "/",
          headers: { Host: "foo.example.test" },
        },
        {
          path: "/",
          headers: { Host: "bar.example.test" },
        },
        {
          path: "/",
          headers: { Host: "baz.example.test" },
        },
        {
          path: "/",
          headers: { Host: "outside.test" },
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/http_only_hostnames.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy HTTP wildcard hostname fixture",
      files: {},
      fullCaddyfile: ({ caddyPort }) =>
        `{
  admin off
  auto_https off
}

http://*:${caddyPort} {
  respond "Hello, world!"
}
`,
      probes: [
        {
          path: "/",
          headers: { Host: "alpha.example.test" },
        },
        {
          path: "/",
          headers: { Host: "beta.localhost" },
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "named matchers and regexp placeholders",
      files: {},
      site: `
  @api {
    path_regexp item ^/api/items/([0-9]+)$
    method POST
    query mode=debug
    header X-Mode debug
  }
  respond @api "item {http.regexp.item.1}" 202
  respond "fallback" 404
`,
      probes: [
        {
          path: "/api/items/42?mode=debug",
          method: "POST",
          headers: { "X-Mode": "debug" },
        },
        {
          path: "/api/items/42?mode=release",
          method: "POST",
          headers: { "X-Mode": "debug" },
        },
        {
          path: "/api/items/42?mode=debug",
          method: "GET",
          headers: { "X-Mode": "debug" },
        },
        {
          path: "/api/items/not-number?mode=debug",
          method: "POST",
          headers: { "X-Mode": "debug" },
        },
      ],
    });

    // Adapted from Caddy's caddytest/integration/caddyfile_adapt/expression_quotes.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy expression quote forms fixture",
      files: {},
      site: `
  @a expression {http.request.method} == "POST"
  respond @a "double quoted string"

  @c expression "{http.request.method} == \\"DELETE\\""
  respond @c "double quoted expression"

  @d expression \`{http.request.method} == "PATCH"\`
  respond @d "backtick quoted expression"

  @e \`{http.request.method} == "OPTIONS"\`
  respond @e "shorthand backtick expression"

  respond "fallback" 404
`,
      probes: [
        {
          path: "/quotes",
          method: "POST",
        },
        {
          path: "/quotes",
          method: "DELETE",
        },
        {
          path: "/quotes",
          method: "PATCH",
        },
        {
          path: "/quotes",
          method: "OPTIONS",
        },
        {
          path: "/quotes",
          method: "GET",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/matcher_syntax.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy matcher syntax vars and expressions fixture",
      files: {},
      site: `
  @matcher4 vars "{http.request.uri}" "/vars-matcher"
  respond @matcher4 "from vars matcher"

  @matcher5 vars_regexp static "{http.request.uri}" \`\\.([a-f0-9]{6})\\.(css|js)$\`
  respond @matcher5 "from vars_regexp matcher with name"

  @matcher6 vars_regexp "{http.request.uri}" \`\\.([a-f0-9]{6})\\.(css|js)$\`
  respond @matcher6 "from vars_regexp matcher without name"

  @matcher7 \`path('/foo*') && method('GET')\`
  respond @matcher7 "inline expression matcher shortcut"

  respond "fallback" 404
`,
      probes: [
        {
          path: "/vars-matcher",
          method: "PUT",
        },
        {
          path: "/app.abcdef.css",
          method: "PUT",
        },
        {
          path: "/app.123456.js",
          method: "POST",
        },
        {
          path: "/foo-item",
        },
        {
          path: "/foo-item",
          method: "POST",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/matcher_syntax.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy matcher syntax merged fields fixture",
      files: {},
      site: `
  @matcher8 {
    header Foo bar
    header Foo foobar
    header Bar foo
  }
  respond @matcher8 "header matcher merging values of the same field"

  @matcher9 {
    query foo=bar foo=baz bar=foo
    query bar=baz
  }
  respond @matcher9 "query matcher merging pairs with the same keys"

  @matcher10 {
    header !Foo
    header Bar foo
  }
  respond @matcher10 "header matcher with null field matcher"

  respond "fallback" 404
`,
      probes: [
        {
          path: "/headers",
          headers: { Foo: "bar", Bar: "foo" },
        },
        {
          path: "/headers",
          headers: { Foo: "foobar", Bar: "foo" },
        },
        {
          path: "/headers",
          headers: { Foo: "nope", Bar: "foo" },
        },
        {
          path: "/query?foo=bar&bar=baz",
        },
        {
          path: "/query?foo=baz&bar=foo",
        },
        {
          path: "/query?foo=nope&bar=foo",
        },
        {
          path: "/null-header",
          headers: { Bar: "foo" },
        },
        {
          path: "/null-header",
          headers: { Foo: "bar", Bar: "foo" },
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "deferred response headers inspect file responses",
      files: {
        "asset.txt": "asset bytes\n",
      },
      site: `
  root * .
  header {
    match {
      status 2xx
      header Content-Type text/plain*
    }
    X-Text-File yes
  }
  header {
    match status 404
    X-Not-Found yes
  }
  file_server
`,
      probes: [
        {
          path: "/asset.txt",
          compareHeaders: ["content-type", "x-text-file", "x-not-found"],
        },
        {
          path: "/missing.txt",
          compareHeaders: ["content-type", "x-text-file", "x-not-found"],
        },
      ],
    });

    // Adapted from caddyserver/caddy issue #3804 (60k+ stars). Localizes the
    // proposed default-header pattern while preserving the supported behavior:
    // `?Cache-Control` is deferred, fills in a missing response header, and
    // leaves an already-set response header alone.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: caddyserver/caddy default response header",
      files: {
        "asset.txt": "asset bytes\n",
      },
      site: `
  root * .

  header ?Cache-Control "no-store"

  handle /explicit {
    header Cache-Control "public, max-age=60"
    respond "explicit"
  }

  file_server
`,
      probes: [
        {
          path: "/asset.txt",
          compareHeaders: ["cache-control"],
          expectedStatus: 200,
          expectedBody: "asset bytes\n",
          expectedHeaders: {
            "cache-control": "no-store",
          },
        },
        {
          path: "/explicit",
          compareHeaders: ["cache-control"],
          expectedStatus: 200,
          expectedBody: "explicit",
          expectedHeaders: {
            "cache-control": "public, max-age=60",
          },
        },
      ],
    });

    // Adapted from caddyserver/caddy issue #7598 (60k+ stars). Localizes the
    // reported shape while preserving the supported behavior: a site-level
    // `header` block is retained alongside `handle` routes, and a scoped
    // `header` inside a `handle` applies only to that branch.
    await compareGeneratedCaddyfile({
      name: "wild Caddyfile: caddyserver/caddy headers with handle blocks",
      files: {
        "index.html": "<!doctype html><main>home</main>",
      },
      site: `
  header {
    X-Frame-Options DENY
    X-Content-Type-Options nosniff
  }

  handle /api/* {
    header X-Api-Route yes
    respond "api"
  }

  handle {
    root * .
    file_server
  }
`,
      probes: [
        {
          path: "/api/users",
          compareHeaders: [
            "x-frame-options",
            "x-content-type-options",
            "x-api-route",
          ],
          expectedStatus: 200,
          expectedBody: "api",
          expectedHeaders: {
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "x-api-route": "yes",
          },
        },
        {
          path: "/",
          compareHeaders: [
            "x-frame-options",
            "x-content-type-options",
            "x-api-route",
          ],
          expectedStatus: 200,
          expectedBody: "<!doctype html><main>home</main>",
          expectedHeaders: {
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "x-api-route": null,
          },
        },
      ],
    });

    await compareGeneratedCaddyfile({
      name: "file server misses run handle_errors routes",
      files: {
        "asset.txt": "asset bytes\n",
      },
      site: `
  root * .
  header {
    match status 404
    X-Outer-404 outer
  }
  file_server
  handle_errors {
    header X-Error-Status {err.status_code}
    respond "handled {err.status_code} {err.status_text}" {err.status_code}
  }
`,
      probes: [
        {
          path: "/asset.txt",
          compareHeaders: ["content-type", "x-error-status", "x-outer-404"],
        },
        {
          path: "/missing.txt",
          compareHeaders: ["content-type", "x-error-status", "x-outer-404"],
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestHandleErrorSimpleCodes.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestHandleErrorSimpleCodes",
      files: {},
      site: `
  error /private* "Unauthorized" 410
  error /hidden* "Not found" 404

  handle_errors 404 410 {
    respond "404 or 410 error"
  }
`,
      probes: [
        {
          path: "/private",
        },
        {
          path: "/hidden",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestHandleErrorRange.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestHandleErrorRange",
      files: {},
      site: `
  error /private* "Unauthorized" 410
  error /hidden* "Not found" 404

  handle_errors 4xx {
    respond "Error in the [400 .. 499] range"
  }
`,
      probes: [
        {
          path: "/private",
        },
        {
          path: "/hidden",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestHandleErrorSort.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestHandleErrorSort",
      files: {},
      site: `
  error /private* "Unauthorized" 410
  error /hidden* "Not found" 404
  error /internalerr* "Internal Server Error" 500

  handle_errors {
    respond "Fallback route: code outside the [400..499] range"
  }
  handle_errors 4xx {
    respond "Error in the [400 .. 499] range"
  }
`,
      probes: [
        {
          path: "/internalerr",
        },
        {
          path: "/hidden",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestHandleErrorRangeAndCodes.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestHandleErrorRangeAndCodes",
      files: {},
      site: `
  error /private* "Unauthorized" 410
  error /threehundred* "Moved Permanently" 301
  error /internalerr* "Internal Server Error" 500

  handle_errors 500 3xx {
    respond "Error code is equal to 500 or in the [300..399] range"
  }
  handle_errors 4xx {
    respond "Error in the [400 .. 499] range"
  }
`,
      probes: [
        {
          path: "/internalerr",
        },
        {
          path: "/threehundred",
        },
        {
          path: "/private",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_test.go::TestHandleErrorSubHandlers.
    await compareGeneratedCaddyfile({
      name: "Caddy integration TestHandleErrorSubHandlers",
      files: {},
      site: `
  error /*/internalerr* "Internal Server Error" 500

  handle_errors 404 {
    handle /en/* {
      respond "not found" 404
    }
    handle /es/* {
      respond "no encontrado" 404
    }
    handle {
      respond "default not found"
    }
  }
  handle_errors {
    handle {
      respond "Default error"
    }
    handle /en/* {
      respond "English error"
    }
  }
`,
      probes: [
        {
          path: "/en/notfound",
        },
        {
          path: "/es/notfound",
        },
        {
          path: "/notfound",
        },
        {
          path: "/es/internalerr",
        },
        {
          path: "/en/internalerr",
        },
      ],
    });

    // Ported from Caddy's caddytest/integration/caddyfile_adapt/error_multi_site_blocks.caddyfiletest.
    await compareGeneratedCaddyfile({
      name: "Caddy error routes across multiple site blocks fixture",
      files: {},
      fullCaddyfile: ({ caddyPort }) =>
        `{
  admin off
  auto_https off
}

http://foo.localhost:${caddyPort} {
  error /private* "Unauthorized" 410
  error /fivehundred* "Internal Server Error" 500

  handle_errors 5xx {
    respond "Error In range [500 .. 599]"
  }
  handle_errors 410 {
    respond "404 or 410 error"
  }
}

http://bar.localhost:${caddyPort} {
  error /private* "Unauthorized" 410
  error /fivehundred* "Internal Server Error" 500

  handle_errors 5xx {
    respond "Error In range [500 .. 599] from second site"
  }
  handle_errors 410 {
    respond "404 or 410 error from second site"
  }
}
`,
      probes: [
        {
          path: "/private",
          headers: { Host: "foo.localhost" },
        },
        {
          path: "/fivehundred",
          headers: { Host: "foo.localhost" },
        },
        {
          path: "/private",
          headers: { Host: "bar.localhost" },
        },
        {
          path: "/fivehundred",
          headers: { Host: "bar.localhost" },
        },
      ],
    });

    // Single byte-range and 416 semantics, matched against Go's
    // net/http.ServeContent (which Caddy's file server delegates to). The ETag
    // value itself is intentionally not compared: zeroserve derives tarball
    // ETags from content, while Caddy derives them from mtime+size.
    {
      const rangeHeaders = [
        "content-range",
        "content-length",
        "content-type",
        "accept-ranges",
        "x-content-type-options",
      ];
      await compareGeneratedCaddyfile({
        name: "Caddy file_server single byte-range semantics",
        files: {
          "asset.txt": "0123456789abcdefghijKLMNOPQRST", // 30 bytes
          "empty.txt": "",
        },
        site: `
  root * .
  file_server
`,
        probes: [
          { path: "/asset.txt", headers: { Range: "bytes=0-9" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=5-" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=-5" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=-0" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=-100" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=20-100" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=0-0" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=0-29" }, compareHeaders: rangeHeaders },
          // Unsatisfiable: start at/after EOF -> 416 with "bytes */N".
          { path: "/asset.txt", headers: { Range: "bytes=30-" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=40-50" }, compareHeaders: rangeHeaders },
          // Malformed: 416 "invalid range" with no Content-Range.
          { path: "/asset.txt", headers: { Range: "bytes=5-3" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=abc" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "items=0-4" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=-" }, compareHeaders: rangeHeaders },
          // Empty spec is ignored -> full 200.
          { path: "/asset.txt", headers: { Range: "bytes=" }, compareHeaders: rangeHeaders },
          // Comma lists that reduce to a single satisfiable range.
          { path: "/asset.txt", headers: { Range: "bytes=0-4," }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=,0-4" }, compareHeaders: rangeHeaders },
          { path: "/asset.txt", headers: { Range: "bytes=0-4,40-50" }, compareHeaders: rangeHeaders },
          // Empty file: explicit range ignored (200), suffix yields empty 206.
          { path: "/empty.txt", headers: { Range: "bytes=0-9" }, compareHeaders: rangeHeaders },
          { path: "/empty.txt", headers: { Range: "bytes=-5" }, compareHeaders: rangeHeaders },
          {
            path: "/asset.txt",
            method: "HEAD",
            headers: { Range: "bytes=0-9" },
            compareHeaders: rangeHeaders,
            compareBody: false,
          },
        ],
      });

      // Conditional request semantics (If-Match / If-None-Match /
      // If-Modified-Since / If-Unmodified-Since / If-Range). Probes avoid
      // depending on the ETag value (only `*` and a deliberately-wrong tag are
      // used); date probes deliberately carry an incorrect weekday to confirm
      // zeroserve, like Go, ignores the weekday rather than rejecting the date.
      await compareGeneratedCaddyfile({
        name: "Caddy file_server conditional request semantics",
        files: {
          "asset.txt": "0123456789abcdefghijKLMNOPQRST",
        },
        site: `
  root * .
  file_server
`,
        probes: [
          // 304: no Content-Type/Content-Length, and no Last-Modified (ETag wins).
          {
            path: "/asset.txt",
            headers: { "If-None-Match": "*" },
            compareHeaders: ["content-type", "content-length", "last-modified"],
          },
          { path: "/asset.txt", headers: { "If-None-Match": `"nope"` } },
          {
            path: "/asset.txt",
            headers: { "If-Modified-Since": "Mon, 21 Oct 2099 07:28:00 GMT" },
            compareHeaders: ["content-type", "content-length", "last-modified"],
          },
          { path: "/asset.txt", headers: { "If-Modified-Since": "Mon, 21 Oct 1995 07:28:00 GMT" } },
          // 412 keeps Content-Type and Last-Modified (Go reaches it via a bare
          // WriteHeader). The 1995 date carries a wrong weekday on purpose.
          {
            path: "/asset.txt",
            headers: { "If-Unmodified-Since": "Mon, 21 Oct 1995 07:28:00 GMT" },
            compareHeaders: ["content-type", "last-modified"],
          },
          { path: "/asset.txt", headers: { "If-Unmodified-Since": "Mon, 21 Oct 2099 07:28:00 GMT" } },
          { path: "/asset.txt", headers: { "If-Match": "*" } },
          {
            path: "/asset.txt",
            headers: { "If-Match": `"nope"` },
            compareHeaders: ["content-type", "last-modified"],
          },
          // If-Range mismatch (tag or non-matching date) drops the range -> 200.
          {
            path: "/asset.txt",
            headers: { Range: "bytes=0-9", "If-Range": `"nope"` },
            compareHeaders: ["content-range", "content-length", "accept-ranges"],
          },
          {
            path: "/asset.txt",
            headers: {
              Range: "bytes=0-9",
              "If-Range": "Mon, 21 Oct 2099 07:28:00 GMT",
            },
            compareHeaders: ["content-range", "content-length", "accept-ranges"],
          },
        ],
      });
    }
  },
});

for (const compiler of ["tcc", "clang"]) {
  Deno.test({
    name:
      `e2e: Caddyfile static region analysis matches stock Caddy (${compiler})`,
    ignore: !canRunScripts || !canRunCaddy,
    async fn() {
      const siteDir = await Deno.makeTempDir();
      let caddy: { origin: string; stop: () => Promise<void> } | null = null;
      try {
        const caddyPort = await getFreePort();
        const caddyfilePath = join(siteDir, "Caddyfile");
        await Deno.writeTextFile(
          caddyfilePath,
          `{
  admin off
  auto_https off
}

:${caddyPort} {
  header /analysis X-Static-Region required
  respond /analysis "static analysis ok" 202
  respond "not found" 404
}
`,
        );

        caddy = await withCaddy(siteDir, caddyfilePath, caddyPort);
        const probes: Probe[] = [
          {
            path: "/analysis",
            compareHeaders: ["x-static-region"],
            expectedStatus: 202,
            expectedBody: "static analysis ok",
            expectedHeaders: { "x-static-region": "required" },
          },
          {
            path: "/missing",
            expectedStatus: 404,
            expectedBody: "not found",
          },
        ];

        const zeroserve = await spawnZeroserve([
          "--ebpf-compiler",
          compiler,
          "--ebpf-require-static-region-analysis",
          "--caddy",
          caddyfilePath,
        ]);
        try {
          const zeroserveOrigin = `http://127.0.0.1:${zeroserve.httpPort}`;
          for (const probe of probes) {
            const caddyObserved = await fetchObserved(caddy, probe);
            const zeroserveObserved = await fetchObserved(
              zeroserveOrigin,
              probe,
            );
            assertEquals(
              zeroserveObserved,
              caddyObserved,
              `${compiler}: ${probeLabel("static region analysis", probe)}`,
            );
            assertExpectedResponse(
              caddyObserved,
              probe,
              `${compiler} static region analysis`,
            );
          }
        } finally {
          await zeroserve.stop();
        }
      } finally {
        if (caddy !== null) {
          await caddy.stop();
        }
        await Deno.remove(siteDir, { recursive: true }).catch(() => {});
      }
    },
  });
}

Deno.test({
  name: "e2e: Caddyfile explicit TLS certificates match stock Caddy",
  ignore: !canRunScripts || !canRunCaddyTls,
  async fn() {
    const siteDir = await Deno.makeTempDir();
    const cert = await generateSelfSignedCert();
    let caddy: { origin: string; stop: () => Promise<void> } | null = null;
    let zeroserve: { origin: string; stop: () => Promise<void> } | null = null;
    try {
      const caddyPort = await getFreePort();
      const zeroservePort = await getFreePort();
      const caddyfilePath = join(siteDir, "Caddyfile");
      await Deno.writeTextFile(
        caddyfilePath,
        `{
  admin off
  auto_https off
}

https://localhost:${caddyPort} {
  tls ${cert.certPath} ${cert.keyPath}
  header X-Compat explicit-tls
  respond /tls "tls ok" 203
}
`,
      );

      caddy = await withCaddyRef(caddyTlsRef, siteDir, caddyfilePath, caddyPort);

      const zeroserveCaddyfilePath = join(siteDir, "Zeroserve.Caddyfile");
      await Deno.writeTextFile(
        zeroserveCaddyfilePath,
        `{
  admin off
  auto_https off
}

https://localhost:${zeroservePort} {
  tls ${cert.certPath} ${cert.keyPath}
  header X-Compat explicit-tls
  respond /tls "tls ok" 203
}
`,
      );
      zeroserve = await withZeroserveCaddyTls(
        zeroserveCaddyfilePath,
        zeroservePort,
      );

      const client = Deno.createHttpClient({
        caCerts: [await Deno.readTextFile(cert.certPath)],
        http2: true,
      });
      try {
        const probe: Probe = {
          path: "/tls",
          compareHeaders: ["x-compat", "content-type", "content-length"],
        };
        const caddyObserved = await fetchObserved(caddy, probe, client);
        const zeroserveObserved = await fetchObserved(zeroserve, probe, client);
        assertEquals(zeroserveObserved, caddyObserved);
        assertExpectedResponse(caddyObserved, {
          ...probe,
          expectedStatus: 203,
          expectedBody: "tls ok",
          expectedHeaders: {
            "x-compat": "explicit-tls",
            "content-type": "text/plain; charset=utf-8",
            "content-length": "6",
          },
        }, "explicit TLS certificate Caddyfile");
      } finally {
        client.close();
      }
    } finally {
      if (zeroserve !== null) {
        await zeroserve.stop();
      }
      if (caddy !== null) {
        await caddy.stop();
      }
      await cert.cleanup();
      await Deno.remove(siteDir, { recursive: true }).catch(() => {});
    }
  },
});

async function compareGeneratedCaddyfile(
  caseDef: GeneratedCase,
): Promise<void> {
  const siteDir = await Deno.makeTempDir();
  let tarPath: string | null = null;
  let upstream: { port: number; stop: () => Promise<void> } | null = null;
  try {
    await Deno.mkdir(join(siteDir, ".zeroserve", "scripts"), {
      recursive: true,
    });
    for (const [path, contents] of Object.entries(caseDef.files)) {
      const filePath = join(siteDir, path);
      await Deno.mkdir(dirname(filePath), { recursive: true });
      if (typeof contents === "string") {
        await Deno.writeTextFile(filePath, contents);
      } else {
        await Deno.writeFile(filePath, contents);
      }
    }

    const caddyPort = await getFreePort();
    if (caseDef.upstream) {
      upstream = await withUpstream();
    }
    const caddyfile = buildGeneratedCaddyfile(caseDef, {
      caddyPort,
      upstreamPort: upstream?.port ?? 0,
    });
    const caddyfilePath = join(siteDir, "Caddyfile");
    await Deno.writeTextFile(caddyfilePath, caddyfile);
    await writeCompiledCaddyMiddleware(siteDir, caddyfilePath, caseDef);

    tarPath = await packSite(siteDir);
    const caddyBaseUrl = await withCaddy(siteDir, caddyfilePath, caddyPort);
    try {
      await withZeroserve(tarPath, async (zeroserveBaseUrl) => {
        const probes = typeof caseDef.probes === "function"
          ? caseDef.probes({ caddyPort, upstreamPort: upstream?.port ?? 0 })
          : caseDef.probes;
        for (const probe of probes) {
          const caddy = await fetchObserved(caddyBaseUrl, probe);
          const zeroserve = await fetchObserved(zeroserveBaseUrl, probe);
          assertEquals(
            zeroserve,
            caddy,
            probeLabel(caseDef.name, probe),
          );
          assertExpectedResponse(caddy, probe, caseDef.name);
        }
      });
    } finally {
      await caddyBaseUrl.stop();
    }
  } finally {
    if (tarPath !== null) {
      await Deno.remove(tarPath).catch(() => {});
    }
    if (upstream !== null) {
      await upstream.stop();
    }
    await Deno.remove(siteDir, { recursive: true }).catch(() => {});
  }
}

function assertExpectedResponse(
  observed: ObservedResponse,
  probe: Probe,
  caseName: string,
): void {
  const label = probeLabel(caseName, probe);
  if (probe.expectedStatus !== undefined) {
    assertEquals(observed.status, probe.expectedStatus, `${label}: status`);
  }
  if (probe.expectedBody !== undefined) {
    assertEquals(observed.body, probe.expectedBody, `${label}: body`);
  }
  for (const [name, value] of Object.entries(probe.expectedHeaders ?? {})) {
    assertEquals(observed.headers[name], value, `${label}: header ${name}`);
  }
}

function probeLabel(caseName: string, probe: Probe): string {
  const headers = probe.headers === undefined
    ? ""
    : ` headers=${JSON.stringify(probe.headers)}`;
  return `${caseName}: ${probe.method ?? "GET"} ${probe.path}${headers}`;
}

function buildGeneratedCaddyfile(
  caseDef: GeneratedCase,
  ctx: { caddyPort: number; upstreamPort: number },
): string {
  if (caseDef.fullCaddyfile !== undefined) {
    return typeof caseDef.fullCaddyfile === "function"
      ? caseDef.fullCaddyfile(ctx)
      : caseDef.fullCaddyfile;
  }
  if (caseDef.site === undefined) {
    throw new Error(`${caseDef.name}: generated case requires site`);
  }
  const site = typeof caseDef.site === "function"
    ? caseDef.site({ upstreamPort: ctx.upstreamPort })
    : caseDef.site;
  return `{
  admin off
  auto_https off
}

${caseDef.prelude ?? ""}
:${ctx.caddyPort} {
${site}}
`;
}

async function writeCompiledCaddyMiddleware(
  siteDir: string,
  caddyfilePath: string,
  caseDef: GeneratedCase,
): Promise<void> {
  const zeroservePath = await getZeroservePath();
  const compiled = await new Deno.Command(zeroservePath, {
    args: ["--caddy-compile", caddyfilePath],
    cwd: repoRoot,
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (!compiled.success) {
    throw new Error(decoder.decode(compiled.stderr));
  }
  const stderr = decoder.decode(compiled.stderr);
  for (const expected of caseDef.expectedCompileWarnings ?? []) {
    if (!stderr.includes(expected)) {
      throw new Error(
        `${caseDef.name}: expected compile warning containing ${
          JSON.stringify(expected)
        }, got:\n${stderr}`,
      );
    }
  }
  await Deno.writeFile(
    join(siteDir, ".zeroserve", "scripts", "caddy.c"),
    compiled.stdout,
  );
}

async function withCaddy(
  siteDir: string,
  caddyfilePath: string,
  port: number,
): Promise<{ origin: string; stop: () => Promise<void> }> {
  const child = new Deno.Command(caddyBin, {
    args: ["run", "--config", caddyfilePath, "--adapter", "caddyfile"],
    cwd: siteDir,
    stdin: "null",
    stdout: "null",
    stderr: "inherit",
  }).spawn();
  const statusPromise = child.status;
  await waitForServer("127.0.0.1", port, statusPromise);
  return {
    origin: `http://127.0.0.1:${port}`,
    stop: () => stopProcess(child, statusPromise),
  };
}

async function withCaddyRef(
  caddyRef: string,
  siteDir: string,
  caddyfilePath: string,
  port: number,
): Promise<{ origin: string; stop: () => Promise<void> }> {
  const spec = await caddyCommandSpec(caddyRef, [
    "run",
    "--config",
    caddyfilePath,
    "--adapter",
    "caddyfile",
  ]);
  const child = new Deno.Command(spec.command, {
    args: spec.args,
    cwd: spec.cwd ?? siteDir,
    stdin: "null",
    stdout: "null",
    stderr: "inherit",
  }).spawn();
  const statusPromise = child.status;
  await waitForServer("127.0.0.1", port, statusPromise);
  return {
    origin: `https://localhost:${port}`,
    stop: () => stopProcess(child, statusPromise),
  };
}

async function withZeroserveCaddyTls(
  caddyfilePath: string,
  tlsPort: number,
): Promise<{ origin: string; stop: () => Promise<void> }> {
  const zeroservePath = await getZeroservePath();
  const child = new Deno.Command(zeroservePath, {
    args: [
      "--addr",
      "127.0.0.1:0",
      "--tls-addr",
      `127.0.0.1:${tlsPort}`,
      "--caddy",
      caddyfilePath,
    ],
    cwd: repoRoot,
    stdin: "null",
    stdout: "null",
    stderr: "inherit",
  }).spawn();
  const statusPromise = child.status;
  await waitForServer("127.0.0.1", tlsPort, statusPromise);
  return {
    origin: `https://localhost:${tlsPort}`,
    stop: () => stopProcess(child, statusPromise),
  };
}

async function fetchObserved(
  server: { origin: string } | string,
  probe: Probe,
  client?: Deno.HttpClient,
): Promise<ObservedResponse> {
  const origin = typeof server === "string" ? server : server.origin;
  if (probe.rawHost !== undefined) {
    return await fetchObservedRaw(origin, probe);
  }
  const res = await fetch(`${origin}${probe.path}`, {
    client,
    method: probe.method ?? "GET",
    headers: probe.headers,
    body: probe.body,
    redirect: probe.redirect ?? "manual",
  });
  const headers: Record<string, string | null> = {};
  for (const name of probe.compareHeaders ?? []) {
    headers[name] = res.headers.get(name);
  }
  let body = "";
  if (probe.compareBody === false) {
    // The body must still be consumed: leaving the stream open trips the
    // test sanitizer ("a fetch response body was created but not consumed").
    await res.body?.cancel();
  } else {
    body = normalizeBody(await res.text(), probe);
  }
  return {
    status: res.status,
    body,
    headers,
  };
}

async function fetchObservedRaw(
  origin: string,
  probe: Probe,
): Promise<ObservedResponse> {
  const url = new URL(origin);
  const conn = await Deno.connect({
    hostname: url.hostname,
    port: Number(url.port),
  });
  try {
    const body = typeof probe.body === "string"
      ? new TextEncoder().encode(probe.body)
      : probe.body instanceof Uint8Array
      ? probe.body
      : new Uint8Array();
    const lines = [
      `${probe.method ?? "GET"} ${probe.path} HTTP/1.1`,
      `Host: ${probe.rawHost}`,
      "Connection: close",
    ];
    for (const [name, value] of Object.entries(probe.headers ?? {})) {
      if (name.toLowerCase() !== "host") {
        lines.push(`${name}: ${value}`);
      }
    }
    if (body.length > 0) {
      lines.push(`Content-Length: ${body.length}`);
    }
    const head = new TextEncoder().encode(`${lines.join("\r\n")}\r\n\r\n`);
    await conn.write(head);
    if (body.length > 0) {
      await conn.write(body);
    }

    return parseRawObservedResponse(await readRawResponse(conn), probe);
  } finally {
    conn.close();
  }
}

async function readRawResponse(conn: Deno.Conn): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  const buf = new Uint8Array(8192);
  while (true) {
    const timeoutMs = chunks.length === 0 ? 5_000 : 500;
    const n = await Promise.race([
      conn.read(buf),
      new Promise<"timeout">((resolve) =>
        setTimeout(() => resolve("timeout"), timeoutMs)
      ),
    ]);
    if (n === "timeout") {
      if (chunks.length === 0) {
        throw new Error("timed out waiting for raw HTTP response");
      }
      return concatBytes(chunks);
    }
    if (n === null) {
      return concatBytes(chunks);
    }
    chunks.push(buf.slice(0, n));
    const raw = concatBytes(chunks);
    if (rawResponseComplete(raw)) {
      return raw;
    }
  }
}

function rawResponseComplete(raw: Uint8Array): boolean {
  const parsed = parseRawHeaders(raw);
  if (parsed === undefined) {
    return false;
  }
  const transferEncoding = parsed.headers.get("transfer-encoding")
    ?.toLowerCase();
  if (transferEncoding === "chunked") {
    return chunkedBodyComplete(raw.slice(parsed.bodyStart));
  }
  const contentLength = Number(parsed.headers.get("content-length"));
  if (Number.isInteger(contentLength) && contentLength >= 0) {
    return raw.length >= parsed.bodyStart + contentLength;
  }
  return false;
}

function parseRawHeaders(
  raw: Uint8Array,
):
  | { statusLine: string; headers: Map<string, string>; bodyStart: number }
  | undefined {
  const text = new TextDecoder().decode(raw);
  const headerEnd = text.indexOf("\r\n\r\n");
  if (headerEnd < 0) {
    return undefined;
  }
  const headerText = text.slice(0, headerEnd);
  const bodyStart = new TextEncoder().encode(text.slice(0, headerEnd + 4))
    .length;
  const [statusLine, ...headerLines] = headerText.split("\r\n");
  const headers = new Map<string, string>();
  for (const line of headerLines) {
    const sep = line.indexOf(":");
    if (sep < 0) {
      continue;
    }
    headers.set(
      line.slice(0, sep).trim().toLowerCase(),
      line.slice(sep + 1).trim(),
    );
  }
  return { statusLine, headers, bodyStart };
}

function parseRawObservedResponse(
  raw: Uint8Array,
  probe: Probe,
): ObservedResponse {
  const parsed = parseRawHeaders(raw);
  if (parsed === undefined) {
    throw new Error("raw HTTP response missing header terminator");
  }
  const status = Number(parsed.statusLine.split(/\s+/, 3)[1]);
  const bodyBytes = parsed.headers.get("transfer-encoding")?.toLowerCase() ===
      "chunked"
    ? decodeChunkedBody(raw.slice(parsed.bodyStart))
    : raw.slice(parsed.bodyStart);
  const headers: Record<string, string | null> = {};
  for (const name of probe.compareHeaders ?? []) {
    headers[name] = parsed.headers.get(name.toLowerCase()) ?? null;
  }
  return {
    status,
    body: probe.compareBody === false
      ? ""
      : normalizeBody(new TextDecoder().decode(bodyBytes), probe),
    headers,
  };
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const len = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function decodeChunkedBody(body: Uint8Array): Uint8Array {
  const chunks: Uint8Array[] = [];
  let offset = 0;
  while (offset < body.length) {
    const lineEnd = findCrlf(body, offset);
    if (lineEnd < 0) {
      break;
    }
    const line = new TextDecoder().decode(body.slice(offset, lineEnd));
    const size = Number.parseInt(line.split(";", 1)[0].trim(), 16);
    offset = lineEnd + 2;
    if (size === 0) {
      break;
    }
    chunks.push(body.slice(offset, offset + size));
    offset += size + 2;
  }
  return concatBytes(chunks);
}

function chunkedBodyComplete(body: Uint8Array): boolean {
  let offset = 0;
  while (offset < body.length) {
    const lineEnd = findCrlf(body, offset);
    if (lineEnd < 0) {
      return false;
    }
    const line = new TextDecoder().decode(body.slice(offset, lineEnd));
    const size = Number.parseInt(line.split(";", 1)[0].trim(), 16);
    if (!Number.isFinite(size) || size < 0) {
      return false;
    }
    offset = lineEnd + 2;
    if (size === 0) {
      return findCrlf(body, offset) >= 0;
    }
    offset += size;
    if (
      offset + 2 > body.length || body[offset] !== 13 || body[offset + 1] !== 10
    ) {
      return false;
    }
    offset += 2;
  }
  return false;
}

function findCrlf(buf: Uint8Array, start: number): number {
  for (let i = start; i + 1 < buf.length; i++) {
    if (buf[i] === 13 && buf[i + 1] === 10) {
      return i;
    }
  }
  return -1;
}

function normalizeBody(body: string, probe: Probe): string {
  if (probe.normalizeBrowseCount) {
    const listing = JSON.parse(body) as unknown[];
    return `entries:${listing.length}`;
  }
  if (!probe.normalizeBrowseJson) {
    return body;
  }
  const listing = JSON.parse(body) as Array<{ name: string; size: number }>;
  return JSON.stringify(listing.map((item) => `${item.name}:${item.size}`));
}

async function withUpstream(): Promise<{
  port: number;
  stop: () => Promise<void>;
}> {
  const controller = new AbortController();
  let port = 0;
  const server = Deno.serve({
    hostname: "127.0.0.1",
    port: 0,
    signal: controller.signal,
    onListen: ({ port: listenPort }) => {
      port = listenPort;
    },
  }, async (req) => {
    let bodyLength = 0;
    if (req.body !== null) {
      bodyLength = (await req.arrayBuffer()).byteLength;
    }
    const url = new URL(req.url);
    if (
      url.pathname === "/auth" || url.pathname === "/auth/" ||
      url.pathname === "/api/authz/forward-auth" ||
      url.pathname === "/outpost.goauthentik.io/auth/caddy"
    ) {
      const originalUri = req.headers.get("x-forwarded-uri") ?? "";
      if (originalUri.includes("denied")) {
        return new Response("denied", { status: 401 });
      }
      return new Response(null, {
        status: 204,
        headers: {
          "X-User-Id": "alice",
          "X-Role": "admin",
          "X-Empty-Auth": "",
          "Remote-User": "alice",
          "Remote-Groups": "admins,users",
          "Remote-Email": "alice@example.test",
          "Remote-Name": "Alice Example",
          "X-Authentik-Username": "alice",
          "X-Authentik-Groups": "admins,users",
          "X-Authentik-Email": "alice@example.test",
          "X-Authentik-Name": "Alice Example",
          "X-Authentik-Uid": "user-123",
        },
      });
    }
    const headers = new Headers({
      "X-Backend-Token": "backend",
      "X-Seen-Method": req.method,
      "X-Seen-Body-Length": String(bodyLength),
      "X-Seen-Host": req.headers.get("host") ?? "",
      "X-Seen-User": req.headers.get("x-user-id") ?? "",
      "X-Seen-Auth-User": req.headers.get("x-auth-user") ?? "",
      "X-Seen-Role": req.headers.get("x-role") ?? "",
      "X-Seen-Forwarded-Method": req.headers.get("x-forwarded-method") ?? "",
      "X-Seen-Forwarded-Uri": req.headers.get("x-forwarded-uri") ?? "",
      "X-Seen-Forwarded-Proto": req.headers.get("x-forwarded-proto") ?? "",
      "X-Seen-Forwarded-Host": req.headers.get("x-forwarded-host") ?? "",
      "X-Seen-Forwarded-For": req.headers.get("x-forwarded-for") ?? "",
      "X-Seen-Forwarded-Port": req.headers.get("x-forwarded-port") ?? "",
      "X-Seen-Forwarded-Prefix": req.headers.get("x-forwarded-prefix") ?? "",
      "X-Seen-Real-IP": req.headers.get("x-real-ip") ?? "",
      "X-Seen-Accept-Encoding": req.headers.get("accept-encoding") ?? "",
      "X-Seen-Origin": req.headers.get("origin") ?? "",
      "X-Seen-Referer": req.headers.get("referer") ?? "",
      "X-Seen-Remote-User": req.headers.get("remote-user") ?? "",
      "X-Seen-Remote-Groups": req.headers.get("remote-groups") ?? "",
      "X-Seen-Remote-Email": req.headers.get("remote-email") ?? "",
      "X-Seen-Remote-Name": req.headers.get("remote-name") ?? "",
      "X-Seen-Authentik-Username": req.headers.get("x-authentik-username") ??
        "",
      "X-Seen-Authentik-Groups": req.headers.get("x-authentik-groups") ?? "",
      "X-Seen-Authentik-Email": req.headers.get("x-authentik-email") ?? "",
      "X-Seen-Authentik-Name": req.headers.get("x-authentik-name") ?? "",
      "X-Seen-Authentik-Uid": req.headers.get("x-authentik-uid") ?? "",
      "Access-Control-Allow-Origin": "https://upstream.local",
    });
    if (url.pathname.startsWith("/wetty/")) {
      headers.set("Content-Security-Policy", "default-src 'self'");
      headers.set("Strict-Transport-Security", "max-age=31536000");
      headers.set("Cross-Origin-Opener-Policy", "same-origin");
      headers.set("Cross-Origin-Resource-Policy", "same-origin");
    }
    if (url.pathname === "/cookie") {
      headers.set("Set-Cookie", "sid=abc; Domain=backend.example; Path=/");
    }
    const status = url.pathname === "/proxy-created" ? 201 : 200;
    return new Response(
      `${url.pathname}:${req.headers.get("x-upstream-token") ?? ""}`,
      { status, headers },
    );
  });

  if (port === 0) {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  if (port === 0) {
    controller.abort();
    await server.finished;
    throw new Error("failed to start upstream");
  }

  return {
    port,
    stop: async () => {
      controller.abort();
      await server.finished;
    },
  };
}

async function hasCommand(command: string): Promise<boolean> {
  try {
    const output = await new Deno.Command(command, {
      args: ["version"],
      stdout: "null",
      stderr: "null",
    }).output();
    return output.success;
  } catch (err) {
    if (err instanceof Deno.errors.NotFound) {
      return false;
    }
    throw err;
  }
}

type CommandSpec = {
  command: string;
  args: string[];
  cwd?: string;
};

async function caddyCommandSpec(
  caddyRef: string,
  args: string[],
): Promise<CommandSpec> {
  try {
    const stat = await Deno.stat(caddyRef);
    if (stat.isDirectory) {
      return {
        command: "go",
        args: ["-C", caddyRef, "run", "./cmd/caddy", ...args],
      };
    }
  } catch (err) {
    if (!(err instanceof Deno.errors.NotFound)) {
      throw err;
    }
  }
  return { command: caddyRef, args };
}

async function hasCaddyRunner(caddyRef: string): Promise<boolean> {
  const spec = await caddyCommandSpec(caddyRef, ["version"]);
  try {
    const output = await new Deno.Command(spec.command, {
      args: spec.args,
      cwd: spec.cwd,
      stdout: "null",
      stderr: "null",
    }).output();
    return output.success;
  } catch (err) {
    if (err instanceof Deno.errors.NotFound) {
      return false;
    }
    throw err;
  }
}
