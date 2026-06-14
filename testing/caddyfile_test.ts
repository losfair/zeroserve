import { assertEquals, assertStringIncludes } from "@std/assert";
import { join } from "@std/path";
import { getZeroservePath } from "./test_utils.ts";

async function adapt(caddyfile: string): Promise<string> {
  const dir = await Deno.makeTempDir();
  const path = join(dir, "Caddyfile");
  await Deno.writeTextFile(path, caddyfile);
  try {
    const zeroservePath = await getZeroservePath();
    const out = await new Deno.Command(zeroservePath, {
      args: ["--adapt-caddyfile", path],
      stdout: "piped",
      stderr: "piped",
    }).output();
    if (!out.success) {
      throw new Error(new TextDecoder().decode(out.stderr));
    }
    return new TextDecoder().decode(out.stdout);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}

async function compile(config: string, name: string): Promise<string> {
  const dir = await Deno.makeTempDir();
  const path = join(dir, name);
  await Deno.writeTextFile(path, config);
  try {
    const zeroservePath = await getZeroservePath();
    const out = await new Deno.Command(zeroservePath, {
      args: ["--caddy-compile", path],
      stdout: "piped",
      stderr: "piped",
    }).output();
    if (!out.success) {
      throw new Error(new TextDecoder().decode(out.stderr));
    }
    return new TextDecoder().decode(out.stdout);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}

async function compileErr(config: string, name: string): Promise<string> {
  const dir = await Deno.makeTempDir();
  const path = join(dir, name);
  await Deno.writeTextFile(path, config);
  try {
    const zeroservePath = await getZeroservePath();
    const out = await new Deno.Command(zeroservePath, {
      args: ["--caddy-compile", path],
      stdout: "piped",
      stderr: "piped",
    }).output();
    if (out.success) {
      throw new Error("expected caddy-compile to fail");
    }
    return new TextDecoder().decode(out.stderr);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
}

Deno.test("adapt a Caddyfile to Caddy JSON", async () => {
  const json = JSON.parse(await adapt(`example.com {
  respond /api/* "api" 200
  respond "fallback" 404
}`));
  const routes = json.apps.http.servers.srv0.routes;
  assertEquals(routes.length, 1);
  assertEquals(routes[0].match[0].host, ["example.com"]);
  const inner = routes[0].handle[0].routes;
  // /api/* is more specific, sorted first.
  assertEquals(inner[0].match[0].path, ["/api/*"]);
  assertEquals(inner[0].handle[0].handler, "static_response");
  assertEquals(inner[0].handle[0].status_code, 200);
});

Deno.test("caddy-compile auto-detects a Caddyfile", async () => {
  const c = await compile(
    `example.com {\n  respond "hi" 200\n}`,
    "Caddyfile",
  );
  // Produces the same eBPF middleware as the equivalent JSON config.
  assertStringIncludes(c, "zs_caddy_respond_static(\"200\"");
});

Deno.test("caddy-compile still accepts Caddy JSON", async () => {
  const config = JSON.stringify({
    apps: {
      http: {
        servers: {
          srv0: {
            routes: [{
              handle: [{
                handler: "static_response",
                status_code: 200,
                body: "ok",
              }],
            }],
          },
        },
      },
    },
  });
  const c = await compile(config, "config.json");
  assertStringIncludes(c, "zs_caddy_respond_static(\"200\"");
});

Deno.test("caddy-compile rejects response-only reverse_proxy handle_response", async () => {
  const err = await compileErr(
    `example.com {
  reverse_proxy 127.0.0.1:8080 {
    @ok {
      status 2xx
      header X-Origin ok*
    }
    handle_response @ok {
      copy_response_headers {
        include X-Origin
      }
      header X-Matched yes
    }
    replace_status @ok 299
  }
}`,
    "Caddyfile",
  );
  assertStringIncludes(
    err,
    "reverse_proxy.handle_response routes suppress upstream response bodies",
  );
});

Deno.test("caddy-compile adapts forward_auth copy_headers", async () => {
  const c = await compile(
    `example.com {
  forward_auth /private/* 127.0.0.1:9091 {
    uri /auth
    copy_headers Remote-User
  }
  respond ok
}`,
    "Caddyfile",
  );
  assertStringIncludes(c, "zs_reverse_proxy(");
  assertStringIncludes(c, "ZS_CALL_ENTRY(caddy_response_");
  assertStringIncludes(c, "zs_req_delete_header(\"Remote-User\"");
  assertStringIncludes(c, "zs_req_set_header(\"Remote-User\"");
  assertStringIncludes(c, "zs_res_continue_request();");
  assertStringIncludes(c, "zs.caddy.reverse_proxy.skip.");
});

Deno.test("caddy-compile adapts try_files", async () => {
  const c = await compile(
    `example.com {
  try_files {path} /index.php?{query}&p={path} {
    policy first_exist_fallback
  }
}`,
    "Caddyfile",
  );
  assertStringIncludes(c, "zs_caddy_file_match(");
  assertStringIncludes(c, "zs_caddy_rewrite_uri(\"{http.matchers.file.relative}\"");
  assertStringIncludes(c, "first_exist_fallback");
  assertStringIncludes(c, "?{http.request.uri.query}&p={http.request.uri.path}");
});

Deno.test("caddy-compile adapts log_append", async () => {
  const c = await compile(
    `example.com {
  log_append /admin* <route admin
  respond "ok" 204
}`,
    "Caddyfile",
  );
  assertStringIncludes(c, "zs_caddy_respond_static(\"204\"");
});

Deno.test("caddy-compile adapts redir html", async () => {
  const c = await compile(
    `example.com {
  redir https://example.org/a?b=<tag> html
}`,
    "Caddyfile",
  );
  assertStringIncludes(c, "zs_caddy_respond_static(\"200\"");
  assertStringIncludes(c, "Content-Type");
  assertStringIncludes(c, "text/html; charset=utf-8");
  assertStringIncludes(c, "https://example.org/a?b=&lt;tag&gt;");
  assertEquals(c.includes("Location"), false);
});

Deno.test("caddy-compile adapts log vars directives", async () => {
  const c = await compile(
    `example.com {
  log_skip /hidden*
  log_name access_a access_b
  respond "ok" 204
}`,
    "Caddyfile",
  );
  assertStringIncludes(c, "zs_caddy_vars_set(");
  assertStringIncludes(c, "log_skip");
  assertStringIncludes(c, "access_logger_names");
  assertStringIncludes(c, "zs_caddy_respond_static(\"204\"");
});

Deno.test("caddy-compile adapts basic_auth", async () => {
  const c = await compile(
    `example.com {
  basic_auth /admin/* bcrypt "Admin Area" {
    alice $2a$14$gqs5yvNgSqb/ksrUoam91ewSE1TjpYIgCuaiuZH395DQEPsiCVIei
  }
  respond "hello {http.auth.user.id}" 200
}`,
    "Caddyfile",
  );
  assertStringIncludes(c, "zs_caddy_basic_auth(");
  assertStringIncludes(c, "Admin Area");
  assertStringIncludes(c, "{http.auth.user.id}");
});

Deno.test("caddy-compile adapts tls certificate files to zeroserve TLS section", async () => {
  const json = JSON.parse(await adapt(`example.com {
  tls /tmp/example.crt /tmp/example.key
  respond ok
}`));
  const policies = json.apps.http.servers.srv0.tls_connection_policies;
  assertEquals(policies[0].match.sni, ["example.com"]);
  assertEquals(policies[0].certificate_selection.certificate, "/tmp/example.crt");
  assertEquals(policies[0].certificate_selection.key, "/tmp/example.key");

  const c = await compile(
    `example.com {
  tls /tmp/example.crt /tmp/example.key
  respond ok
}`,
    "Caddyfile",
  );
  assertStringIncludes(c, "ZS_TLS_ENTRY");
  assertStringIncludes(c, "zs_caddy_tls_certificate(");
  assertStringIncludes(c, "/tmp/example.crt");
  assertStringIncludes(c, "/tmp/example.key");
});
