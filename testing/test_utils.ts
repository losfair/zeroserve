import { fromFileUrl, join } from "@std/path";

const decoder = new TextDecoder();
export const repoRoot = fromFileUrl(new URL("..", import.meta.url));

let zeroservePathPromise: Promise<string> | null = null;

export async function getZeroservePath(): Promise<string> {
  return join(repoRoot, "target", "release", "zeroserve");
}

export async function packSite(siteRoot: string): Promise<string> {
  const zeroservePath = await getZeroservePath();
  const tarPath = await Deno.makeTempFile({ suffix: ".tar" });
  const output = await runCommand(
    zeroservePath,
    [...ebpfCompilerArgs(), "--pack", siteRoot],
    { cwd: repoRoot },
  );
  await Deno.writeFile(tarPath, output.stdout);
  return tarPath;
}

export async function compileScriptObject(
  source: string,
  objectPath: string,
): Promise<void> {
  const sourcePath = await Deno.makeTempFile({ suffix: ".c" });
  const bcPath = await Deno.makeTempFile({ suffix: ".bc" });
  try {
    await Deno.writeTextFile(sourcePath, source);
    await runCommand("clang", [
      "-O2",
      "-Wall",
      "-target",
      "bpf",
      "-fno-builtin",
      "-emit-llvm",
      "-c",
      "-I",
      join(repoRoot, "sdk"),
      sourcePath,
      "-o",
      bcPath,
    ]);
    await runCommand("llc", [
      "-march=bpf",
      "-bpf-stack-size=4096",
      "-mcpu=v3",
      "-filetype=obj",
      bcPath,
      "-o",
      objectPath,
    ]);
  } finally {
    await Deno.remove(sourcePath).catch(() => {});
    await Deno.remove(bcPath).catch(() => {});
  }
}

export interface ZeroserveProc {
  child: Deno.ChildProcess;
  statusPromise: Promise<Deno.CommandStatus>;
  httpPort: number;
  tlsPort: number | null;
  stop: () => Promise<void>;
}

/**
 * Spawn zeroserve bound to port 0 and learn the actual ports from its
 * "listening on ..." stderr lines. Pre-picking a free port and probing it with
 * a bare TCP connect is racy under `deno test --parallel`: another test's
 * server can take the port in the spawn window (zeroserve then exits with
 * EADDRINUSE, or silently shares the port via SO_REUSEPORT) and the probe
 * cannot tell whose socket answered.
 */
export async function spawnZeroserve(
  args: string[],
  opts: { tls?: boolean; quiet?: boolean } = {},
): Promise<ZeroserveProc> {
  const zeroservePath = await getZeroservePath();
  const child = new Deno.Command(zeroservePath, {
    args: [
      "--addr",
      "127.0.0.1:0",
      ...(opts.tls ? ["--tls-addr", "127.0.0.1:0"] : []),
      "--disable-request-logging",
      ...ebpfCompilerArgs(args),
      ...args,
    ],
    cwd: repoRoot,
    stdin: "null",
    stdout: "null",
    stderr: "piped",
  }).spawn();
  const statusPromise = child.status;
  try {
    const { httpPort, tlsPort, pump } = await waitForListenPorts(child, opts);
    return {
      child,
      statusPromise,
      httpPort,
      tlsPort,
      stop: async () => {
        await stopProcess(child, statusPromise);
        await pump;
      },
    };
  } catch (err) {
    await stopProcess(child, statusPromise);
    throw err;
  }
}

function ebpfCompilerArgs(existingArgs: string[] = []): string[] {
  if (existingArgs.includes("--ebpf-compiler")) {
    return [];
  }
  const compiler = Deno.env.get("ZEROSERVE_EBPF_COMPILER");
  if (compiler === undefined || compiler === "") {
    return [];
  }
  if (compiler !== "tcc" && compiler !== "clang") {
    throw new Error(
      `ZEROSERVE_EBPF_COMPILER must be "tcc" or "clang", got ${compiler}`,
    );
  }
  return ["--ebpf-compiler", compiler];
}

async function waitForListenPorts(
  child: Deno.ChildProcess,
  opts: { tls?: boolean; quiet?: boolean },
  timeoutMs = 10_000,
): Promise<{ httpPort: number; tlsPort: number | null; pump: Promise<void> }> {
  const reader = child.stderr.getReader();
  const echo = async (chunk: Uint8Array) => {
    if (opts.quiet) {
      return;
    }
    let written = 0;
    while (written < chunk.length) {
      written += await Deno.stderr.write(chunk.subarray(written));
    }
  };
  const stderrDecoder = new TextDecoder();
  const deadline = Date.now() + timeoutMs;
  let text = "";
  try {
    while (true) {
      const httpMatch = text.match(/listening on http:\/\/[^\s]+:(\d+)/);
      const tlsMatch = text.match(/listening on https:\/\/[^\s]+:(\d+)/);
      if (httpMatch && (!opts.tls || tlsMatch)) {
        // Keep draining stderr for the life of the process so the child never
        // blocks on a full pipe; `stop` awaits this to avoid leaking ops.
        const pump = (async () => {
          while (true) {
            const { value, done } = await reader.read();
            if (done) {
              break;
            }
            await echo(value);
          }
        })()
          .catch(() => {})
          .finally(() => reader.releaseLock());
        return {
          httpPort: Number(httpMatch[1]),
          tlsPort: tlsMatch ? Number(tlsMatch[1]) : null,
          pump,
        };
      }
      const result = await raceWithTimeout(
        reader.read(),
        deadline - Date.now(),
      );
      if (result === null) {
        throw new Error(
          "timed out waiting for zeroserve to report its listen address",
        );
      }
      if (result.done) {
        const status = await child.status;
        throw new Error(`zeroserve exited early with code ${status.code}`);
      }
      await echo(result.value);
      text += stderrDecoder.decode(result.value, { stream: true });
    }
  } catch (err) {
    await reader.cancel().catch(() => {});
    throw err;
  }
}

export async function withZeroserve(
  tarPath: string,
  fn: (baseUrl: string) => Promise<void>,
  extraArgs: string[] = [],
): Promise<void> {
  const proc = await spawnZeroserve([...extraArgs, tarPath]);
  try {
    await fn(`http://127.0.0.1:${proc.httpPort}`);
  } finally {
    await proc.stop();
  }
}

export async function withZeroserveTls(
  tarPath: string,
  certPath: string,
  keyPath: string,
  fn: (httpUrl: string, httpsUrl: string) => Promise<void>,
): Promise<void> {
  const proc = await spawnZeroserve(
    ["--cert", certPath, "--key", keyPath, tarPath],
    { tls: true },
  );
  try {
    await fn(
      `http://127.0.0.1:${proc.httpPort}`,
      `https://127.0.0.1:${proc.tlsPort}`,
    );
  } finally {
    await proc.stop();
  }
}

export async function hasBpfToolchain(): Promise<boolean> {
  return true;
}

export async function waitForServer(
  hostname: string,
  port: number,
  statusPromise: Promise<Deno.CommandStatus>,
  timeoutMs = 10_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const exited = await checkExited(statusPromise);
    if (exited) {
      throw new Error(
        `zeroserve exited early with code ${exited.code}`,
      );
    }
    try {
      const conn = await Deno.connect({ hostname, port });
      conn.close();
      return;
    } catch {
      await delay(100);
    }
  }
  throw new Error(`timed out waiting for zeroserve at ${hostname}:${port}`);
}

export async function stopProcess(
  child: Deno.ChildProcess,
  statusPromise: Promise<Deno.CommandStatus>,
): Promise<void> {
  try {
    child.kill("SIGTERM");
  } catch {
    return;
  }

  const status = await raceWithTimeout(statusPromise, 1000);
  if (status) {
    return;
  }

  try {
    child.kill("SIGKILL");
  } catch {
    return;
  }
  await statusPromise;
}

export async function getFreePort(): Promise<number> {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;
  listener.close();
  return port;
}

async function runCommand(
  command: string,
  args: string[],
  options: Deno.CommandOptions = {},
): Promise<Deno.CommandOutput> {
  const output = await new Deno.Command(command, {
    args,
    ...options,
    stdout: "piped",
    stderr: "piped",
  }).output();
  if (output.code !== 0) {
    const stderr = decoder.decode(output.stderr);
    const stdout = decoder.decode(output.stdout);
    throw new Error(
      `command failed: ${command} ${args.join(" ")}\n${stderr}${stdout}`,
    );
  }
  return output;
}

async function hasCommand(command: string): Promise<boolean> {
  try {
    const output = await new Deno.Command(command, {
      args: ["--version"],
      stdout: "null",
      stderr: "null",
    }).output();
    return output.code === 0;
  } catch (err) {
    if (err instanceof Deno.errors.NotFound) {
      return false;
    }
    throw err;
  }
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function checkExited(
  statusPromise: Promise<Deno.CommandStatus>,
): Promise<Deno.CommandStatus | null> {
  const exited = await Promise.race([
    statusPromise,
    immediate(),
  ]);
  return exited ?? null;
}

export async function raceWithTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
): Promise<T | null> {
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    return await Promise.race([
      promise,
      new Promise<null>((resolve) => {
        timer = setTimeout(() => resolve(null), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== null) {
      clearTimeout(timer);
    }
  }
}

function immediate(): Promise<null> {
  return new Promise((resolve) => queueMicrotask(() => resolve(null)));
}

export async function generateSelfSignedCert(): Promise<{
  certPath: string;
  keyPath: string;
  cleanup: () => Promise<void>;
}> {
  const certPath = await Deno.makeTempFile({ suffix: ".pem" });
  const keyPath = await Deno.makeTempFile({ suffix: ".pem" });

  const genCmd = new Deno.Command("openssl", {
    args: [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-days",
      "1",
      "-nodes",
      "-subj",
      "/CN=localhost",
      "-addext",
      "basicConstraints=CA:FALSE",
      "-addext",
      "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ],
    stdout: "null",
    stderr: "null",
  });
  const output = await genCmd.output();
  if (!output.success) {
    throw new Error("Failed to generate self-signed certificate");
  }

  return {
    certPath,
    keyPath,
    cleanup: async () => {
      await Deno.remove(certPath).catch(() => {});
      await Deno.remove(keyPath).catch(() => {});
    },
  };
}
