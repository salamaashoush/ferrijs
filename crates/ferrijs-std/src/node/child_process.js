// `node:child_process` over the realm's two primitives (see
// child_process.rs): `native.spawnSync` runs a program to completion,
// `native.spawn` starts one and reports its output and exit as events.
// What is written here is Node's surface and Node's error shapes; the
// `run` grant is checked natively, on the program each call executes.

export default function childProcess(native, { events, stream, process, Buffer }) {
  const { EventEmitter } = events;
  const { Readable, Writable } = stream;
  const promisifyCustom = Symbol.for("nodejs.util.promisify.custom");

  function invalidArg(name, value) {
    const error = new TypeError(`The "${name}" argument must be of type string. Received ${typeof value}`);
    error.code = "ERR_INVALID_ARG_TYPE";
    return error;
  }

  function toBytes(chunk, encoding) {
    if (chunk instanceof Uint8Array) return chunk;
    if (ArrayBuffer.isView(chunk)) return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    return Buffer.from(String(chunk), encoding);
  }

  function decode(bytes, encoding) {
    if (bytes == null) return bytes;
    const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return encoding && encoding !== "buffer" ? buffer.toString(encoding) : buffer;
  }

  function stdioModes(stdio, fallback) {
    const one = (mode) => {
      if (mode === undefined || mode === null || mode === "pipe" || mode === "overlapped") return "pipe";
      if (mode === "inherit" || mode === 0 || mode === 1 || mode === 2) return "inherit";
      if (mode === "ignore") return "ignore";
      // A stream or descriptor of the parent's is its own output: inherit.
      return "inherit";
    };
    if (stdio === undefined) return fallback.slice();
    if (typeof stdio === "string") return [one(stdio), one(stdio), one(stdio)];
    return [one(stdio[0]), one(stdio[1]), one(stdio[2])];
  }

  // `normalizeSpawnArguments` in Node's lib/child_process.js.
  function normalize(file, args, options, stdioFallback) {
    if (typeof file !== "string") throw invalidArg("file", file);
    if (file.length === 0) {
      const error = new TypeError("The argument 'file' cannot be empty. Received ''");
      error.code = "ERR_INVALID_ARG_VALUE";
      throw error;
    }
    if (Array.isArray(args)) {
      args = args.map(String);
    } else if (args == null) {
      args = [];
    } else if (typeof args === "object") {
      options = args;
      args = [];
    } else {
      throw invalidArg("args", args);
    }
    options = options == null ? {} : { ...options };
    let windowsVerbatimArguments = Boolean(options.windowsVerbatimArguments);
    if (options.shell) {
      const command = [file, ...args].join(" ");
      if (process.platform === "win32") {
        file = typeof options.shell === "string" ? options.shell : process.env.comspec || "cmd.exe";
        // cmd.exe parses its own command line, so the line goes to it as
        // written, quotes and all, rather than quoted again per argument.
        if (/^(?:.*\\)?cmd(?:\.exe)?$/i.test(file)) {
          args = ["/d", "/s", "/c", `"${command}"`];
          windowsVerbatimArguments = true;
        } else {
          args = ["-c", command];
        }
      } else {
        file = typeof options.shell === "string" ? options.shell : "/bin/sh";
        args = ["-c", command];
      }
    }
    const env = options.env ?? process.env;
    const pairs = [];
    for (const key of Object.keys(env)) {
      if (env[key] !== undefined) pairs.push([key, String(env[key])]);
    }
    const cwd = options.cwd == null ? undefined : options.cwd instanceof URL ? decodeURIComponent(options.cwd.pathname) : String(options.cwd);
    return {
      file,
      args,
      options,
      spawnargs: [options.argv0 ?? file, ...args],
      native: {
        cwd,
        env: pairs,
        stdio: stdioModes(options.stdio, stdioFallback),
        argv0: options.argv0 === undefined ? undefined : String(options.argv0),
        windowsVerbatimArguments,
        timeout: options.timeout,
        killSignal: options.killSignal,
        maxBuffer: options.maxBuffer,
      },
    };
  }

  function systemError(info, spawnargs) {
    const error = new Error(info.message);
    error.errno = info.errno;
    error.code = info.code;
    error.syscall = info.syscall;
    error.path = info.path;
    error.spawnargs = spawnargs.slice(1);
    return error;
  }

  function spawnSync(file, args, options) {
    const spec = normalize(file, args, options, ["pipe", "pipe", "pipe"]);
    const input = spec.options.input;
    const run = native.spawnSync(spec.file, spec.args, {
      ...spec.native,
      maxBuffer: spec.options.maxBuffer ?? 1024 * 1024,
      input: input == null ? undefined : toBytes(input, spec.options.encoding),
    });
    const encoding = spec.options.encoding;
    const stdout = decode(run.stdout, encoding);
    const stderr = decode(run.stderr, encoding);
    const result = {
      pid: run.pid ?? 0,
      output: [null, stdout ?? null, stderr ?? null],
      stdout: stdout ?? null,
      stderr: stderr ?? null,
      status: run.status,
      signal: run.signal,
    };
    if (run.error) result.error = systemError(run.error, spec.spawnargs);
    return result;
  }

  // `checkExecSyncError` in Node.
  function checkSync(result, command) {
    if (result.error) {
      const error = result.error;
      Object.assign(error, result);
      throw error;
    }
    if (result.status !== 0 || result.signal) {
      let message = `Command failed: ${command}`;
      if (result.stderr && result.stderr.length > 0) message += `\n${result.stderr.toString()}`;
      const error = new Error(message);
      Object.assign(error, result);
      throw error;
    }
  }

  function syncExec(file, args, options, command) {
    // Without `stdio`, the child's stderr is shown on the parent's as well
    // as kept on the error, as Node does.
    const showStderr = !options || options.stdio === undefined;
    const result = spawnSync(file, args, options);
    if (showStderr && result.stderr && result.stderr.length > 0 && process.stderr) {
      process.stderr.write(result.stderr);
    }
    checkSync(result, command);
    return result.stdout;
  }

  function execFileSync(file, args, options) {
    if (!Array.isArray(args) && args != null && typeof args === "object") {
      options = args;
      args = [];
    }
    const command = [file, ...(args ?? [])].join(" ");
    return syncExec(file, args ?? [], options, command);
  }

  function execSync(command, options) {
    return syncExec(command, [], { ...options, shell: options?.shell ?? true }, command);
  }

  class ChildProcess extends EventEmitter {
    constructor() {
      super();
      this.pid = undefined;
      this.exitCode = null;
      this.signalCode = null;
      this.killed = false;
      this.connected = false;
      this.stdin = null;
      this.stdout = null;
      this.stderr = null;
      this.stdio = [null, null, null];
      this.spawnfile = undefined;
      this.spawnargs = [];
      this._handle = null;
    }

    kill(signal = "SIGTERM") {
      if (!this._handle || this.exitCode !== null || this.signalCode !== null) return false;
      const sent = this._handle.kill(signal);
      if (sent) this.killed = true;
      return sent;
    }

    ref() {}

    unref() {}

    [Symbol.dispose]() {
      if (!this.killed) this.kill();
    }
  }

  function spawn(file, args, options) {
    const spec = normalize(file, args, options, ["pipe", "pipe", "pipe"]);
    const child = new ChildProcess();
    child.spawnfile = spec.file;
    child.spawnargs = spec.spawnargs;
    const [inMode, outMode, errMode] = spec.native.stdio;
    if (outMode === "pipe") child.stdout = new Readable({ read() {} });
    if (errMode === "pipe") child.stderr = new Readable({ read() {} });
    // Node emits `spawn` before any output or `exit`; the child's first
    // report can come before the microtask that would emit it, so
    // whichever is first emits it, once.
    let announced = false;
    const announce = () => {
      if (announced || child.pid === undefined) return;
      announced = true;
      child.emit("spawn");
    };
    const handle = native.spawn(spec.file, spec.args, spec.native, (event, a, b) => {
      if (event !== "error") announce();
      if (event === "stdout") {
        child.stdout?.push(decode(a));
      } else if (event === "stderr") {
        child.stderr?.push(decode(a));
      } else if (event === "exit") {
        child.exitCode = a ?? null;
        child.signalCode = b ?? null;
        child.stdout?.push(null);
        child.stderr?.push(null);
        child.emit("exit", child.exitCode, child.signalCode);
        queueMicrotask(() => child.emit("close", child.exitCode, child.signalCode));
      } else if (event === "error") {
        child.emit("error", systemError(a, spec.spawnargs));
        queueMicrotask(() => child.emit("close", -2, null));
      }
    });
    child._handle = handle;
    child.pid = handle.pid;
    if (inMode === "pipe" && handle.pid !== undefined) {
      child.stdin = new Writable({
        write(chunk, encoding, callback) {
          handle.write(toBytes(chunk, encoding));
          callback();
        },
        final(callback) {
          handle.end();
          callback();
        },
      });
    }
    child.stdio = [child.stdin, child.stdout, child.stderr];
    if (handle.pid !== undefined) queueMicrotask(announce);
    const killSignal = spec.options.killSignal ?? "SIGTERM";
    if (spec.options.timeout > 0) {
      const timer = setTimeout(() => child.kill(killSignal), spec.options.timeout);
      child.once("exit", () => clearTimeout(timer));
    }
    const signal = spec.options.signal;
    if (signal) {
      const abort = () => {
        if (child.kill(killSignal)) {
          const error = new Error("The operation was aborted");
          error.name = "AbortError";
          error.code = "ABORT_ERR";
          error.cause = signal.reason;
          child.emit("error", error);
        }
      };
      if (signal.aborted) queueMicrotask(abort);
      else {
        signal.addEventListener("abort", abort, { once: true });
        child.once("exit", () => signal.removeEventListener("abort", abort));
      }
    }
    return child;
  }

  // `execFile(file[, args][, options][, callback])`.
  function execFile(file, ...rest) {
    let args = [];
    let options = {};
    let callback;
    if (Array.isArray(rest[0])) args = rest.shift();
    else if (rest[0] == null && rest.length > 1) rest.shift();
    if (rest[0] != null && typeof rest[0] === "object") options = rest.shift();
    else if (rest[0] == null && rest.length > 1) rest.shift();
    if (typeof rest[0] === "function") callback = rest.shift();
    options = { encoding: "utf8", maxBuffer: 1024 * 1024, ...options };
    const child = spawn(file, args, options);
    const command = [file, ...args].join(" ");
    const out = [];
    const err = [];
    let size = 0;
    let finished = false;
    let killedForBuffer = false;
    const collect = (into) => (chunk) => {
      size += chunk.length;
      if (size > options.maxBuffer) {
        killedForBuffer = true;
        child.kill(options.killSignal ?? "SIGTERM");
        return;
      }
      into.push(chunk);
    };
    child.stdout?.on("data", collect(out));
    child.stderr?.on("data", collect(err));
    const text = (chunks) => {
      const buffer = Buffer.concat(chunks);
      return options.encoding && options.encoding !== "buffer" ? buffer.toString(options.encoding) : buffer;
    };
    const finish = (error) => {
      if (finished) return;
      finished = true;
      const stdout = text(out);
      const stderr = text(err);
      if (error) {
        error.cmd = command;
        error.stdout = stdout;
        error.stderr = stderr;
      }
      if (callback) callback(error ?? null, stdout, stderr);
    };
    child.on("error", finish);
    child.on("close", (code, signal) => {
      if (code === 0 && signal === null && !killedForBuffer) return finish(null);
      const message = killedForBuffer ? "stdout maxBuffer length exceeded" : `Command failed: ${command}\n${text(err)}`;
      const error = new Error(message);
      error.code = killedForBuffer ? "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" : code;
      error.killed = child.killed;
      error.signal = signal;
      finish(error);
    });
    return child;
  }

  // `exec(command[, options][, callback])`.
  function exec(command, options, callback) {
    if (typeof options === "function") {
      callback = options;
      options = undefined;
    }
    return execFile(command, [], { ...options, shell: options?.shell ?? true }, callback);
  }

  // `util.promisify(execFile)` and `util.promisify(exec)` resolve to
  // `{ stdout, stderr }` and carry the child on the promise, as Node's do.
  for (const fn of [execFile, exec]) {
    Object.defineProperty(fn, promisifyCustom, {
      value: (...args) => {
        let child;
        const promise = new Promise((resolve, reject) => {
          child = fn(...args, (error, stdout, stderr) => {
            if (error) reject(error);
            else resolve({ stdout, stderr });
          });
        });
        promise.child = child;
        return promise;
      },
      enumerable: false,
    });
  }

  return { ChildProcess, exec, execFile, execFileSync, execSync, spawn, spawnSync };
}
