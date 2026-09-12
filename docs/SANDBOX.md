# The sandbox

What a script running in a ferrijs realm can and cannot do, why the
model is shaped the way it is, and what it does not promise.

## The model in one paragraph

A realm starts with nothing. QuickJS has no ambient authority: a fresh
context can compute and nothing else. Everything a script can reach
beyond that is a capability the host installed, and every capability
asks the realm's `Container` before acting. The container holds one
`Permissions` policy for the realm's whole life; it can only ever get
narrower. There is no dynamic scope, no per-call narrowing, no policy
carried through callbacks. A host with two trust levels runs them in two
realms.

## Where it comes from

The runtime this was extracted from carried its sandbox as a cell
swapped around every poll of a handler's future, with the timer and
microtask globals capturing and re-entering that cell so a callback
kept its registrar's grants. That is Java's stack-inspection Security
Manager, reinvented. Java removed it ([JEP 411]) for exactly the
reasons it hurt here: the checks must be woven through every API and
kept complete as the surface grows, the model is slow, and it cannot
express least privilege without every library documenting and every
application re-granting.

The models still standing are all per-isolate and static:

- [Deno]: permissions per process (or per Worker, reduced), five kinds
  scoped by path, host, port and name, deny lists overriding allow
  lists, a `NotCapable` error, `revoke` to narrow at runtime and a
  prompt to widen under a human. Code evaluation is not a permission:
  everything on the thread runs at one privilege level.
- [Node]: per process, not inherited by workers, `ERR_ACCESS_DENIED`
  carrying `permission` and `resource`, `process.permission.drop` as an
  irreversible narrowing. Node documents that symlinks are followed out
  of a granted directory as a hazard the operator must avoid.
- [workerd]: no ambient network or filesystem at all; a Worker reaches
  the outside only through the bindings its configuration names. "No
  API means no access."
- [Hardened JavaScript]: `lockdown()` freezes the intrinsics so two
  programs in one realm cannot reach each other through a shared
  prototype; a `Compartment` gets its own globals and evaluators and
  only the endowments it was handed.
- [Figma]'s plugin sandbox: QuickJS with no I/O, the host reachable
  only through an explicit, auditable API.

ferrijs takes the capability model as the first line (a module or
global that is not served is absent, not present and refusing), Deno's
scoped grants as the second line inside what is served, Node's error
shape, Hardened JavaScript's intrinsic freezing and clock taming as
opt-ins, and workerd's position that process-level isolation is the
host's layer.

## The five kinds

| kind    | grants                                          | checked by                                  |
|---------|-------------------------------------------------|---------------------------------------------|
| `read`  | directories or files, with everything under them | every `fs` read, `stat`, `readdir`, `open`  |
| `write` | likewise                                        | every `fs` write, `mkdir`, `rm`, `rename`, `chmod`, `symlink` |
| `net`   | hosts, optionally with a port; `*.` wildcards    | `fetch` on the first URL and every redirect hop |
| `env`   | variable names                                  | what `process.env` is populated with        |
| `sys`   | facts about the host: hostname, release, uptime, load, interfaces, memory, uid, gid, username, cpus, homedir, priority | each `os` member |

Each kind is `None`, `All`, or a list. A `deny` list per kind overrides
the grant: `read: All` with `deny.read: ["/etc"]`.

Paths are judged twice: as written, after lexical normalisation, and as
the filesystem will resolve them, after following every symlink in the
longest existing prefix. Both must fall under a granted root. A link
planted inside an allowed directory therefore cannot reach out of it,
which is the hazard Node leaves to the operator.

`open()` is checked for the access its flags ask for; the `FileHandle`
it returns is not re-checked, since the grant was given at open time.
That is how a capability works, and it is also what Node documents
about existing descriptors.

## What is absent rather than refusing

`ModulePolicy::builtins` decides which of the standard library's modules
the realm serves at all. A module not served cannot be imported or
required; there is nothing to refuse. `ModulePolicy::no_files` serves
nothing from disk. `Builder::without_fetch` installs no `fetch`, no
`Headers`, no `Request`, no `Response`. `RealmOptions::remove_globals`
deletes any global by name after every extension installed.

## Narrowing at runtime

`Container::revoke(remaining)` intersects the policy with `remaining`;
`Container::deny(kind, resource)` carves one thing out. From a script,
`process.permission.drop(scope, resource?)` does the same and
`process.permission.has(scope, resource?)` asks. Nothing widens except
the host's `Hook`, consulted case by case when the policy refuses, which
is where a prompt lives. An `Audit` sees every decision, granted or not,
which is Node's audit mode.

Because the policy only narrows, `fetch` does not need to snapshot it:
a check made on a redirect hop, after the call returned, is never looser
than one made at the call.

## The realm itself

`Limits` bound what a realm consumes: a heap ceiling (an allocation past
it throws, and the realm is poisoned because the heap can no longer be
trusted), a JS stack ceiling, a cycle-GC threshold, and a wall-clock
budget per run enforced by the interrupt handler, with a backstop for a
run parked on a native await. A poisoned realm refuses every later run;
the host builds a new one.

Dropping an armed `Runtime::run` also poisons the realm and requests a
QuickJS interrupt. JavaScript continuations can outlive the Rust future
that awaited them, so the host must replace a cancelled realm. Dropping
a raw `VmHandle::with` caller cancels its queued or parked job on the VM
owner; it does not revoke JavaScript work or native side effects already
started. Raw VM access remains a trusted host interface.

`Builder::vm_capacity` bounds queued plus active host jobs (1024 by
default). Excess submissions fail immediately with `VM job capacity
exhausted`, before changing run limits or console capture. Waiting for
capacity could deadlock a callback behind the run awaiting it. Hosts
must leave capacity for callbacks and handle overload errors. This is a
job count, not a byte budget: captured request bodies, native buffers,
JavaScript promises and tasks spawned directly through `Ctx::spawn`
need their own limits.

`RealmOptions` shapes the language:

- `eval: false` replaces `eval`, `Function` and the async and generator
  function constructors with throwers. It is done after every extension
  installed and covers every path to the compiler, because
  `Function.prototype.constructor` is reachable from any function.
  Modules and the host's own evaluation are unaffected. Deno does not
  offer this: it sets no limits on code at the same privilege level.
  ferrijs offers it because an embedder that hands a realm bytecode it
  compiled itself may want no other way to make code.
- `freeze_intrinsics` deep-freezes what a program reaches from
  `globalThis` without naming a host global, so a script cannot change
  what another script in the same realm sees. Off by default because
  code that patches a prototype on load stops working.
- `clock_resolution` quantises `Date.now()`, `new Date()`,
  `performance.now()` and `process.hrtime()` to a resolution. A
  high-resolution clock is the instrument of a timing side channel;
  coarsening it is what browsers and workerd do for code they do not
  trust. `Date` keeps its real prototype, so a `Date` the host creates
  natively is still `instanceof Date`.

## What it does not promise

- **It is not process isolation.** A bug in the engine, in a vendored
  module or in this crate is a sandbox escape. workerd's documentation
  says the same of workerd and asks that possibly-malicious code run
  inside a VM; JEP 411 recommends containers and hypervisors for the
  same reason. A host running untrusted code puts the process in a
  sandbox of its own (seccomp, a container, a VM) on top of this.
- **Denial of service is bounded, not prevented.** The limits stop a run
  from taking the process down with it; they do not stop a script from
  spending its whole budget.
- **A `throw null` reads as exhaustion.** QuickJS throws a bare `null`
  when it cannot allocate even the error object, so a null exception is
  the out-of-memory signal and poisons the realm. A deliberate `throw
  null` is indistinguishable and pays the same price; `throw undefined`
  and `Promise.reject()` do not.
- **Extensions are trusted.** A host's own extension installs whatever
  it installs; the model governs what the standard library and `fetch`
  do, and gives an extension the same `check_*` functions to call.
  Whether it calls them is the extension's discipline.
- **Two trust levels need two realms.** There is no way to run one
  function under a narrower policy than the code around it, on purpose.

[JEP 411]: https://openjdk.org/jeps/411
[Deno]: https://docs.deno.com/runtime/fundamentals/security/
[Node]: https://nodejs.org/api/permissions.html
[workerd]: https://blog.cloudflare.com/mitigating-spectre-and-other-security-threats-the-cloudflare-workers-security-model/
[Hardened JavaScript]: https://github.com/endojs/endo/blob/master/packages/ses/docs/guide.md
[Figma]: https://www.figma.com/blog/how-we-built-the-figma-plugin-system/
