# Runtime measurements

Measured on Linux x86_64, Ryzen 9 9950X3D, Rust 1.98.1, rquickjs 0.13.0,
with four Tokio workers. The bench profile uses release optimization,
LTO and one codegen unit. No local QuickJS patch was enabled. These are
desktop measurements without fixed CPU affinity or frequency.

The baseline is the merged 0.5.0 runtime. The changed cache evicts its
least recently used entry instead of clearing every entry when full.
Both measurements use the same benchmark source, 30 samples, a one-second
warmup and a three-second measurement window. Raw samples and 95%
confidence intervals are in [the measurement record](performance-2026-09-12.json).

| Workload | Before | After |
| --- | ---: | ---: |
| Hot script plus a distinct cold script, 32 cache slots | 5.71 us | 3.84 us |
| Same workload, cache disabled | 63.66 us | 63.69 us |

The mixed workload takes about 33% less time. Its hot script contains
512 no-op statements and returns its argument plus one; the cold script
changes each iteration. This measures the cost of losing a useful
compiled script to cache churn. It does not establish a 33% improvement
for every script or either consuming application.

The measurements before the VM admission and cancellation changes were:

| Operation | Time |
| --- | ---: |
| Build default realm | 1.98 ms |
| Dispatch an empty VM job | 319 ns |
| Empty `Runtime::run` bracket | 683 ns |
| Cached `eval_script`, returning one number | 1.11 us |
| Cached script with one await | 2.25 us |
| Stored synchronous handler and request/response conversion | 1.79 us |
| Stored asynchronous handler and request/response conversion | 3.10 us |

Stored handlers use a streaming console and pass a request object to a
previously installed function through `Runtime::run`, following ferrimock's
dispatch shape. Both validate the returned response on every iteration.
They exclude HTTP routing, sockets, host-specific bindings and browser I/O.
The mixed-script workload represents repeated script evaluation with
changing scripts, relevant to browser automation. Full ferrimock and
ferridriver throughput and tail latency remain separate measurements.

Run the focused comparison before and after a cache change:

```sh
cargo bench -p ferrijs --bench runtime -- script_working_set \
  --sample-size 30 --warm-up-time 1 --measurement-time 3 --save-baseline before
cargo bench -p ferrijs --bench runtime -- script_working_set \
  --sample-size 30 --warm-up-time 1 --measurement-time 3 --baseline before
```

Run the broader runtime measurements:

```sh
cargo bench -p ferrijs --bench runtime -- \
  'startup|run_overhead|stored_handlers|script_working_set' \
  --sample-size 30 --warm-up-time 1 --measurement-time 3
```

The correctness changes accompanying these measurements require both
grants for read/write file handles and combined filesystem access modes,
preserve open error metadata, and coerce proxy array lengths without
panicking in the Rust deserializer. File creation, exclusive flag aliases
and proxy length cases were checked against Node 26.8.1.

These fixes do not provide process isolation or close the separate
path-check/open race. Host VM jobs now have a configurable count bound. Rust-side body buffers
and directly spawned tasks still need separate bounds for hostile workloads. See
[the sandbox model](SANDBOX.md) for the boundary a host must enforce.

## VM admission, cancellation and browser callbacks

The VM now limits queued plus active host jobs and cancels abandoned
jobs. A dropped armed run poisons its realm and requests an interpreter
interrupt. The single persistent VM owner remains in place, so a parked
run can still receive callbacks.

The first admission implementation used a Tokio semaphore. Its permit
release locks a waiter list even though this API never waits for
capacity. An atomic permit counter removes that lock. Cancellation
registers a wakeup only when the job parks, avoiding that work for
synchronous dispatch.

The following are Criterion slope estimates from the same workloads.
The baseline includes the earlier fixes above, before the VM changes.
Raw samples and 95% confidence intervals for the baseline, semaphore,
two exploratory atomic passes and final release-order fix are retained
in the [VM measurement record](vm-performance-2026-09-12.json).

| Operation | Before VM changes | Final implementation |
| --- | ---: | ---: |
| Empty VM dispatch | 322 ns | 340 ns |
| Dispatch touching globals | 325 ns | 352 ns |
| Empty run bracket | 690 ns | 694 ns |
| Cached numeric script | 1.126 us | 1.166 us |
| Cached script with one await | 2.353 us | 2.362 us |
| Small script with one argument | 1.122 us | 1.241 us |
| Batch of 16 concurrent runs | 14.10 us | 16.44 us |

Empty dispatch fell from 384 ns with the semaphore to 340 ns with the
atomic counter. Compared with the original unbounded, uncancellable
dispatch, the final implementation costs another 18 ns. The small
argument workload costs 11% more; concurrent batches cost 17% more by
these final slope estimates. Earlier atomic passes measured the latter
at 14.75 and 15.15 us. These changes buy bounded admission and
cancellation safety, not a general throughput improvement. Desktop
load and scheduling remain uncontrolled; neither consuming application's
end-to-end throughput is established here.

Ferridriver had a separate deadlock: its WebSocket pump awaited one
callback's promise before invoking the next callback. A handler awaiting
a later message, or a message on another socket, stalled the pump. It
now preserves invocation order while observing returned promises
independently. This matches the callback dispatch in
[Playwright's client source](https://github.com/microsoft/playwright/blob/d1ead3ecca23182f2d06d761c28e3d4edafb6595/packages/playwright-core/src/client/network.ts).

Both new browser regressions timed out at 5 seconds before the fix.
In the final combined suite they passed in 48–53 ms on the two Chromium
transports, 323–380 ms on BiDi and 157–163 ms on WebKit. These are test
durations proving the deadlock is gone, not throughput ratios. All 81
selected browser tests passed; 11 existing skips remained.

The final ferrijs gate passed formatting, Clippy with warnings denied,
and 532 tests, with two existing ignored doctests. Ten VM regressions
cover queued and parked cancellation, busy-script interruption, poisoned
realm reuse, capacity recovery, concurrent admission, reentrant callbacks,
invalid capacity, releasing a completed job before replying, and rejection without changing an active run's console
or limits. Ferridriver's scripting checks passed 77 Rust tests, Clippy
and the e2e TypeScript typecheck; ten existing Rust tests/doctests were
ignored.

Ferridriver's workspace now patches all six ferrijs crates to the sibling
checkout, so normal Cargo builds use these fixes without a command-line
override. Its dependencies require 0.5.0; the previous 0.2.4 Git pin is
removed. Cargo metadata was checked to confirm that all six resolve to
this checkout. A standalone checkout therefore needs the sibling runtime
until those patches are replaced with a published release containing the
fixes.

## 0.6.0 release candidate, 2026-10-05

Measured on the same machine with Rust 1.98.1, comparing 0.5.0 (rquickjs
0.13) with the candidate (rquickjs 0.14). Both use the candidate's bench
source and neither has the local QuickJS patch. A third build carries
every change except the cache tag, the engine bump and the bench fix, so
a difference can be placed either on the earlier fixes or on the engine.
Builds alternated within each round. Every row and run, with 95%
confidence intervals and the raw samples of the VM-job and run-bracket
rows, is in [the measurement record](performance-2026-10-05.json).

A full `just bench` now completes. The two module-evaluation cases
declared every module on one realm for the whole run, and Criterion's
warm-up ran that realm out of memory on 0.5.0 as well; they now take a
fresh realm every 1024 evaluations, outside the timed loop.

| Operation | 0.5.0 | Pre-engine | Candidate | Recorded 2026-09-12 |
| --- | ---: | ---: | ---: | ---: |
| Empty VM dispatch | 323 ns | 336 ns | 336 ns | 340 ns |
| Dispatch floor | 320 ns | 339 ns | 337 ns | |
| Empty run bracket | 674 ns | 693 ns | 683 ns | 694 ns |
| Cached numeric script | 1.172 us | 1.162 us | 1.151 us | 1.166 us |
| Cached script with one await | 2.305 us | 2.322 us | 2.341 us | 2.362 us |
| Small script with one argument | 1.151 us | 1.166 us | 1.163 us | 1.241 us |
| Batch of 16 concurrent runs | 14.55 us | 14.37 us | 14.80 us | 16.44 us |
| Build default realm | 1.884 ms | 2.005 ms | 1.905 ms | 1.977 ms |
| Hot script plus a cold one, 32 slots | 5.91 us | 4.01 us | 3.98 us | 3.84 us |

Each cell is the mean of every run of that build, between two and nine
of them. The candidate is no slower than the recorded figures on any
VM-job or run-bracket row.

Against 0.5.0, two differences outlast reruns. VM dispatch costs 13 to
17 ns more, about 4%, and the scalar `json_to_js` and `value_to_json`
cases move with it because a dispatch is most of their time. All of it
arrives with the admission and cancellation change: the pre-engine build
already has it and the engine adds nothing. It is the cost measured and
explained in the section above.

`crypto.getRandomValues` on a 32-byte array is 3.3% slower, and only
with the new engine. quickjs-ng now hashes the atom before indexing an
object's property table, where it used to mask the atom directly, to
stop power-of-two keys from sharing a bucket. A profile of the case
moves `JS_GetPropertyInternal` from 1.8% to 3.9% of samples. Nothing in
the property-heavy JS rows moved beyond noise.

The module registry's lookups, whose code has not changed since 0.5.0,
moved by a fraction of a nanosecond in both directions (`serves_hit`
0.2 ns slower, `canonical_hit` 0.6 ns faster). That is where the linker
placed the code, not more work.

Startup measured up to 6% slower in a single pass, and within 2.4%
either way across three alternating rounds of 100 samples, so it is
noise. Of the 103 cases, the full run marked 17 slower; two more
alternating rounds left only the rows above. The full run also has the
engine faster at `throw_catch_50k` (12.6%) and `sha256_20k` (5.1%),
each from one run.
