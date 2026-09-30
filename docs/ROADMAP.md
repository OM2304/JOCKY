# JOCKY Roadmap — future vision

> Status legend: [x] done, [~] partial, [ ] planned. Ordered by value to the
> final SIH round first, then by forensic value.

## Track A — ship-quality hardening (pre-submission)

- [x] Native Rust VM with cross-VM byte parity (`ci/parity_check.py`, 6/6)
- [x] CFG block-shuffling + symbol mangling (PS "alters CFGs / tokens")
- [x] De-subprocessed census natives (zero child processes, both OSes)
- [x] Concurrent multi-agent demo (PS "multiple systems simultaneously")
- [x] Hardened JYCRYPT1 key derivation (256-bit state, warm-up rounds)
- [ ] **Evidence bundle export**: one flag that writes a timestamped,
      hash-chained case folder (report JSON + triage output + file hashes +
      chain-of-custody header) — turns "a script" into "a forensic tool"
- [ ] Controller TLS (self-signed, token-pinned) so the lab demo can show
      encrypted transport without the mock-CDN caveat
- [ ] Native VM `--disasm` (port of `jocky info --disasm`) for demo symmetry

## Track B — forensic depth (what NTRO judges probe)

- [~] Persistence sweep: native VM covers run keys/services/startup folders;
      port the scheduled-task XML walk to Rust (no-std XML subset parser)
- [ ] `timeline()`: unified chronology from file mtimes/ctimes, prefetched
      registry, scheduled-task timestamps, event-log tails — the classic
      examiner view, built from read-only natives
- [ ] Event-log reader (`evtx()` native): parse Windows EVtx records
      (4688 process creation, 7045 service install) read-only
- [ ] Registry diffing (`regdiff()`): snapshot Run keys/services before &
      after a suspected compromise window
- [ ] YARA integration (load rules, scan read-only) — bridges JOCKY output
      to the tooling examiners already trust
- [ ] SIEM hand-off: emit controller reports as Sysmon-like JSON / STIX
      fragments so findings land in existing blue-team pipelines

## Track C — transport & scale

- [ ] Real cloud-API dead-drop channel (documented, ToS-respected provider)
      with per-deployment tokens — replaces the modelled channel
- [ ] Controller clustering: multiple controllers behind one queue, agent
      heartbeats, task TTLs and retry semantics
- [ ] Agent-side rate limiting + jittered polling (mimics ordinary beacon
      traffic patterns for the "does not trigger heuristics" story)

## Track D — the long game (architecture already supports these)

- [ ] **LLVM backend**: `JOCKY → LLVM IR → native object` emitter for
      AOT-hardened deployments (the IR/cipher/VM are producer-agnostic;
      see architecture.md §8 for why the custom IR stays primary)
- [ ] AES-256-GCM keystream swap (format unchanged; hardware AES-NI path)
- [ ] Linux FFI census via netlink `sock_diag` (per-socket PIDs without
      the /proc fd walk)
- [ ] Cross-arch triage: qemu-user backend or ARM64 native build
- [ ] Signed driver-load monitoring feed for `byovd.py` (ETW kernel events)

## Submission checklist (deadline 20 Sep)

- [x] git repo + CI green on push
- [ ] GitHub Actions run green (verify after push) + badge in README
- [ ] Final demo rehearsal: `bash demo.sh fast` → `edr.py` → `byovd.py`
- [ ] 1-page PS-requirement → evidence map (DEMO.md §3 is the seed)
- [ ] Video: 3-minute screen capture of the demo for the submission portal
