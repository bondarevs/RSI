# Task 8 Report — Guarded Promotion and Recovery

## Baseline and safety boundary

- Worktree: `/Users/macbook/Documents/ChatGPT/RSI/.worktrees/rsi-task-1`.
- Baseline commit: `5e1d698a7295ba2390dea7178e46639da3cf7c56` (`feat: add isolated RSI validation plans`).
- Approved specification SHA-256: `4d691659fc3f2a97c863fc8153e49227fc152ebe6dcf0c7a6aa8829842dd0b37`.
- Initial live provider source aggregate: `6688ad5a44a6b33911251adc26992f17623b58ac824167ae001bd0480f2a4e09`.
- Initial real provider ledger: `201acccac622b379f9c031a095a951133b033d92678fefece63967a6f13b1a6c`, 1255 lines.
- Task 8 addendum Markdown raw SHA-256:
  `6fd2ab2a1d45e678f7eaf237c462c49e6dcf3ad133e30c41e28326b9d5f909b6`.
- Canonical registry addendum JSON SHA-256:
  `ef84059ca0df0d3804dc090616cef3e4abbe3ce7f11ec6f8535e74aa3afe02c0`;
  it directionally binds the Markdown digest and defines
  `TASK8_CONTROL_PLANE_VERSION=1.1.0`.
- Architecture mapping and capability probes were read-only to the repository/provider/ledger. Atomic-exchange probes used deleted private temporary directories only.

## Architecture decisions

- Closed Task 6 proposal runs are never reopened and `candidate.captured` is
  never duplicated. Task 8 uses one deterministic `promote-safe` continuation;
  only run-index-1 `promotion.gated` may cause the prior external capture.
- The approved specification remains untouched. Its registry lacks a truthful
  rollback terminal, so the architecture adds exactly one versioned normative
  event, `apply.reverted`, through the separately hashed Markdown/JSON addendum.
  Task 7 V2 binds both addendum digests and control-plane version. Every Task 8
  event has one exact deterministic ID formula; verification carries its
  lifecycle-critical outcome/reason inline.
- EventStore remains lifecycle truth. Strict content-addressed transaction
  sidecars are event-bound evidence only; orphan evidence has no authority and
  durable `apply.started` is the mutation commit marker. Existing homes open
  zero-write; a marker-last initializer is the sole Task 8 topology upgrade.
  `resolution.recorded` uses one direct bounded content-addressed
  `resolution-readback` sidecar so its complete lease/target/provider evidence
  cannot exceed the event limit; the event itself carries only bounded IDs and
  digests.
- The origin seal indexes and re-admits every Task 6 sidecar and Task 7 V2 object,
  including report/freshness and issuance-bound raw deployment attestations.
  Origins are permanently pinned until a later closed retention protocol exists;
  fabricated expiry/tombstones do not authorize absence. Heavy lineage bytes are
  admitted/double-scanned outside locks into immutable views. Terminal unrelated
  appends structurally verify seal/prefix and pinned-object metadata without
  reading MiB bodies under provider/EventStore locks.
- Historical provider authority binds exact byte/event prefix, last/latest event,
  ledger protocol, immutable RSI fold profile, five candidate authority digests,
  and gate identity. Approved compatible provider upgrades may replay an old
  prefix with its old pure profile; arbitrary live source/helper/contract drift
  fails. Batches use one ledger lock/FD, group at most eight profiles, stream each
  once, and cap total decoded applications; current guards never recursively
  acquire a historical flock.
- Task 7 V2 marker-last publication persists the two exact deployment-attestation
  raw files and all authority/control/addendum digests across current state,
  reservation, result, attestation and plan. Outer reservation and inner
  experiment request digests remain distinct. V1 is readable/replayable but
  promotion-ineligible. The revised architecture fixes literal closed key sets,
  domains, null unions, signed-body/raw/plan/operation-ID preimages, exact
  seven-member publication, and provider/runtime/verifier/policy cross-bindings.
  `PromotionAuthorityV2` is an exact 21-key acyclic mapping: it also binds the
  artifact-store identity and the constructor-approved namespace-lease backend/
  capability, while its verifier field is the independent execution-base digest
  rather than the final control-plane digest.
- Provider list/get/validate/guards are parent-local existing-only descriptor
  folds; they launch no child and perform no repair, chmod, temp copy, cache or
  write. The named lock protocol covers every provider ledger mutation. Guard A
  covers `apply.started`; bounded temp I/O is provider-unlocked but remains under
  the outer mandatory namespace lease; and short Guard B performs fresh volatile
  admission/exchange/post-refold without a historical batch or EventStore append.
  Append-capable terminal guards fold the all-origin batch on the same FD before
  their callback.
- Provider writes still use a pinned contained subprocess and explicit creating
  initializer. Transport/output/timeout failure is never proof of no append; the
  parent performs exact locked operation lookup and classifies committed,
  uncommitted, conflict, or unknown. Snapshot/resolve guarded-v2 requests bind
  candidate ID, all five authority digests and expiry; lookup-first exact replay
  survives later drift, while new commits atomically recheck authority.
- `apply.completed` is a closed applied/not-applied union. A prepared post is
  retained and event-bound before cleanup only by the uninterrupted process that
  still owns its original exclusive-create FD; no pre-event removal arm exists.
  After process loss any present unbound reserved name is preserved and
  incidents, even when bytes look exact. A retained partial/full inode is cleanly
  bound only after the uninterrupted holder successfully syncs that exact inode
  and its artifact parent; persistent sync failure is incident-only.
  `not-started` separately handles exact-pre or non-attributable stale-external
  state before apply authority. Initial atomic-exchange probing precedes any
  allow gate.
- Durable live verification uses one acyclic constructor-approved execution-base,
  parser, pinned signing key and non-exportable signer capability. Intent commits
  a fresh nonce and request-core; only a durable applied event completes the final
  request. The strict create-once receipt is domain-separated and signed for that
  event-bound request. Its arm is exactly present or authenticated terminal
  non-issuance; the latter embeds a strict domain-separated signed non-issuance
  object, is mutually exclusive with receipt issuance, and re-proves the receipt
  path absent. Partial, malformed, transport-unknown, possible-issued or late/
  conflicting receipt state emits no verification event and incidents from the
  applied predecessor.
- `apply.reverted` follows only durable inline rollback-armed verification after
  a real reverse exchange. Its sidecar sets `retainedPreimage=null`, proves exact
  pre, and records the displaced post as the sole swap-name inode before the
  event authorizes cleanup. Defer/review drift does not strand rollback, but any
  terminal/unknown resolution blocks it.
- Plain `os.replace()` is forbidden for live targets. Full nofollow ancestry is
  retained through forward/reverse exchange and cleanup; `EINTR` is classified
  from both exact operands and never blindly retried. Exact-artifact emergency
  reverse with whole-tree drift remains an incident and preserves displaced data.
  The deterministic swap basename is created in the exact artifact parent and
  every forward/reverse exchange and sync uses that one retained parent dirfd;
  cross-directory exchange is not a Task 8 state.
- Descriptor checks and advisory locks do not close the final same-UID mutation
  window. Every protected phase therefore requires a constructor-registry-only,
  signed `TrustedNamespaceMutationLease` outside all RSI/provider/EventStore
  locks. Its privileged backend performs the mutation and excludes ancestry,
  name, link, content, metadata, alias, pre-opened-handle, mmap, dirty-writeback
  and whole-managed-tree mutation through full readback/verifier/event callback.
  The ordinary macOS/Linux backend is permanently unavailable; production fails
  before a gate unless an attested non-bypassable backend exists. Holder death
  releases, enforcer death remains fail-closed, and protection never silently
  expires beneath a live holder.
- Every applicable event-bound sidecar/incident record has one top-level lease-
  evidence field whose non-null arm embeds the complete signed acquisition
  request, exact scope, receipt and exact ordered signed backend-result sequence.
  Nested cleanup/exchange/namespace-failure witnesses carry only its recomputed
  digest; no evidence auxiliary or duplicate complete object exists.
  Provider-ledger identity, ancestry, artifact-parent, managed-tree policy,
  target, retained-name and member-metadata witness preimages are literal closed
  CFL/D schemas rather than opaque digests. The emergency
  arm is the sole five-result/two-readback sequence. A mutating backend call whose
  causal apply/revert event is missing after a crash is always ambiguous; path
  hashes, orphan receipts/results or sidecars never reconstruct it.
- Before `apply.started`, one closed per-kind vector proves every future
  sidecar/incident/receipt fits its cap without pretending future exact bytes
  exist. Exact CFL length is computed only for a complete publication/replay
  document and must not exceed that bound. The general ceiling is 200 MiB with
  at most two protected readbacks; resolution remains 144 MiB and verifier
  receipt 64 KiB, with identical counters at every I/O/parser consumer.
- Incident publication is the acyclic create-once chain record → quarantine CAS
  → latch CAS → event → decision → close. Created/preexisting dispositions allow
  concurrent incidents to bind an existing blocker without counterfeiting its
  ownership. Incident ID/path is transaction-only and one fixed record CAS selects
  the winner; concurrent classifiers adopt it without reason-derived scans.
  Every predecessor/reason, exact decision/status mapping and crash cut is
  closed, including a live-FD prepared inode whose sync remains unproved and an
  authorized unlink whose parent-sync/absence proof fails.
- Promoted cleanup requires the conjunction of `resolution.recorded`, its exact
  provider result, and the causally bound affirmative verification witness.
  Terminal provider assertions occur under new-apply, rollback, or terminal-
  readback guard as appropriate; all fallible final checks complete before
  `run.closed`, after which guard exit is release-only.
- Read-only diagnosis never constructs a mutating store or repairs state. No real
  provider ledger or target is used by Task 8 tests.
- Architecture review paused GREEN after the first lifecycle slice. The temporary
  `events.py` implementation was reverted alone and is byte-identical to baseline;
  retained tests remain RED and no Task 8 production edit is currently present.

## Atomic-exchange capability evidence

The temp-only probe on macOS 26.5.1 / Darwin 25.5.0 / APFS established:

```text
RENAME_SWAP=0x02
RENAME_NOFOLLOW_ANY=0x10
RENAME_RESOLVE_BENEATH=0x20
production flags=0x32
```

`renameatx_np` swapped and reverse-swapped exact inodes, file and directory sync succeeded, and `RESOLVE_BENEATH` rejected `..` with numeric `ENOTCAPABLE=107`. The same probe demonstrated that final-component symlinks, FIFO and `st_nlink=2` files are accepted by the syscall, and a target replacement after precheck is exchanged successfully. Production code therefore must never treat platform flags as sufficient topology or compare-and-swap proof.

## TDD evidence

### Baseline

The isolated worktree baseline was run with `.venv/bin/python -m pytest -qq
--disable-warnings`; the command exited `0`. Collection reports exactly `870
tests collected`.

### Lifecycle continuation RED 1

Before any production edit, the first Task 8 tests added the normative
`apply.reverted` registry edge and the closed-run external predecessor gate.

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q \
  recursive-self-improvement/tests/test_events.py \
  -k 'external_predecessor or every_normative_event_type or every_event_declares_its_normative_legal_predecessors'
```

Exact RED:

```text
3 failed, 48 passed, 179 deselected in 0.12s
```

The failures were the intended missing production behavior: unknown
`apply.reverted`, absent predecessor registry entry, and `fold_run()` rejecting
the new explicit `external_predecessors` argument. No production file had been
edited at this point.

The minimal registry/external-gate implementation then produced:

```text
51 passed, 179 deselected in 0.09s
2 passed, 228 deselected in 0.08s  # all external-gate cases
```

### Exact rollback RED 2

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q \
  recursive-self-improvement/tests/test_events.py \
  -k 'rollback or negative_verification'
```

Exact RED:

```text
6 failed, 2 passed, 228 deselected in 0.12s
```

The missing behavior was exact rollback folding: a proven negative
verification could not discharge the completed apply, while wrong transaction,
pre/post digest, `rollbackVerified=false`, and rollback-after-affirmative-
verification events were incorrectly accepted as inert audit events.

### Architecture review pause

The initial minimal lifecycle GREEN was intentionally removed after independent
review found cross-store authority and crash-state gaps. Only the RED tests and
this report were retained. `recursive-self-improvement/scripts/rsi_core/events.py`
matches baseline exactly. No production edit may resume until the frozen brief/
addendum pass independent lifecycle and provider-boundary review. The next
authoritative lifecycle RED must cover the exact addendum registry/ID/inline-
verification arm, sidecar-aware Task 6 origin seal and provider prefix, promote-
safe Task 4 close branch, Task 7 V2 authority/addendum/raw-attestation lineage,
closed sidecar map, and applied/not-applied/not-started/rollback terminal unions.
Provider RED follows only after that lifecycle slice and uses temporary learning
homes exclusively.

## Superseded architecture snapshot

The following exact `a6541129...` snapshot passed the provider-boundary review
but was rejected by the formal lifecycle and final apply/recovery reviews. It is
retained only as audit history; it is not the current Task 8 authority:

- Brief: 1,845 lines / 127,832 bytes, SHA-256
  `a6541129ce0d92b43ab6794fd406a385f79594d4a7d91090bb96c3a28e43ffbc`.
- Normative Markdown addendum: 98 lines / 4,851 bytes, raw SHA-256
  `b0ad693d757469e347b3aa5db3c2ad581cc0ae14e03f17384b760af709f661b8`.
- Canonical-final-LF registry JSON: 1 line / 389 bytes, SHA-256
  `38d1ebe63302be7ab4eaeb0e31d2c59d90d48ecab91a3cd328530e649ac8164c`.
  Canonical round-trip is byte-identical and its
  `normativeMarkdownRawSha256` exactly matches the Markdown file.
- Approved spec remains exactly
  `4d691659fc3f2a97c863fc8153e49227fc152ebe6dcf0c7a6aa8829842dd0b37`;
  repository production scripts have no diff from baseline, and `events.py`
  working/baseline SHA-256 are both
  `8257e0ab787a7696185c52873639fc2929c081500c608937d75af238836b9260`.
- Live provider source aggregate and real ledger remain exactly the initial
  values above; the ledger still has 1,255 lines. `git diff --check` and artifact
  trailing-whitespace scans are clean. The only tracked worktree change is the
  retained preliminary RED file `recursive-self-improvement/tests/test_events.py`;
  generated caches are untracked and retained while prior test runs may still
  reference them.
- Production and retained RED tests remained frozen during architecture closure;
  no test command was rerun for this freeze.

The reopened architecture subsequently added exact Task 7 V2 schemas, durable
verifier receipt authority, complete incident/terminal closure, crash-safe
unbound-temp semantics, and same-artifact-parent exchange. Those changes also
changed the normative Markdown, so the canonical JSON was rebound directionally.
A new candidate freeze is recorded below after contradiction and hash checks.

## Superseded corrected architecture candidate freeze

The `0845...` candidate below was rejected after further lifecycle and final-gap
review found a result-marker count mismatch, a verifier digest cycle/provenance
gap, and the absence of a non-bypassable check-to-mutation namespace boundary.
It remains audit history only.

- Brief: 2,378 lines / 159,613 bytes, SHA-256
  `0845b9cdf376e803229610cc2dfd768f45d8071059725a14d62b5e6866a1df9f`.
- Normative Markdown addendum: 104 lines / 5,232 bytes, raw SHA-256
  `bd611a9c2de78c65e66d904a6d7aef2a9fa9c5f503d7e69e5e689dbaf7046f3b`.
- Canonical-final-LF registry JSON: 1 line / 389 bytes, SHA-256
  `5ed830e783ae96097c9cd2adab3065ab367e00858aa1555ca0750dbd13460572`.
  Its strict sorted compact round-trip is byte-identical and its
  `normativeMarkdownRawSha256` exactly equals the current Markdown raw digest.
- Approved spec remains byte-identical at
  `4d691659fc3f2a97c863fc8153e49227fc152ebe6dcf0c7a6aa8829842dd0b37`.
  Production scripts/references/contracts have no diff from baseline;
  `events.py` working/baseline hashes both remain
  `8257e0ab787a7696185c52873639fc2929c081500c608937d75af238836b9260`.
- Live provider non-cache source aggregate remains
  `6688ad5a44a6b33911251adc26992f17623b58ac824167ae001bd0480f2a4e09`.
  The real ledger remains
  `201acccac622b379f9c031a095a951133b033d92678fefece63967a6f13b1a6c`
  with 1,255 lines.
- `git diff --check`, architecture trailing-whitespace scan, final-LF/NUL checks,
  canonical JSON binding, production diff and targeted contradiction scans are
  clean. The only tracked change remains the preliminary RED
  `recursive-self-improvement/tests/test_events.py`; generated caches remain
  untracked. Production and retained tests stayed frozen and no test command was
  rerun while correcting this snapshot.

## Superseded namespace-lease architecture freeze

This candidate superseded both earlier historical snapshots but was itself
rejected by final lease/lifecycle review. It closed the formal
Task 7/lifecycle/verifier findings and the final same-UID mutation gap with an
outer non-bypassable namespace lease. Its signed lease evidence includes exact
before/after witness preimages, closed per-operation result sequences, an acyclic
target-readback body/scan digest, truthful live-create versus restart-no-create
arms, truthful removed-now versus already-absent cleanup, and a provider guard
held continuously through bounded cleanup and terminal callback. Durable causal
evidence remains historically valid after its original live deadline; it never
authorizes a new mutation. Review then found that the evidence embedded only an
opaque request digest rather than the full request/scope, several nested
filesystem witness preimages were not literal, resolution evidence could not
safely fit inline in an event, authenticated verifier non-issuance was
underspecified, and two persistent sync/cleanup incident states were not
representable. The next freeze corrects those findings; this hash remains audit
history only.

- Brief: 3,269 lines / 221,863 bytes, SHA-256
  `40161d0f048b20ea970836af0b08471429619862b1388d8486962a01a7776348`.
- Normative Markdown addendum: 122 lines / 6,410 bytes, raw SHA-256
  `6fd2ab2a1d45e678f7eaf237c462c49e6dcf3ad133e30c41e28326b9d5f909b6`.
- Canonical-final-LF registry JSON: 1 line / 389 bytes, SHA-256
  `ef84059ca0df0d3804dc090616cef3e4abbe3ce7f11ec6f8535e74aa3afe02c0`.
  Its strict sorted compact round-trip is byte-identical and its prefixed
  `normativeMarkdownRawSha256` exactly equals the current Markdown raw digest.
- Approved spec remains byte-identical at
  `4d691659fc3f2a97c863fc8153e49227fc152ebe6dcf0c7a6aa8829842dd0b37`.
  Production scripts/references/contracts have no diff from baseline;
  `events.py` working/baseline hashes both remain
  `8257e0ab787a7696185c52873639fc2929c081500c608937d75af238836b9260`.
- Live provider non-cache source aggregate remains
  `6688ad5a44a6b33911251adc26992f17623b58ac824167ae001bd0480f2a4e09`.
  The real ledger remains
  `201acccac622b379f9c031a095a951133b033d92678fefece63967a6f13b1a6c`
  with 1,255 lines.
- `git diff --check`, architecture trailing-whitespace/final-LF/NUL scans,
  canonical JSON/Markdown binding, exact schema/count/digest-cycle scans,
  production diff and targeted contradiction scans are clean. The only tracked
  change remains the preliminary RED
  `recursive-self-improvement/tests/test_events.py`; generated caches remain
  untracked. Production and retained tests stayed frozen and no test command was
  rerun during this architecture correction.

## Superseded literal lease-evidence candidate freeze

This candidate supersedes the rejected `40161d0f...` freeze. It embeds the full
lease request and scope beside their recomputed digests; closes literal schemas
for provider-ledger identity, ancestry, artifact parent, managed policy, target,
retained name and member metadata; moves complete resolution evidence into one
direct event-bound `resolution-readback` sidecar; authenticates verifier
non-issuance with a mutually exclusive signed terminal object; and represents
the persistent prepared-sync and authorized-unlink durability gaps as exact
incident-only arms. Failed attestation has deterministic precedence over failed
tests. No Task 8 production/test/provider file was edited or executed while
making this architecture correction.

Formal re-review found P1-only closure defects in this candidate: the two
pre-apply incident rows omitted enforcer loss; the minimum topology omitted the
new resolution sidecar; a backend result was incorrectly required to equal a
nonce it does not contain; prepared and retained-name witnesses were compared as
differently shaped whole objects; managed-policy entries used non-Task-7 field
names and overclaimed whole-object equality to the request; readable drift and
known missing/special/link states were not representable without violating the
exact-pre/post witness rules; and the 64-MiB resolution bound ignored maximum
JSON path escaping. The next candidate corrects these without changing the
approved provider boundary or addendum.

- Brief: 3,566 lines / 242,612 bytes, SHA-256
  `47a8f1d21b05d33587b63ed09caa8e12411b7c56d677946ac22aa876caaacfcb`.
- Normative Markdown addendum is unchanged: 122 lines / 6,410 bytes, raw
  SHA-256
  `6fd2ab2a1d45e678f7eaf237c462c49e6dcf3ad133e30c41e28326b9d5f909b6`.
- Canonical-final-LF registry JSON is unchanged: 1 line / 389 bytes, SHA-256
  `ef84059ca0df0d3804dc090616cef3e4abbe3ce7f11ec6f8535e74aa3afe02c0`.
  Its strict `jq -S -c` round-trip is byte-identical and its prefixed Markdown
  digest exactly matches the current addendum.
- Exact schema assertions pass for 5-key `ProviderLedgerIdentityV1`, 16-key
  `AncestryEdgeV1`, 5-key `AncestryWitnessV1`, 11-key
  `ArtifactParentWitnessV1`, 10-key `ManagedTreePolicyV1`, 13-key
  `TargetWitnessV1`, 6-key `RetainedNameWitnessV1`, 12-key
  `MemberMetadataWitnessV1`, 8-key `NamespaceMutationScopeV1`, 12-key
  `NamespaceMutationLeaseEvidenceV1`, 24-key `ResolutionReadbackV1`, and
  13-key `VerifierNonIssuanceEvidenceV1`. Task 7 V2's already approved
  21/34/21/9/19/22/6/12/5/4/23 schemas and acyclic authority DAG are unchanged.
- Approved specification remains byte-identical at
  `4d691659fc3f2a97c863fc8153e49227fc152ebe6dcf0c7a6aa8829842dd0b37`.
  Production scripts/references/contracts have no diff from baseline;
  `events.py` working/baseline hashes both remain
  `8257e0ab787a7696185c52873639fc2929c081500c608937d75af238836b9260`.
- Live provider non-cache source aggregate remains
  `6688ad5a44a6b33911251adc26992f17623b58ac824167ae001bd0480f2a4e09`.
  The real ledger remains
  `201acccac622b379f9c031a095a951133b033d92678fefece63967a6f13b1a6c`
  with 1,255 lines.
- Markdown fences, trailing whitespace, final-LF/NUL, stale resolution-null/
  digest-only evidence wording, canonical addendum binding, production diff and
  `git diff --check` are clean. The only tracked change remains the retained
  preliminary RED `recursive-self-improvement/tests/test_events.py`; generated
  caches remain untracked. Production and retained tests stayed frozen and no
  test command was rerun.

## Superseded bounded-lease-evidence architecture freeze

This candidate supersedes the P1-only-rejected `47a8f1d2...` freeze. It adds
enforcer loss to both pre-apply incident rows and the resolution sidecar to the
minimum topology; removes the impossible result-nonce comparison; relates
prepared and retained-name witnesses through the exact `objectFromNamed`
projection; uses the literal Task 7 managed-entry vocabulary and fieldwise
request/plan relations; and treats target/member witnesses as bounded
observations whose plan equality applies only to exact-pre/post. Readable drift
has a complete `other` view, while proven missing/special/unsafe-link drift has
one closed null-view witness and only unprovable state is unreadable. The
resolution sidecar now has one exact 144-MiB cap—96 MiB escaped paths, 32 MiB
metadata, 8 MiB fixed fields, and 8 MiB margin—preflighted before
`apply.started` and enforced identically by writer, readback, and replay. Its
publication remains marker-last and content-addressed. No addendum, production,
test, provider-source, or provider-ledger byte was edited by the implementer.

Formal review found a final P1-only correction set. This candidate computed an
exact future sidecar length too early and lacked the general 200-MiB per-kind
terminal bound; overclaimed parent/request and policy/Task-7 whole-object
equalities; referred to a nonexistent target `executable` field; left full
member and known-drift observations overlapping; and used an incomplete
protected-readback outcome union. It also duplicated complete namespace-lease
evidence inside cleanup/exchange/phase witnesses instead of retaining one
top-level object with digest-only nested references. The next candidate closes
those points without changing the approved provider boundary or normative
addendum.

- Brief: 3,628 lines / 247,048 bytes, SHA-256
  `d7a567812f1546e1e70c37625349704f12e1b020d4e3c52e38871e4249f61b7a`.
- Normative Markdown addendum is unchanged: 122 lines / 6,410 bytes, raw
  SHA-256
  `6fd2ab2a1d45e678f7eaf237c462c49e6dcf3ad133e30c41e28326b9d5f909b6`.
- Canonical-final-LF registry JSON is unchanged: 1 line / 389 bytes, SHA-256
  `ef84059ca0df0d3804dc090616cef3e4abbe3ce7f11ec6f8535e74aa3afe02c0`.
  Its strict `jq -S -c` round-trip is byte-identical and its prefixed Markdown
  digest exactly matches the addendum.
- Closed-schema checks cover both pre-apply enforcer rows, the direct
  `resolution-readback` topology/ref, request/receipt-only nonce equality,
  named-witness projection, Task 7 policy entry vocabulary, readable versus
  known versus unreadable drift arms, and the single 144-MiB terminal budget.
  Task 7 V2's approved 21/34/21/9/19/22/6/12/5/4/23 schemas, the provider
  boundary, and the acyclic authority DAG are unchanged.
- Approved specification remains byte-identical at
  `4d691659fc3f2a97c863fc8153e49227fc152ebe6dcf0c7a6aa8829842dd0b37`.
  Production scripts/references/contracts have no diff from baseline;
  `events.py` working/baseline hashes both remain
  `8257e0ab787a7696185c52873639fc2929c081500c608937d75af238836b9260`.
- Live provider non-cache source aggregate remains
  `6688ad5a44a6b33911251adc26992f17623b58ac824167ae001bd0480f2a4e09`.
  The immutable first 1,255-event ledger prefix remains exactly
  `201acccac622b379f9c031a095a951133b033d92678fefece63967a6f13b1a6c`.
  During final read-only checks a separate lease reviewer legitimately appended
  two standing skill-learning workflow events (`Budget canonical JSON after
  escaping` capture plus reviewed deferral); the validated current append-only
  head is 1,257 events,
  `a8d64ee73cd30921047f83c7a2c80582011f150ba944ae98fdbea69cbfb848be`.
  No provider or ledger write came from this implementer.
- Markdown fences, trailing whitespace, final-LF/NUL, canonical addendum
  binding, schema/count/contradiction scans, production diff and
  `git diff --check` are clean. The only tracked change remains the retained
  preliminary RED `recursive-self-improvement/tests/test_events.py`; generated
  caches remain untracked. Production and retained tests stayed frozen and no
  test command was rerun during this architecture correction.

## Current per-kind bounded single-evidence architecture freeze

This candidate supersedes the P1-only-rejected `d7a56781...` freeze. Pre-apply
admission now computes only one closed worst-case vector per reachable evidence
kind; a complete publication or replay computes exact CFL length once and must
satisfy `exactLength<=preflightBound(kind)<=cap(kind)`. The 200-MiB general
bound derives from 120 MiB escaped paths, 48 MiB member metadata, 16 MiB signed
evidence/framing, and 16 MiB outer envelope with `R<=2`; resolution retains its
stricter 144-MiB cap and verifier receipt its 64-KiB cap. Allocation, write,
`fstat`, read, parse, readback, replay, and every consumer share the same
per-kind cap and counters.

Parent/request/path relations and Task 7 policy members are now strictly
fieldwise projections. Target and member mappings are bounded observations, not
plan echoes: exact-pre/post alone bind selected size/hash/manifest and mode
execute bits, with no invented target `executable` field. Full member views
contain only safe regular single-link files; deterministic first-path missing,
unsafe-link, and special states are disjoint known drift, while only
unconstructable/bounds failure is unreadable. Protected-readback result outcome
equals the complete state classification and digests the whole state.

Each applicable sidecar or incident record has one top-level complete namespace
lease evidence field. The exact nine-key cleanup, 10-key exchange, and seven-key
namespace-failure mappings carry only its digest under closed null/non-null
rules; there is no duplicate object or auxiliary evidence sidecar. Clean and
incident decisions remain disjoint exact 19-key arms, and the incident record is
an exact 24-key mapping. The addendum needs no edit because it binds the
rollback sidecar's top-level evidence and describes final cleanup authority
without naming the nested cleanup field.

- Brief: 3,780 lines / 257,189 bytes, SHA-256
  `6857d7dcbd0defc859f864b3e09d07b93602d6ca6959687f8774257bfcffe61b`.
- Normative Markdown addendum is unchanged: 122 lines / 6,410 bytes, raw
  SHA-256
  `6fd2ab2a1d45e678f7eaf237c462c49e6dcf3ad133e30c41e28326b9d5f909b6`.
- Canonical-final-LF registry JSON is unchanged: 1 line / 389 bytes, SHA-256
  `ef84059ca0df0d3804dc090616cef3e4abbe3ce7f11ec6f8535e74aa3afe02c0`.
  Its strict sorted compact round-trip is byte-identical and its prefixed
  Markdown digest exactly matches the addendum.
- Closed-schema/count scans cover the future-bound/exact-publication relation,
  200/144-MiB and 64-KiB caps, parent/ancestry/request digests, Task 7 member
  projections, exact target relations, full-view/known-drift/unreadable union,
  result outcome/state digest binding, single top-level evidence, nested digest
  arms, and absence of an evidence auxiliary. Existing 5/16/5/11/10/13/6/12/
  8/12/24/13 witness/sidecar counts and Task 7 V2's approved
  21/34/21/9/19/22/6/12/5/4/23 counts remain closed.
- Approved specification remains byte-identical at
  `4d691659fc3f2a97c863fc8153e49227fc152ebe6dcf0c7a6aa8829842dd0b37`.
  Production scripts/references/contracts have no diff from baseline;
  `events.py` working/baseline hashes both remain
  `8257e0ab787a7696185c52873639fc2929c081500c608937d75af238836b9260`.
- Live provider non-cache source aggregate remains
  `6688ad5a44a6b33911251adc26992f17623b58ac824167ae001bd0480f2a4e09`.
  The immutable first 1,255-event ledger prefix remains
  `201acccac622b379f9c031a095a951133b033d92678fefece63967a6f13b1a6c`;
  the validated append-only head remains 1,257 events,
  `a8d64ee73cd30921047f83c7a2c80582011f150ba944ae98fdbea69cbfb848be`,
  including only the already attributed lease-reviewer learning capture and
  deferral after that prefix. This implementer made no provider or ledger write.
- Markdown fences, trailing whitespace, final-LF/NUL, canonical addendum
  binding, contradiction/count/arithmetic scans, production diff and
  `git diff --check` are clean. The only tracked change remains the retained
  preliminary RED `recursive-self-improvement/tests/test_events.py`; generated
  caches remain untracked. Production and retained tests stayed frozen and no
  test command was rerun during this architecture correction.

## Implementation result

The approved architecture was implemented with an authoritative RED-to-GREEN
matrix. The final production slice adds the Task 8 registry/FSM arms, strict
existing-only EventStore and promotion journal, Task 7 V2 authority and
marker-last bundle loaders, provider pure-fold/current/historical guards,
guarded-v2 snapshot/resolve lookup-first replay, the closed CLI selectors,
promotion/namespace/verifier wire models, and read-only phase-exact recovery.

The ordinary local-host `PromotionService` is intentionally fail-closed before
any continuation event or target/provider write because the approved brief
forbids treating advisory macOS/Linux namespace primitives as a trusted
mutation lease. No privileged kernel/filesystem promotion coordinator is
installed in this workspace. The constructor-owned registry now has a positive
integration seam for an exact attested complete coordinator and rejects an
unavailable, mismatched, partial or wrong-result backend. The exact privileged
backend schemas, lock order, result sequences, crash classification, caps,
evidence placement, cleanup authority and incident convergence are implemented
and tested as closed contracts; a production apply cannot be claimed until a
separately attested privileged backend exists.

Provider hardening changed the user-owned `skill-evolver` source and contract:

- `scripts/learning_log.py` SHA-256
  `6bb49ccd528dbbcebe7d5aa6ff9bb85015fa92d0b1dedcf20d9458a5f049814b`;
- `skill-contract.json` SHA-256
  `a12c223c9b2175bba3ca5ad0cbc2bb38a2432211f2816bc793e126837c8d337b`;
- non-cache provider aggregate SHA-256
  `0ce89715b97bc790da4fd132ad287f9c028d90d04b518ddc453183724ce24226`.

The provider now declares `skill-learning.guard`. New guarded writes accept
only the complete v2 authority union, atomically recompute the current native
full-record/provider-authority digests under the ledger lock, enforce expiry
before a new append, bind all authority fields into the operation request, and
perform lookup-first exact replay after commit/expiry. The legacy/manual v1
snapshot and resolve forms remain compatible but cannot authorize Task 8.

## Independent review

The read-only implementation review and final existing-ledger admission check
reproduced eleven P1 defects:
an unconditional coordinator stub, dropped EventStore authority batches,
pathname-reopened state home, a hard-link sidecar crash interval, provider
name-swap/restore, mutable caller authority dictionaries, legacy transaction
publication with a blocking named-temp residue, same-inode ledger write/restore,
rejection of valid insertion-ordered provider-v1 JSONL, rejection of legacy
reviews without operation metadata, and attempted semantic re-admission of an
already-resolved legacy candidate lacking `change_class`. Each received an
isolated regression and a focused GREEN check.
The resulting design uses the exact attested coordinator seam, typed immutable
authority batches with complete coverage/cross-binding, a retained EventStore
home descriptor, atomic no-replace legacy publication, dedicated strict Task 8
publication from unlinked staging, and provider namespace/content metadata
postchecks while preserving strict compact legacy-v1 framing. The final
compatibility selection and full adapter suite pass. The
reviewer made no implementation edit and did not invoke the live provider CLI.

## Final verification

- Authoritative RED baseline: `459 failed, 535 passed`.
- Combined Task 8 implementation matrix: `994 passed` before the final
  provider-contract/recovery tightening.
- Focused promotion/recovery/events/storage/provider matrix after review fixes:
  `608 passed in 10.85s`.
- Final 10-case reviewer/compatibility regression selection:
  `10 passed in 0.35s`.
- Final three-case legacy-ledger compatibility selection:
  `3 passed, 83 deselected in 0.19s`; full adapter suite:
  `86 passed in 1.04s`.
- Full RSI suite after all review fixes, run twice with bytecode disabled:
  `1377 passed in 48.96s` and `1377 passed in 51.15s`.
- User-owned `skill-evolver` suite: `117 passed in 39.89s`.
- Skill validator: `Skill is valid!`.
- Python compilation and `git diff --check`: exit 0.
- Approved spec remains exact at
  `4d691659fc3f2a97c863fc8153e49227fc152ebe6dcf0c7a6aa8829842dd0b37`;
  the frozen brief/addendum/registry artifacts remain exact at
  `6857d7dc...`, `6fd2ab2a...`, and `ef84059c...` respectively.
- The live learning ledger was never invoked by this implementation. External
  activity appended eight events while verification ran, moving the head from
  the previously recorded 1,257-event `a8d64ee7...` to 1,265 events,
  `bfaee4702fdb4cf9ab472b127462b247241674e87b12c778728b9ba6e2dd6624`.
  The exact 1,257-event prefix still hashes to `a8d64ee7...`, and the original
  1,255-event prefix still hashes to `201accca...`, proving append-only drift.

## Final artifacts and commit

Generated Python/pytest caches were moved to macOS Trash. The exact final
implementation hashes include `storage.py`
`41f770b2f7587e71eefb23e3d69bd79a3b036ff347efc70c500deb1716736e90`,
`evolver_adapter.py`
`7f2b7f7d85619e66635acb30af9a5ef2d893f99ce4171a1d9ca1babdb7b19366`,
`promotion.py`
`7e346c4a37957f4191d36d2f9a0e9d425a24b8ddfdab9f3fd2a9088bd716db44`,
and the corresponding storage/adapter/promotion tests
`4230c97fd3bea699f89242939632ffcac2a2feff2a82de6a4d90418bf460ebf1`,
`90d508079b640e8618dbf06764e9ad9b76bc2d168441647a5829ef335e50dd7d`,
and `e35851ab6d745ea47031972f296fb827f02b2189098d59cf4bf78127700acf8d`.
The scoped implementation commit completes Task 8; the worktree and feature
branch stay preserved for the user's integration choice.
