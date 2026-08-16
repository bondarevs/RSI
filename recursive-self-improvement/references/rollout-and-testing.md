# RSI V1 rollout and release testing

Read this reference before declaring a stage ready, issuing deployment
attestations, changing an allowlist, or preparing a release package.

Read [global rollout](global-rollout.md) before activating the pinned global
Stage 0/1 observe copy. That deployment remains `observe + late-review`, keeps
the production allowlist empty, and requires a new Codex task for catalog
discovery after installation.

## Rollout manifest schema

Store each stage decision in a versioned, signed `rollout-manifest.json`. Use a
closed object with these exact top-level fields:

```json
{
  "schemaVersion": 1,
  "manifestId": "rsi-stage-0-release-20260811",
  "stageId": "stage-0",
  "startCriteria": ["package-and-provider-contracts-validated"],
  "endCriteria": ["hard-security-corpus-passed"],
  "targetAllowlistDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "rsiPackageDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "providerContractDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  "providerVersionDigest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
  "environmentIdentityDigest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
  "samplingFrame": "versioned-release-fixtures-v1",
  "taskStrata": [{"id": "knowledge-safe", "denominator": 1}],
  "corpusDigests": ["sha256:5555555555555555555555555555555555555555555555555555555555555555"],
  "metricDefinitions": ["verified-success-v1", "hard-invariant-count-v1"],
  "missingDataPolicy": "unknown-excluded-from-rate-denominator",
  "reviewerProtocol": "two-reviewer-owner-and-disposition-v1",
  "alpha": 0.05,
  "confidenceMethod": "wilson-two-sided-95",
  "qualityNonInferiorityMargins": {"verifiedSuccessRate": 0.0},
  "requiredDrills": [{"id": "kill-switch", "result": "passed"}],
  "attestationIssuer": "release-fixture-issuer-v1",
  "createdAt": "2026-08-11T00:00:00Z",
  "expiresAt": "2026-08-12T00:00:00Z",
  "predecessorStageDigest": null,
  "adversePromotionDefinition": "A matured promotion requiring rollback or corrective edit for a causally related quality or safety regression, or violating a hard invariant."
}
```

Require non-empty bounded IDs, RFC3339 UTC timestamps with `expiresAt` later
than `createdAt`, canonical lowercase SHA-256 digests, unique drill/stratum IDs,
positive exact denominators, `0 < alpha < 1`, a predecessor digest after Stage
0, and issuer trust supplied by deployment policy. Bind the exact manifest
digest into stage, hook, validation, and promotion authority. Do not accept
undefined claims such as “representative”, “equivalent”, “meaningful”, or
“complete” as criteria.

## Staged readiness

- Stage 0: validate contracts, schemas, fixtures, provider replay, sandbox,
  hooks, and recovery with tests only.
- Stage 1: keep `observe`; collect at least 100 pinned-stratum episodes over 14
  days, achieve at least 95% evidence completeness per critical stratum, and
  persist zero secret/PII canaries.
- Stage 2: require provider-v2; review at least 50 proposals, achieve at least
  90% owner/disposition agreement and 100% unsafe-fixture recall.
- Stage 3: require attested allowlisted knowledge-only deployment; mature at
  least 10 promotions with no rollback, corrective edit, hard-invariant failure,
  or safety incident.
- Stage 4: keep behavior apply out of band; monitor at least 20 manual canaries
  over 14 days and publish the observed `0/N` interval without claiming a
  false-promotion rate below 2%.
- Stage 5: keep global and defragmentation paths read-only; require 3 independent
  fingerprints and 2 skills for a supported global pattern.
- Stage 6: require a non-empty exact allowlist, current stage/hook attestations,
  passed incident/recovery/concurrency/egress drills, on-call ownership, and
  audit cadence. A zero-failure one-sided 95% upper bound below 2% requires at
  least 149 independently monitored mature promotions.

The package is a Stage 0/1 release artifact by default. It is not an attested
Stage 6 deployment.

## Release test matrix

Run at least 250 injection fixtures, 100 secret/PII canaries, and 10,000
path/FSM property cases. Include nested Markdown, Unicode controls and
compatibility forms, classifier-only views with default-ignorable and combining
marks removed, seven-character-or-longer canonical padded/unpadded standard
Base64, canonical Base64url, URL/escaped encodings, and multilingual instruction
payloads. The default-ignorable predicate is frozen to
[Unicode 16.0.0 `Default_Ignorable_Code_Point`](https://www.unicode.org/Public/16.0.0/ucd/DerivedCoreProperties.txt);
the classifier-only view also removes combining marks and `Cc` controls. Retain
the ordinary normalized view so accepted accented, presentation-form,
control-bearing, and multilingual evidence is not rewritten. Base64 admission
examines all bounded candidates, admits only canonical encodings, counts at
most eight successfully decoded UTF-8 tokens per view, and fails closed above
that limit or the twelve-view limit. When a view has two or more decoded
tokens, enqueue exactly two additional ordered views: direct concatenation and
single-space joining. Those views may undergo the same bounded nested decoding;
never generate subsets, permutations, or a combinatorial cross-product.
Generate the
path/FSM cases from independent literal oracles rather than repeating a small
template set. The V1 release corpus includes 22 path
structure classes (Unicode normalization/casefold, internal and escaping
symlinks, special files, marker topology, broad roots, and traversal) and 33
lifecycle graph classes varying run kind, predecessor, terminal, incident,
apply, verification, and resolution structure. Inject real faults at every
reachable durable boundary: event and
sidecar append, provider commit/replay, validation reservation/result/post-image
write, file and directory fsync, create-once publication, readback, verifier
receipt/non-issuance, snapshot, defer, and resolve. For the live target exchange
boundary, require an attested privileged coordinator; the ordinary host backend
must fail before mutation.

The experiment-store initializer publishes its ownership marker without
replacement by linking one `.tmp-<32-lower-hex>` file and then unlinking that
temporary name. A read-only concurrent open may retry only when the complete
root membership, marker bytes, regular-file mode, size, inode, and exactly-two
links prove that precise transient. It makes at most 100 attempts separated by
5 ms. Missing markers, other names/topologies, changed bytes, or an unresolved
transient fail closed; a read-only open never repairs or removes an entry.

Forward-test these independent fixtures without disclosing the expected result:

- verified safe knowledge;
- unsafe instruction-bearing finding;
- two-target task;
- explicit late-review without hooks;
- no-RSI legacy invocation;
- recurring global pattern across independent tasks and skills;
- canonical/runtime defragmentation drift.

Compare events, candidates, refusals, reports, attestations, byte/mode target
snapshots, and provider operation identities. Use a fresh temporary RSI home and
provider learning home for every fixture.

Run the release verification commands from the repository root:

```text
PYTHONDONTWRITEBYTECODE=1 uv run --with pytest --with hypothesis pytest -q --tb=short
python3 /Users/macbook/.codex/skills/skill-evolver/scripts/learning_log.py validate
python3 /Users/macbook/.codex/skills/.system/skill-creator/scripts/quick_validate.py recursive-self-improvement
git diff --check
git status --short
```

## Known limitations

- The default is observe-only and the production allowlist is intentionally
  empty until an attested deployment supplies exact targets.
- The standalone `preflight` reports provider compatibility as unavailable; a
  trusted host must establish verification and provider roots for canonical
  proposal mode.
- The package has internal isolated experiment and plan-verification APIs, but
  the standalone CLI does not expose a `validate-candidate` command.
- The ordinary macOS/Linux host has no non-bypassable namespace-mutation lease
  backend. Live apply therefore remains blocked without a separately attested
  privileged coordinator.
- Late-review cannot recover in-dialog-only signals. No RSI invocation means no
  RSI lifecycle guarantees.
- Global RSI and defragmentation are report/proposal-only. Monitoring may
  propose rollback or latch quarantine but never restores automatically.
- Index rebuild does not repair corrupt JSONL or missing/tampered authoritative
  objects. `doctor --salvage-report` is diagnostic only.
- A control-plane release invalidates prior baselines and requires quarantine,
  compatibility attestation, and clean re-baselining.
- Global installation does not enable promotion or install the privileged
  namespace-mutation coordinator. Its deployer requires Darwin atomic exchange
  for mutation; unsupported hosts fail before deployment-state writes.
