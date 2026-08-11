# RSI monitoring metrics and read-only global reports (V1)

Task 9 evaluates later verified work against a promotion without changing the
target.  The public commands are `monitor`, `global-review`, and `report`.
Every result and durable report declares `mutationPerformed=false`.

## Metric record

A V1 record is a closed JSON object with:

```text
schemaVersion, baselineKey, taskFingerprint, controlPlaneVersion,
hardInvariantViolations, verifiedSuccess, userCorrection, retryCount,
testsPassed, testsTotal, latencyMs, toolCalls
```

`baselineKey` is exactly `(targetSkill, taskClass, targetSkillVersion,
evaluatorVersion, harnessVersion)`. Comparisons reject different keys.
Unavailable observations are JSON `null`: they are never converted to zero and
do not enter a rate denominator. Test rates retain the exact aggregate
numerator and denominator. Confidence bounds use the two-sided 95% Wilson score
interval over the exact observed denominator.

Monitoring decisions are lexicographic:

1. a new critical/high invariant violation or control-plane drift is
   `quarantined`;
2. a causally isolated correctness, correction, test, or retry regression is
   `rollback-proposed`;
3. only then can latency or tool-call regression propose rollback;
4. otherwise the result is `stable`.

Confounded regression evidence cannot authorize rollback. A rollback proposal
contains the immutable promotion resolution reference, its exact snapshot path
and expected post hash, requires approval, and never performs restore.

## Causal and storage boundaries

`monitoring.recorded` belongs to the later evaluation run. Its `evaluationId`
equals its causal `evaluation.completed`; its `promotionRef` names an earlier,
other-run `resolution.recorded` whose verification has affirmative live
readback, passing tests, and matching attestation. The monitoring JSON object
is content-addressed under `reports/` and is durably published before the event
that makes it authoritative. Retry must return identical bytes and one event.
The fixed monitoring window is a read-only fold over unique later evaluation
references for the same promotion (10 tasks by the default profile). Duplicate
delivery never grows the denominator; conflicting outcomes for one evaluation
fail closed. The window remains `open` until the exact task threshold is met,
then becomes `mature` without performing restore or any other mutation.

## Global aggregation

Global evidence pairs each metric record with one immutable evaluation whose
task fingerprint matches. Fingerprints are deduplicated; contradictory
duplicates fail closed. Control-plane versions are checked before
deduplication, so a duplicate cannot hide drift. A supported conclusion needs
at least three unique task fingerprints and two distinct target skills unless
the caller raises those thresholds.

The JSON report preserves all source references, raw records, exact counts,
duplicate count, per-rate denominators, thresholds, control-plane versions,
and uncertainty. Markdown is a deterministic rendering of the same report.
The JSON event is the marker-last authority. A `runKind=global` lifecycle
accepts only one `global.report.generated`, an optional incident, and close; it
cannot contain local observation, candidate, apply, provider, or mutation
events.

Global review has no target writer. The CLI nevertheless requires explicit,
real, disjoint target roots; the verification suite snapshots their complete
byte/mode trees before and after the command. `report` opens existing state
read-only and accepts only the exact
content-addressed global JSON reference.
