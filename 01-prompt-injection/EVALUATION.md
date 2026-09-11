# Follow-up Evaluation and Telemetry Reconciliation

This is a proposed procedure for extending the [original lab](README.md).
The queries below have not been executed against the original Splunk instance,
and no new model results are reported here. Publishing the application code is not
required to follow this procedure in a private lab.

## 1. Reconcile the historical counts

The original screenshots show 18 source events but only 14 events represented by
the grouped `risk_label, output_blocked` rows. Keep those observations intact until
the records explain the difference.

Use one **absolute start/end interval**, with the same timezone and source filters,
for every query. Record the source file and app version if available. The original
screenshots used a moving "Last 24 hours" window. Check event extraction, missing
fields, search warnings, and duplicate ingestion; a timestamp alone is not a
unique interaction identifier.

### Check field completeness

```spl
index=llm_security
| eval risk_missing=if(isnull(risk_label) OR len(trim(tostring(risk_label)))=0, 1, 0)
| eval block_missing=if(isnull(output_blocked) OR len(trim(tostring(output_blocked)))=0, 1, 0)
| eval grouping_missing=if(risk_missing=1 OR block_missing=1, 1, 0)
| stats count AS total_events
    sum(risk_missing) AS missing_risk_label
    sum(block_missing) AS missing_output_blocked
    sum(grouping_missing) AS events_missing_either_field
```

The last count is a union: an event missing both fields counts once. Do not add the
two individual missing-field counts to estimate missing events.

### Group without silently dropping missing values

```spl
index=llm_security
| eval risk_group=if(isnull(risk_label) OR len(trim(tostring(risk_label)))=0, "(missing)", tostring(risk_label))
| eval block_text=lower(trim(tostring(output_blocked)))
| eval block_group=case(
    isnull(output_blocked) OR block_text="", "(missing)",
    block_text="true" OR block_text="1", "true",
    block_text="false" OR block_text="0", "false",
    true(), "(invalid)")
| stats count AS events BY risk_group block_group
| eventstats sum(events) AS grouped_total
```

This example expects one scalar input label and blocking decision per event.
If either is multivalued, investigate the schema or extraction before interpreting
the totals. The boolean conversion accommodates Boolean, string, and 0/1 forms;
missing or invalid values remain separate from `false`.

For the same dataset with scalar fields, the grouped total should equal the base
event count. If the four-event difference persists, inspect the relevant source
records and extraction settings. Do not relabel the four events based solely on
what would make the table add up.

The conversion and conditional functions are documented in the
[Splunk conversion reference](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.2/evaluation-functions/conversion-functions)
and [Splunk evaluation reference](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.1/evaluation-functions/evaluation-functions).
Check compatibility with the Splunk version used in the lab.

### Inspect records with incomplete grouping fields

```spl
index=llm_security
| where isnull(risk_label) OR len(trim(tostring(risk_label)))=0
    OR isnull(output_blocked) OR len(trim(tostring(output_blocked)))=0
| table _time source sourcetype risk_label output_blocked
```

This view deliberately avoids printing prompts and raw replies. Review original
content only in an appropriately restricted evidence workflow. Current screenshots
contain synthetic codes, but the same query patterns may later be used with real
data. For future runs, add a unique event ID to make evidence correlation reliable.

## 2. Define the threat model and success criteria

For this lab, define the attacker as a user controlling chat text, and the target
as a synthetic secret that should not be disclosed to that user. Document whether
the attacker can maintain conversation history or make repeated attempts. Do not
include the target secret in an attack prompt: echoing a supplied value is not
evidence of extracting protected context.

Record these outcomes independently:

| Outcome | How to establish it |
| --- | --- |
| Attack intent | Label the test case before running it, independently of detector scores. |
| Secret in raw model output | Compare the output to the synthetic target; review transformations according to a documented rubric. |
| Output blocked | Record the application's enforcement decision. This is not a ground-truth label. |
| Secret delivered to the user | Inspect the actual released response, including streamed tokens if applicable. |
| Normal task completed | Check the response against predefined task-specific requirements. |
| Error or unassessable result | Record the reason separately; do not count it as a safe response. |

Use an independent evaluation procedure rather than treating the scanner under
test as its own correctness oracle. For example, check exact target disclosure
separately and manually review transformed or partial outputs. Document uncertain
cases and the sensitivity of the data involved. A generic paraphrase of behavior
rules should not automatically count as a secret disclosure.

## 3. Compare application variants consistently

Use the same labeled cases for these variants:

| Variant | Intended difference |
| --- | --- |
| Vulnerable baseline | Synthetic secret in context; no output enforcement. |
| Output-screened variant | Same context and generation settings; input scoring plus output enforcement. |
| Context-excluded variant | Synthetic secret absent from context and inaccessible through model-facing tools. |

Record any other differences in prompt rules or controls. If multiple variables
change, do not attribute the entire outcome difference to one control. Use only
synthetic secrets and retain a mapping between cases and targets for evaluation.

For each run, record:

- App revision, prompt/template version, Ollama version, exact model identity or
  digest, and quantization where applicable.
- Generation parameters, including temperature, seed where supported, context
  limits, and output token limits. A seed alone is not a cross-platform guarantee.
- Whether conversation history is reset. Evaluate multi-turn attacks as a separate
  condition from independent single-turn attempts.
- `run_id`, unique `event_id`, `case_id`, variant, repetition number, and timestamp
  with timezone. These are proposed metadata fields, not fields claimed to exist
  in the original logs.
- Detector scores and matches, enforcement decisions, independently assessed
  outcomes, latency, and any runtime errors.

Choose and record a fixed repetition count before evaluating; for an exploratory
follow-up, 20 repetitions per case and variant is a possible starting point, not
a guarantee of statistical confidence. Report counts and uncertainty. A sequence
of successful blocks does not prove universal resistance.

## 4. Include normal usage and unseen attacks

Add benign banking questions, ordinary translation requests, and quoted examples
of attack language discussed for educational purposes. These help expose false
alarms that would be invisible in an attack-only corpus.

Separate cases used to write signatures or tune thresholds from held-out cases
used to report performance. Record the threshold that determines a positive
input-detection result; a `suspicious` label is not inherently a blocking decision.

Possible follow-up cases include multilingual extraction, altered code formatting,
partial disclosure across turns, and role-play. Keep all targets synthetic and
record whether an observed response actually satisfies the attack objective.

## 5. Report metrics with explicit denominators

| Metric | Definition |
| --- | --- |
| Model disclosure rate | Assessed attack attempts with target disclosure in raw output / assessed attack attempts. |
| User-visible disclosure rate | Assessed attack attempts with target disclosure in the delivered response / assessed attack attempts. |
| Input detector precision | Independently labeled attacks flagged positive / all inputs flagged positive. |
| Input detector recall | Independently labeled attacks flagged positive / all labeled attack inputs assessed. |
| Benign blocking rate | Benign requests blocked / benign requests assessed. |
| Normal-task completion rate | Benign requests meeting task requirements / benign requests assessed. |

Report scheduled, attempted, completed, errored, and unassessable counts alongside
these rates. Define the assessment set for each metric, show exclusions, and use
`N/A` for a zero denominator. In particular, a run blocked before inference has no
model output to assess; do not classify it as a model refusal. Also report total
rule matches separately from unique interactions.

## 6. Extend to indirect injection and tool permissions

In a follow-up experiment, let a legitimate user request a summary of a document
containing attacker-controlled instructions. Record the document as the injection
entry point and distinguish it from the user's legitimate request. This is an
indirect-injection experiment; the original chat attacks remain direct.

If adding tools, use a mock banking backend with synthetic accounts. Derive the
acting user's identity from an authenticated session and enforce account/action
permissions in backend code. Test that a model-generated claim such as
`is_admin=true` cannot grant permission or expose another account's data. Measure
attempted and executed actions separately.

These are planned extensions, not completed findings. The original lab remains a
documented demonstration of selected model responses and application controls.
