# LLM Security Labs

Hands-on AI/LLM application security lab write-ups covering prompt injection,
layered defenses, and SIEM-based investigation. Risk mappings explicitly reference
the **OWASP Top 10 for LLM Applications, 2025 edition**.

| Lab | Topics | Published material |
| --- | --- | --- |
| [01: Defending an LLM application against prompt injection](01-prompt-injection/README.md) | Direct injection, secret disclosure, output screening, least privilege, Splunk | Write-up and eight original screenshots |

The first lab uses Ollama with `llama3.2:3b`, a synthetic banking assistant, and
Splunk. It separates model behavior, application enforcement, and detection
telemetry, including the limitations of each observation.

This repository publishes documentation and screenshots. Application source code
and raw interaction logs are not included; the screenshots are illustrative
evidence, not a reproducible benchmark or a complete event dataset.

The [evaluation and reconciliation guide](01-prompt-injection/EVALUATION.md)
describes how to investigate the original event-count discrepancy and design a
repeatable follow-up evaluation. It does not report additional experiments.

All shown support codes and banking scenarios are synthetic lab data.
