# Agent security lab - results

Independent, defensive research on LLM agent security and reliability.
Stdlib-only Python, no external services, EUR0. All claims are measured
on the lab corpus; the claim policy is "reduces, measured in X", never
"prevents".

## Findings

1. **Tool-description scanner** (`gateway/sec_scanner.py`)
   - v1: 83% detection on the attack corpus.
   - The regression tests caught two scanner bugs: homoglyph-obfuscated
     instructions (Cyrillic lookalikes folded by normalization) and
     base64 payloads with stripped/non-standard padding.
   - v2: 100% detection, 3% false positives.

2. **Tool-output sanitizer** (`gateway/sec_sanitizer.py`)
   - 100% of injected instructions in tool output neutralized,
     0% false positives on benign outputs.

3. **Fake-confirmation hijack** (tool output claims "the user said yes")
   - No defense: 72% hijack success.
   - Prompt hardening: 57% (within noise of no defense - does not work).
   - Gateway stripping: 0%.
   - n=40 per arm, 0.5B local model. Illustrates the method; it is not
     a production benchmark.

4. **Context-policy router** (`router_model.py` in the original lab)
   - Routes context per policy so untrusted data never lands in a
     privileged context. Rebuilt here as the gateway's two-checkpoint
     design (scan at registration, sanitize at output).

## Module

`gateway/gateway.py` combines scanner + sanitizer into a fail-closed
policy layer: scan tool descriptions at registration, sanitize tool
output before it reaches the model, audit log every decision.

## Reproduce

    python3 -m unittest discover -s tests -v

9 tests: full attack corpus coverage, FP budgets, and one regression
test per scanner bug.
