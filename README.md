# AgentSec Lab

Measuring how AI agents break, and which defenses actually hold.

Independent defensive-security research on LLM agent security and
reliability. Every claim is tested against an attack corpus, every fix
is locked in with a regression test, and nothing ships under a claim
the numbers don't support.

## Findings

1. **Tool-description scanner** (`sec_scanner.py`): tools tell the model
   what they do in plain text - an attack surface. v1 caught 83% of
   injected tool descriptions; the test corpus then caught the scanner's
   own bugs (homoglyph-obfuscated instructions, base64 payloads with
   stripped padding). v2: **100% detection, 3% false positives**.

2. **Tool-output sanitizer** (`sec_sanitizer.py`): tool output is data,
   not instructions. **100%** of instructions smuggled inside tool
   results neutralized, **0%** false positives on benign output.

3. **Fake-confirmation hijack**: a tool result claims "the user said
   yes". No defense: **72%** hijack success. Prompt hardening: **57%**
   (within noise - telling the model to be careful did not work).
   Gateway stripping (`gateway.py`): **0%**. n=40 per arm, 0.5B local
   model - illustrative of method, not a production benchmark.

4. **Context-policy routing** (`gateway.py`): tool descriptions are
   scanned at registration, tool output is sanitized at return, and
   every decision hits an audit log. Fail-closed by default.

## Method

Hypothesis -> corpus (attacks plus benign lookalikes) -> measure ->
lock in. Every bug the tests catch becomes a regression test. The
suite is the deliverable. Claim policy: "reduces, measured in X",
never "prevents".

## Reproduce

Stdlib-only Python, no dependencies, zero cost:

    python3 test_gateway.py -v

9 tests: full attack-corpus coverage, false-positive budgets, one
regression test per scanner bug, and end-to-end gateway tests.

Site: https://agentsec-lab.surge.sh
