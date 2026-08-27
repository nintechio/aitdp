# Contributing to AITDP

Thanks for helping make AI systems safer. There are three ways to contribute, in
increasing order of effort:

## 1. Add or improve a detection rule (15 minutes)

Rules live in [`rules/`](rules/) as YAML. This is the easiest and most valuable
contribution — every rule protects every user of the protocol.

1. Copy an existing rule, e.g. `rules/injection/AITDP-INJ-001-instruction-override.yaml`.
2. Pick the next free ID for the family (`INJ`, `JB`, `EXF`, `LEAK`, `TOOL`, `OBF`, `OUT`, …).
3. Fill in `patterns`, at least **3 `tests.match`** and **2 `tests.no_match`** samples, and
   `references` (OWASP LLM / MITRE ATLAS / CWE).
4. Run:

   ```bash
   aitdp rules validate
   aitdp rules test
   python benchmarks/run.py --show-misses   # make sure you didn't add false positives
   ```

5. Open a PR. The `Rules` workflow gives you feedback in about a minute.

Guidelines:

- Prefer precision over recall. A noisy rule gets disabled; a narrow rule gets extended.
- Regexes must be linear-time. `aitdp rules test` runs a ReDoS smoke test and will fail
  patterns that take > 50 ms on pathological input.
- Keep `confidence` honest: 0.9+ only for patterns that are almost never benign.
- Filenames are `<ID>-<kebab-slug>.yaml`.

## 2. Build a detector or adapter

Anything implementing `aitdp.Detector` (see [SPEC.md §4](SPEC.md#4-detector-interface))
can plug into the pipeline. Adapters for third-party scanners go in
`python/src/aitdp/adapters/` and must be import-guarded so the core stays
dependency-light. Include tests that don't require the third-party package (mock it).

## 3. Propose a spec change

Open a GitHub Discussion or an issue tagged `spec`. Minor versions may add optional
fields / enum values; anything that removes or renames a field is a major version.
Spec changes need: rationale, JSON schema diff, and an updated example event.

## Development setup

```bash
git clone https://github.com/nintechio/aitdp && cd aitdp
uv pip install -e "python[dev]"      # or: pip install -e "python[dev]"
pytest python/tests
ruff check python && ruff format python
```

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
