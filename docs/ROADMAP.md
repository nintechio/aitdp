# Roadmap

Rough order. Anything here is up for grabs — comment on the tracking issue before
starting large items so we don't duplicate work.

## v0.1 — Foundation (current)
- [x] Spec v0.1: Threat Event, Detector Interface, Rule Format
- [x] JSON Schemas
- [x] Python SDK + CLI
- [x] 15 seed rules with tests
- [x] Examples: OpenAI, LangChain, FastAPI, MCP, SIEM

## v0.2 — Coverage
- [ ] 50+ rules; dedicated families for multi-agent (`AGT`), RAG poisoning (`RAG`), resource abuse (`DOS`)
- [ ] Larger benchmark: ingest public prompt-injection datasets (deepset, HackAPrompt, Gandalf) with a licence check
- [ ] `aitdp rules bench` — per-rule precision/recall against the benchmark
- [ ] Multilingual injection rules (es, de, fr, zh, ja, ru)
- [ ] `sanitize` strategies per category (strip, quote, neutralise markdown)

## v0.3 — Interop
- [ ] TypeScript SDK (`@aitdp/core`) with the same rules bundled
- [ ] OpenTelemetry exporter (`aitdp.threat` events)
- [ ] Adapters: Rebuff, NeMo Guardrails, Lakera, Prompt Guard (HF)
- [ ] Sigma / OCSF mapping doc so SIEM teams can ingest events natively

## v0.4 — Semantics
- [ ] `semantic:` pattern type — embedding similarity against example attacks, model-agnostic
- [ ] Conversation-level detectors (multi-turn escalation, slow-burn jailbreaks) using `Context.history`
- [ ] Reference classifier detector with a small, permissively licensed model

## v1.0 — Stable spec
- [ ] Spec frozen after community review
- [ ] Conformance test suite for third-party implementations
- [ ] Rule signing / provenance
