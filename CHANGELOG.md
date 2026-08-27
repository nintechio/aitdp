# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-08-27

### Added
- AITDP specification v0.1: Threat Event schema, Detector Interface, Rule Format.
- JSON Schemas for threat events and rules.
- Initial community ruleset (15 rules) covering prompt injection, jailbreaks,
  data exfiltration, credential leakage, tool abuse, obfuscation and insecure output.
- Python reference SDK `aitdp`: `Pipeline`, `RuleDetector`, `SecretsDetector`,
  `CanaryDetector`, `ToolPolicyDetector`, `ClassifierDetector` adapter,
  `llm-guard` adapter, sanitisation helpers.
- `aitdp` CLI: `scan`, `rules list|test|validate`, `--fail-on` for CI gates.
- Examples for OpenAI, LangChain, FastAPI, MCP and SIEM export.
- Benchmark harness with a seed dataset.
