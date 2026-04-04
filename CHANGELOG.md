# Changelog

## [0.24.0](https://github.com/taoq-ai/ziran/compare/v0.23.0...v0.24.0) (2026-03-30)


### Features

* **ui:** knowledge graph, attack library, settings, Docker, UX polish ([#244](https://github.com/taoq-ai/ziran/issues/244)) ([c0e0104](https://github.com/taoq-ai/ziran/commit/c0e01040f1c171a4434d2fb2a64d2dd4a36f24e5))

## [0.23.0](https://github.com/taoq-ai/ziran/compare/v0.22.0...v0.23.0) (2026-03-24)


### Features

* **ui:** add findings management, OWASP compliance, TaoQ design system ([#233](https://github.com/taoq-ai/ziran/issues/233)) ([1e9debf](https://github.com/taoq-ai/ziran/commit/1e9debf142d3d3d89ac8839f9100b9d86a5cc435))

## [0.22.0](https://github.com/taoq-ai/ziran/compare/v0.21.0...v0.22.0) (2026-03-23)


### Features

* **ui:** web UI foundation + core API ([#229](https://github.com/taoq-ai/ziran/issues/229)) ([a320676](https://github.com/taoq-ai/ziran/commit/a320676051cfa760a7a95bc839b14762a9dae891))

## [0.21.0](https://github.com/taoq-ai/ziran/compare/v0.20.0...v0.21.0) (2026-03-23)


### Features

* expand ground truth dataset with authorization, LLM judge, and framework scenarios ([#226](https://github.com/taoq-ai/ziran/issues/226)) ([2c27337](https://github.com/taoq-ai/ziran/commit/2c27337e962cad245d86c21ef04be63d65672ecd))

## [0.20.0](https://github.com/taoq-ai/ziran/compare/v0.19.0...v0.20.0) (2026-03-22)


### Features

* implement resilience gap metric with baseline vs under-attack delta ([#198](https://github.com/taoq-ai/ziran/issues/198)) ([79005be](https://github.com/taoq-ai/ziran/commit/79005be36b456d54b9c14b4ad429c07d427ecb2a)), closes [#155](https://github.com/taoq-ai/ziran/issues/155)


### Performance Improvements

* optimize YAML parsing, library caching, benchmarks, and chain analysis ([#223](https://github.com/taoq-ai/ziran/issues/223)) ([478be97](https://github.com/taoq-ai/ziran/commit/478be97a9bb3f7d507af6608f6cd8bc1c6f85430))

## [0.19.0](https://github.com/taoq-ai/ziran/compare/v0.18.4...v0.19.0) (2026-03-21)


### Features

* implement utility-under-attack aggregate metrics ([#199](https://github.com/taoq-ai/ziran/issues/199)) ([a3af35c](https://github.com/taoq-ai/ziran/commit/a3af35c0b8eaaf09aab1a620a7cf44f480582b50))

## [0.18.4](https://github.com/taoq-ai/ziran/compare/v0.18.3...v0.18.4) (2026-03-21)


### Bug Fixes

* suppress coroutine warning by mocking AgentScanner in scan test ([#209](https://github.com/taoq-ai/ziran/issues/209)) ([221de4a](https://github.com/taoq-ai/ziran/commit/221de4a474384ff9898e82a886e5da95ca7d7003))

## [0.18.3](https://github.com/taoq-ai/ziran/compare/v0.18.2...v0.18.3) (2026-03-21)


### Performance Improvements

* reduce test suite runtime from 7min to 1.5min (4.7x speedup) ([#210](https://github.com/taoq-ai/ziran/issues/210)) ([5a1d465](https://github.com/taoq-ai/ziran/commit/5a1d465af19a70c243bca5d175b43194ec86d32b))

## [0.18.2](https://github.com/taoq-ai/ziran/compare/v0.18.1...v0.18.2) (2026-03-21)


### Bug Fixes

* increase performance benchmark targets to 30s for CI compatibility ([138dbaa](https://github.com/taoq-ai/ziran/commit/138dbaa4b18635a037842aaec0df0d352b27f086))

## [0.18.1](https://github.com/taoq-ai/ziran/compare/v0.18.0...v0.18.1) (2026-03-21)


### Bug Fixes

* add workflow_dispatch to release workflow for re-releasing versions ([13b169c](https://github.com/taoq-ai/ziran/commit/13b169c53608f30a0b4fb0f5656e64d3dc563bbf))
* trigger release workflow on release event from release-please ([#206](https://github.com/taoq-ai/ziran/issues/206)) ([5fd8ebf](https://github.com/taoq-ai/ziran/commit/5fd8ebfae75ed5296173524b78d866b4a11b53c4))
* use correct context for job-level if conditions in release workflow ([b353fb0](https://github.com/taoq-ai/ziran/commit/b353fb07e1d8cdacd312156fc60b3de821deb02a))

## [0.18.0](https://github.com/taoq-ai/ziran/compare/v0.17.0...v0.18.0) (2026-03-21)


### Features

* add comparative analysis against Promptfoo, Garak, and other tools ([#203](https://github.com/taoq-ai/ziran/issues/203)) ([d526b64](https://github.com/taoq-ai/ziran/commit/d526b64c8944edb5773efadc046a10a0cdcff824)), closes [#153](https://github.com/taoq-ai/ziran/issues/153)
* add historical tracking and trend analysis for benchmarks ([#204](https://github.com/taoq-ai/ziran/issues/204)) ([4783f75](https://github.com/taoq-ai/ziran/commit/4783f750ced7d9a9cc994f8e826ff2701fb41391)), closes [#154](https://github.com/taoq-ai/ziran/issues/154)
* add performance benchmarks with timing, throughput, and memory tracking ([#202](https://github.com/taoq-ai/ziran/issues/202)) ([3fa307e](https://github.com/taoq-ai/ziran/commit/3fa307e4576b1376f2093312b7f32e4a914bd602)), closes [#152](https://github.com/taoq-ai/ziran/issues/152)

## [0.17.0](https://github.com/taoq-ai/ziran/compare/v0.16.0...v0.17.0) (2026-03-20)


### Features

* expand AgentHarm multi-step vector coverage to 161 vectors ([#193](https://github.com/taoq-ai/ziran/issues/193)) ([3b632ea](https://github.com/taoq-ai/ziran/commit/3b632ea243f71c74dc0e91a692ae114b48a723a5))

## [0.16.0](https://github.com/taoq-ai/ziran/compare/v0.15.0...v0.16.0) (2026-03-20)


### Features

* add precision, recall, and F1 metrics for detection accuracy ([#197](https://github.com/taoq-ai/ziran/issues/197)) ([2958e5c](https://github.com/taoq-ai/ziran/commit/2958e5c8f73620b6a7779c47e3dd16b650c2982a))
* close GAP-04 quality-aware scoring and update benchmarks ([#195](https://github.com/taoq-ai/ziran/issues/195)) ([470c487](https://github.com/taoq-ai/ziran/commit/470c487792c10d807a5f024ab38f0249c01a9a9a))
* expand MCPTox tool poisoning coverage to 100+ vectors ([#192](https://github.com/taoq-ai/ziran/issues/192)) ([c414792](https://github.com/taoq-ai/ziran/commit/c4147920dc7cdbd79367a09d42a63c538fcda397))

## [0.15.0](https://github.com/taoq-ai/ziran/compare/v0.14.0...v0.15.0) (2026-03-20)


### Features

* add --dry-run mode and config validation to CLI ([76611f7](https://github.com/taoq-ai/ziran/commit/76611f7c9a8149a9575c431f08bc802c8fbef8f7))
* add campaign checkpoint/resume support ([9c79f2e](https://github.com/taoq-ai/ziran/commit/9c79f2e0b7bc7031acc00be5acd13f9befa83658))

## [0.14.0](https://github.com/taoq-ai/ziran/compare/v0.13.0...v0.14.0) (2026-03-20)


### Features

* add MCP write/git and broader financial patterns to classifier ([#187](https://github.com/taoq-ai/ziran/issues/187)) ([9d3197d](https://github.com/taoq-ai/ziran/commit/9d3197d0c4a6feb576de58c0285a43370e77a257)), closes [#163](https://github.com/taoq-ai/ziran/issues/163)
* make detector pipeline configurable and extensible ([#189](https://github.com/taoq-ai/ziran/issues/189)) ([71c8028](https://github.com/taoq-ai/ziran/commit/71c80289f02d40f08c18dc062be0821346452fa5)), closes [#121](https://github.com/taoq-ai/ziran/issues/121)


### Performance Improvements

* pre-compile regex patterns in static analysis checks ([#186](https://github.com/taoq-ai/ziran/issues/186)) ([eb2b25a](https://github.com/taoq-ai/ziran/commit/eb2b25afb7a394b85d595c9fb1bb9db64901376f)), closes [#113](https://github.com/taoq-ai/ziran/issues/113)
