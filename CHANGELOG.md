# Changelog

本文件记录面向开源发布的版本变更历史，遵循 Keep a Changelog 风格。

## [Unreleased]

### Added
- 开源治理文件：`LICENSE`、`CONTRIBUTING.md`、`CHANGELOG.md`。
- 格式配置：`.clang-format`。

### Changed
- `.gitignore` 增加跨平台构建与调试产物忽略规则。

## [0.4.0] - 2026-03-02

### Added
- Phase 4 完整工程化能力：CA/RA 子系统、PKI 客户端接口、统一认证链路。
- OpenSSL 3.x EVP 路径迁移（签名/验签）。
- 审计整改测试项：
  - CBOR 畸形输入覆盖增强；
  - 网络抖动/断网/重连序列测试；
  - 受限参数布谷鸟过滤器误判率测试；
  - 真实 X.509 DER 基线对比测试。

### Notes
- 当前 OCSP SLA/FPR 数据来自同进程 mock 回调链路，用于逻辑验证，不等价真实网络端到端时延。

