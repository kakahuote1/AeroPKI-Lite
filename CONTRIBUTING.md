# 贡献指南（Contributing）

感谢你对 `sm2` 项目的关注。本文档说明如何提交 Issue、贡献代码和参与评审。

## 1. 贡献流程

1. Fork 仓库并创建功能分支（例如 `feat/revoke-ci`）。
2. 在提交前完成格式检查、编译检查和测试。
3. 提交 Pull Request，描述问题背景、修改范围、验证结果和兼容性影响。
4. 等待维护者 Review，通过后合并。

## 2. 代码与文档规范

- 语言：核心实现使用 C 语言。
- 注释风格：优先使用 `/* ... */`。
- 格式：遵循仓库 `.clang-format`。
- 文档：新增 API 或行为变化时，必须更新 `README.md` / `CHANGELOG.md`。

## 3. 提交与 PR 规范

- Commit 建议采用 `type(scope): subject`，例如：
  - `feat(revoke): add constrained cuckoo filter config`
  - `fix(auth): avoid fallback performance regression`
- PR 描述至少包含：
  - 变更摘要
  - 风险评估
  - 回归验证命令与结果

## 4. 测试要求

- 本地至少通过一次完整测试。
- 若修改接口、证书编码、撤销逻辑、认证流程，必须补充对应测试。

## 5. License 与 CLA

- 本项目使用 Apache-2.0 许可证。
- 贡献代码默认同意以 Apache-2.0 方式授权。
- 当前仓库未单独引入外部 CLA 系统；如后续引入，会在本文件更新说明。

## 6. 开源发布分支策略（internal_doc 清理）

- `internal_doc/` 用于开发过程管理（`task.md` / `record.md`），开发分支保留。
- 面向开源发布的分支或发布包中，默认不携带 `internal_doc/`，以 `CHANGELOG.md` 与 Release Notes 作为对外变更追踪。

