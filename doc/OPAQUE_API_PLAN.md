# API 不透明化迁移计划（Phase 5 - S15）

## 目标

将公开头文件中直接暴露内部字段的结构体，逐步迁移为“不透明句柄 + accessor/API”模型，以提升：

- ABI 稳定性
- 向后兼容性
- 模块封装性

## 当前暴露结构（优先级）

1. `sm2_revocation_ctx_t` / `sm2_cuckoo_filter_t`
2. `sm2_pki_service_ctx_t`
3. `sm2_pki_client_ctx_t`

## 迁移策略

### Step 1（兼容期）

- 新增句柄类型声明（仅前向声明）：
  - `typedef struct sm2_rev_ctx_st SM2_REV_CTX;`
  - `typedef struct sm2_pki_service_st SM2_PKI_SERVICE;`
  - `typedef struct sm2_pki_client_st SM2_PKI_CLIENT;`
- 提供 `new/free`、关键 accessor 与行为 API。
- 保留旧结构体与旧接口，标记 deprecated（文档层面先标注）。

### Step 2（过渡期）

- 内部实现迁移到私有结构定义（仅在 `.c` 中可见）。
- 测试代码从字段直访迁移到 accessor。

### Step 3（收口期）

- 移除或冻结旧接口，统一使用句柄 API。
- 在 `CHANGELOG.md` 与发布说明中声明破坏性变更窗口。

## 风险与处置

- 风险：测试和上层调用对结构体字段有直接依赖。
- 处置：分阶段兼容，先加新 API，再迁移调用，最后清理旧字段直访。

## 验收标准

- 核心上下文结构不再在公开头暴露字段定义。
- 全量测试通过，且编译告警无回归。
- API 变更记录完整（README + CHANGELOG + 迁移说明）。

