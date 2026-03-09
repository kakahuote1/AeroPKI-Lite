# Opaque API 现状说明

## 目标

本文件记录 TinyPKI 在 opaque handle 方向上的当前状态，而不是迁移计划。

## 当前状态

以下上下文已经收口为 owning handle + opaque state：
- `sm2_pki_service_ctx_t`
- `sm2_pki_client_ctx_t`

公开头文件只暴露：
- 初始化状态
- 不透明 `state` 指针
- 明确的访问器与行为接口

调用约束：
- 初始化后不得按值复制
- 不得赋值给另一实例
- 不得使用 `memcpy` 复制上下文
- 必须在同一实例上执行 cleanup

## 已完成收口

- 不再通过公共 API 暴露服务端内部可写撤销状态
- 客户端改为绑定服务能力，而不是借用内部撤销对象
- README、测试与公开头文件已经统一到 owning handle 语义
- 负面测试已覆盖错误生命周期路径的 fail-closed 行为

## 当前结论

该方向已经从“迁移计划”进入“已落地状态”。
后续若继续演进，重点应放在类型系统层面的进一步约束，而不是重新引入兼容结构体或 deprecated 过渡接口。
