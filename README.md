# AeroPKI-Lite

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-C11-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

<p align="center">
  <span style="font-size:18px">
    <b>AeroPKI-Lite</b> 是一个纯 C11 语言编写的 PKI 协议栈，底层依赖 OpenSSL 3.0 EVP 接口，深度融合了 <b>ECQV 隐式证书</b> 与 <b>国密商用密码算法（SM2/SM3/SM4）</b>。
  </span>
</p>

## 📖 项目背景与核心设计

针对航空链路环境中普遍面临的**终端资源受限**、**信号链路不稳定**、以及**核心节点高并发压力**三大原生约束，本项目给出了一套从底层算法到系统工程化的全链路解答：

- 🪶 **轻证书 (应对资源受限)**
  基于 ECQV 将公钥与签名过程在数学上融合，结合自定义 CBOR 紧凑编码与位掩码字段裁剪机制。在极限配置下，隐式证书序列化体积仅为 `67 Bytes`（相较于传统 X.509 降低近 90%），极大地降低了电台传输成本。

- 🛡️ **稳撤销 (应对链路不稳定 & 长周期断网)**
  支持常态在线 OCSP 缓存查询，并在网络受限时降级至离线模式（近似 `O(1)` 的布谷鸟过滤器极速匹配）。系统独创 **离线空中同步 (Cuckoo Sync)** 机制，允许断网环境下的无人机集群在空中相遇时，仅通过微量哈希桶摘要交换即可导出差异包（Delta），利用 O(1) 环形写入实现撤销黑名单的快速“传染”与双向收敛。

- ⚡ **快认证 (应对高并发压力)**
  为突破高频短连接性能瓶颈，底层引入**预计算池**（静默填充签名素材复用上下文均摊开销）和**批量并行验签**引擎，高层应用域封装由 SM2 隐式双向认证无缝衔接至 SM4 会话防护的一体化逻辑链。

- 🏗️ **高工程标准**
  全量逻辑紧密托管于独立的上下文对象体系以确保多线安全，并深度适配 CMake/CTest 标准构建流与核心用例全覆盖。

---

## 📂 当前目录结构

```text
AeroPKI-Lite/
├── include/
│   ├── sm2_*.h                 # 兼容层公共 API
│   └── sm2ecqv/                # 命名空间化公共 API
├── src/
│   ├── ecqv/                   # ECQV + CBOR
│   ├── revoke/                 # 撤销管理
│   │   ├── cuckoo.c            # 布谷鸟过滤器引擎
│   │   ├── revoke.c            # OCSP/CRL/查询状态机
│   │   ├── sync.c              # 离线同步协议
│   │   └── revoke_internal.h   # 模块内部共享声明
│   ├── auth/                   # 认证、预计算、批量验签、会话保护
│   ├── pki/                    # CA/RA 服务端与客户端封装
│   └── app/
│       ├── main.c
│       ├── demo_test_cert_flow.c  # 演示测试1：证书链路
│       └── demo_test_sync_flow.c  # 演示测试2：离线同步链路
├── tests/
│   ├── test_cuckoo.c
│   ├── test_revoke.c
│   ├── test_sync.c
│   ├── test_ecqv.c
│   ├── test_auth.c
│   ├── test_pki.c
│   └── test_main.c
├── CMakeLists.txt
└── Makefile
```

---

## 🚀 构建与回归

### 🛠️ 环境依赖

- 🧰 **C11 编译器** (GCC / Clang / MSVC)
- ⚙️ **CMake** (>= 3.14)
- 🔒 **OpenSSL** (>= 3.0，链接 `libcrypto` 与 `libssl`)

### 📦 推荐编译流程

```bash
cmake -S . -B build_local -DCMAKE_BUILD_TYPE=Release
cmake --build build_local -j 1
ctest --test-dir build_local --output-on-failure
```

### ✅ 全量验证入口

集成所有模块单元与集成用例，确保回归安全。

```bash
./build_local/test_all.exe
```

---

## 💻 完整编程演示程序

为了快速上手业务流，我们在 `src/app/` 下提供了可独立编译与运行的 Demo 程序。

### 📜 核心流：证书签发 -> 验签 -> 吊销拦截

**功能覆盖**:
  1. 服务端初始化、身份注册、证书请求与签发。
  2. 客户端导入隐式证书并重构自身合法公私钥对。
  3. 利用重构私钥执行签名与验签（吊销前应通过）。
  4. 模拟服务端吊销后终端再次验证（链路应彻底被阻断）。

运行命令：

```bash
cmake --build build_local --target sm2_test_cert_flow -j 1
./build_local/sm2_test_cert_flow.exe
```

预期输出（示意）：

```text
[OK]   Service Init
[OK]   Identity Register
[OK]   Cert Request
[OK]   Cert Issue
[OK]   Get CA Public Key
[OK]   Client Init
[OK]   Import Cert
[OK]   Sign Message
[OK]   Verify Before Revoke
[OK]   Revoke Cert
[OK]   Revoke Check
[OK]   Verify After Revoke blocked as expected
[PASS] demo_test_cert_flow
```

### 📡 断网相遇同步

**功能覆盖**:
  1. 初始化双节点 A 与 B 的撤销上下文并装载同步身份标识。
  2. A 节点本地执行增量撤销记录。
  3. B 节点相遇发送 `hello` 广播。
  4. A 根据自身清单与 `hello` 计算同步计划并导出带签名的差异包（Delta Packet）。
  5. B 严格校验完整性与签名后，应用数据包，与 A 实现版本对齐。
  6. B 对同步后的故障序列号发起本地查询，结果确认为阻断状态（`revoked`）。

运行命令：

```bash
cmake --build build_local --target sm2_test_sync_flow -j 1
./build_local/sm2_test_sync_flow.exe
```

预期输出（示意）：

```text
[OK]   Init Node A
[OK]   Init Node B
[OK]   Set Sync Identity A
[OK]   Set Sync Identity B
[OK]   Apply Delta On A
[OK]   B Hello
[OK]   A Plan For B
[OK]   Export Delta Packet
[OK]   Apply Delta Packet On B
[OK]   Query Serial 880001 On B
[OK]   Query Serial 880002 On B
[PASS] demo_test_sync_flow
```

> **💡 注意**：该演示为了快速剥离周边依赖环境，使用了被精简的“最小签名/验签回调函数”以此保证核心协议层的接口调用路径完整无缺。生产环境实际部署时，请替换挂载为真实 SM2 原生签名验签外壳。

---

## 🤝 开源与参与贡献

- 📜 **许可证**: `Apache-2.0`（详见 [LICENSE](LICENSE)）
- 👥 **贡献规范**: 提交 PR 前请务必阅读并遵守 [CONTRIBUTING.md](CONTRIBUTING.md) 以了解架构约束与 C11 编码缩进约定。
- 📝 **演进记录**: 核心 API 的增加或重构逻辑与解释，请追踪查阅 [CHANGELOG.md](CHANGELOG.md)。

---

## 🌎 English Summary

AeroPKI-Lite is a C11 PKI prototype for constrained aviation networks.
It combines ECQV implicit certificates with SM2/SM3/SM4, and provides:

- compact certificate encoding and key reconstruction,
- hybrid revocation (`OCSP + incremental CRL + Cuckoo Filter`),
- offline encounter sync (Cuckoo Sync),
- high-throughput auth via precompute pool and batch verify.

Quick build and test:

```bash
cmake -S . -B build_local -DCMAKE_BUILD_TYPE=Release
cmake --build build_local -j 1
ctest --test-dir build_local --output-on-failure
```
