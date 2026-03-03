# sm2-ecqv-pki

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-C11-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

> A High-Performance, Lightweight ECQV Implicit Certificate PKI Library based on SM2/SM3/SM4. 
> 面向航空、卫星物联网及极度受限网络的国密轻量化隐式证书 PKI 基础设施。

[English](#english-summary) | [中文说明](#📖-项目简介-introduction)

---

## 📖 项目简介 (Introduction)

`sm2-ecqv-pki` 是一个专为带宽极度受限、高并发接入场景（如无人机蜂群、卫星数据链、V2X 车联网）打造的 **C 语言轻量级 PKI 协议栈**。
它在 OpenSSL 3.0 的基础上，深度融合了 **ECQV（Elliptic Curve Qu Vanstone）隐式证书机制** 与 **国密商用密码算法（SM2/SM3/SM4）**，彻底打破了传统 X.509 体系中证书体积庞大、验证耗时、依赖持续在线查询的痛点。

### ✨ 核心特性 (Key Features)

*   🚀 **极致轻量化 (Ultra-Lightweight)**
    *   **体积削减 90%**：基于 ECQV 将公钥与签名融合，配合自研零依赖 CBOR 编码与位掩码字段裁剪，证书大小由传统 X.509（RSA-2048）的 `~675 Bytes` 暴减至 **`67 Bytes`**。
    *   **公钥压缩**：采用 33 字节压缩坐标集存储。
*   🛡️ **高可靠混合撤销管理 (Hybrid Revocation)**
    *   **断网生存能力**：基于配置受限的**布谷鸟过滤器 (Cuckoo Filter)** 实现本地离线撤销校验，数万黑名单仅占极小内存，受限场景实测误判率控制在 `0.05%` 以下。
    *   **在线回落**：支持带有 TTL 内存缓存的在线 OCSP 查验，具备网络抖动自适应容错（在线/离线平滑切换的混合逻辑）。
*   ⚡ **高吞吐统一认证 (High-Throughput Authentication)**
    *   **预计算池 (Precomputation Pool)**：复用底层 `EVP_PKEY` 对象与环境上下文，极大降低设备身份高频验证时的 CPU 开销。
    *   **批量并行验签**：支持将多个签名聚合验证，适应高并发接入（如蜂群起飞瞬间的组网风暴）。
    *   **一站式跨域互认**：提供从证书链校验到基于 SM4 会话密钥 (Session Key) 协商推导的完整链路封装。
*   🛠️ **工业级工程化 (Engineering & OpenSSL 3.x Ready)**
    *   **EVP 路径集成**：底层数学运算全量接入 OpenSSL 3.x EVP 现代 API，保障密码原语的安全性与性能。
    *   **无全局可变状态**：全面应用上下文对象（Context-based）设计，支持严格的多线程并发安全。
    *   **双域 API**：同步提供在内存运行的轻量级 CA/RA 服务端函数与对开发者友好的 PKI Client 接口。

---

## 📂 项目结构 (Repository Structure)

```text
sm2-ecqv-pki/
├── include/
│   ├── sm2_*.h               # 原始底层 API
│   └── sm2ecqv/              # 现代命名空间头文件 (推荐首选包含此目录: #include <sm2ecqv/ecqv.h>)
├── src/
│   ├── ecqv/                 # ECQV 核心逻辑与自研极简 CBOR 编解码
│   ├── revoke/               # 在线 OCSP、增量 CRL 及布谷鸟过滤器
│   ├── auth/                 # 统一认证、预计算与批量验签
│   ├── pki/                  # 高级客户端封装与内存 CA 服务端
│   └── app/                  # 演示程序 (main.c)
├── tests/                    # 完整覆盖的模块化单元测试体系 (覆盖率/稳定性验证)
├── doc/                      # 架构设计与部署说明文档
├── CMakeLists.txt            # 跨平台现代 CMake 构建脚手架
└── Makefile                  # 兼容型备用传统构建脚本
```

---

## 🚀 快速上手 (Quick Start)

### 1. 环境依赖 (Prerequisites)

*   **C 编译器**: 支持 C11 标准 (GCC / Clang / MSVC)
*   **构建工具**: [CMake](https://cmake.org/) (>= 3.14) (+ 可选 Ninja)
*   **依赖库**: [OpenSSL](https://www.openssl.org/) (>= 3.0) (`libcrypto`, `libssl`)

*(Ubuntu/Debian 快速安装: `sudo apt-get install cmake libssl-dev gcc`)*

### 2. 编译与测试 (Build & Test)

强烈推荐使用 CMake 进行跨平台构建：

```bash
# 1. 生成构建配置 (指定 Release 模式)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# 2. 执行编译 (将生成 libsm2ecqv.a, sm2_demo, test_all 等目标产物)
cmake --build build

# 3. 运行全套自动化测试桩
ctest --test-dir build --output-on-failure
```

你可以直接运行 Demo 看完整的生命周期输出：
```bash
./build/sm2_demo
```

---

## 💻 示例代码 (Usage Example)

使用带有上下文参数的现代 API 写一个精简版"发证与验证"全流：

```c
#include <stdio.h>
#include <sm2ecqv/ecqv.h> // 包含核心头文件

int main() {
    // 0. 准备阶段：初始化组、随机数以及 CA 的公私钥对 (示例省略错误校验与具体创建)
    // ...

    // 1. 终端节点 (Client)：生成证书请求 (包含自身 Ephemeral 公钥与 SubjectID 等)
    SM2_ECQV_CERT_REQUEST req;
    SM2_ECQV_PRIVATE_KEY temp_priv;
    SM2_ECQV_create_cert_request(&req, (uint8_t*)"Device-001", 10, SM2_KU_DIGITAL_SIGNATURE, &temp_priv);

    // 2. 认证机构 (CA)：根据请求签发 ECQV 隐式证书 (利用上下文对象控制掩码裁减字段)
    SM2_ECQV_CERT_RESULT result;
    SM2_ECQV_ISSUE_CTX issue_ctx;
    SM2_ECQV_issue_ctx_init(&issue_ctx);
    SM2_ECQV_issue_ctx_set_field_mask(&issue_ctx, SM2_IC_FIELD_SUBJECT_ID); // 仅保留ID，实现极致压缩
    
    // CA 签发隐式证书并计算私钥重建数据 (s)
    SM2_ECQV_ca_generate_cert_with_ctx(&result, &req, NULL, 0, &ca_priv, &ca_pub, &issue_ctx);

    // 3. 终端节点 (Client)：收到 CA 返回的证书 (V) 与私钥重建数据 (s)，演算得出自己的确切公私钥
    SM2_ECQV_PRIVATE_KEY user_priv;
    SM2_ECQV_POINT user_pub;
    SM2_ECQV_reconstruct_keys(&user_priv, &user_pub, &result, &temp_priv, &ca_pub);

    // 4. 其他节点 (Verifier)：验证拿到该隐式证书是否真实合法
    if (SM2_ECQV_verify_cert(&result.cert, &user_pub, &ca_pub) == SM2_ECQV_SUCCESS) {
        printf("隐式证书验证通过！(Certificate Verification Passed!)\n");
    }

    return 0;
}
```

---

## 📊 性能与资源消耗 (Benchmarks)

| 测试比对项           | 传统主流方案                       | `sm2-ecqv-pki` 方案                         | 核心赋能与对比       |
| :------------------- | :--------------------------------- | :------------------------------------------ | :------------------- |
| **证书传输带宽代价** | X.509 DER (RSA-2048): `~675 Bytes` | ECQV+CBOR 隐式证书: **`67 Bytes`**          | **↓ 降幅达 90.1%**   |
| **撤销防线内存开销** | 完整 CRL 内存装载: ~数十MB量级     | 离线式布谷鸟过滤器: **`极小 (可参数配置)`** | 无感知的极低系统负载 |

*(注：测试基线数据来源自本库体系内置的 `test_x509_real_baseline_size` 用例动态产出对比)*

---

## 🤝 参与贡献 (Contributing)

我们非常欢迎且渴望开源代码社区的朋友参与打磨此项目！无论你是想修复一个 typo 注释，还是准备提交核心算法重构优化的 PR，都请：
1. 细致阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解代码风格与提交指引要求（代码全量遵循 OpenSSL标准的 `/* */` 注释及 Allman C 代码风格规范）。
2. 本项目现已配备了完善的 CI（Linux/Windows 双轨编译单元测试验证与 `clang-format` 格式检查链），在请确保您提交 PR 前所有的自动构建核验项目均为绿灯。
3. 可查阅 [CHANGELOG.md](CHANGELOG.md) 了解最新功能发布动态及架构变更说明记录。

---

## 📄 许可证 (License)

本项目严格采用 **[Apache License Version 2.0](LICENSE)** 协议对外开源分发。
您可以根据需要自由决定是否合法地将此库的源码及变体融入到学术科研原型、甚至集成入您的商业工业级核心安全基座产品之中。

---
## English Summary

`sm2-ecqv-pki` is a highly-optimized, high-performance C language Public Key Infrastructure (PKI) stack prototype purpose-built for aviation-grade constrained networks, V2X, and heavily restricted satellite IoT environments. 

It fully implements the **ECQV (Elliptic Curve Qu Vanstone) Implicit Certificate** scheme smoothly merged with Chinese standard commercial cryptographic algorithms (**SM2/SM3/SM4**). By mitigating verbose X.509 chains overhead, utilizing robust fallback offline-revocation strategies bounded with memory-tight Cuckoo filters, and achieving high-throughput signatures pool optimizations running purely on top of modernized OpenSSL 3.x EVP APIs underneath, the library stands completely thread-safe.

With zero-dependency custom CBOR serialization, it enables secure device bootstrapping and credential handshakes with under **$10\%$** of traditional X.509 DER bandwidth footprints (achieving ~67 Bytes per end-entity cert wrapper).

For code contribution guidelines and standardized issue tracking rules, please refer proactively to `CONTRIBUTING.md`.
