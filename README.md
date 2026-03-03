# AeroPKI-Lite

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-C11-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

> 基于 SM2/SM3/SM4 算法的 ECQV 隐式证书 PKI 协议栈，专为受限航空网络与无人机机载环境设计。

[English](#english-summary) | [中文说明](#项目简介)

---

## 📖 项目简介

`AeroPKI-Lite` 是一个 C11 语言编写的 PKI 协议栈，底层依赖 OpenSSL 3.0 的 EVP 接口。项目中融合了 ECQV (Elliptic Curve Qu Vanstone) 隐式证书机制与国密商用密码算法（SM2/SM3/SM4），提供证书的签发、解析、验证及撤销管理功能。

### 核心设计

*   **证书体积缩减**：基于 ECQV 将公钥与签名过程融合，结合自定义 CBOR 编码规范与位掩码机制屏蔽可选字段。在裁剪配置下，隐式证书序列化体积为 `67 Bytes`（供参考：X.509 RSA-2048 证书体积约 `675 Bytes`）。
*   **混合撤销管理**：支持在线 OCSP 查询（带 TTL 缓存机制）以及在网络受限时的离线降级查询。离线模式基于布谷鸟过滤器 (Cuckoo Filter) 进行匹配，支持增量 CRL 更新。
*   **认证与并发控制**：
    *   **预计算池**：在内存中预生成签名素材复用底层上下文，降低计算开销。
    *   **批量并行验签**：支持将多个请求聚合至队列进行批量验证。
    *   **高阶会话接口**：提供基于 SM4 的通信加解密、跨域信任链验证及密钥协商 (Key Agreement) 的高级封装。
*   **工程化结构**：规避全局可变变量，核心逻辑建立在上下文对象（Context-based）上层，保证多线程安全。

---

## 📂 项目结构

```text
AeroPKI-Lite/
├── include/
│   ├── sm2_*.h               # 原始底层公共 API (如 sm2_implicit_cert.h, sm2_auth.h)
│   └── sm2ecqv/              # 现代命名空间风格头文件
├── src/
│   ├── ecqv/                 # ECQV 核心运算逻辑与 CBOR 序列化实现
│   ├── revoke/               # OCSP 发送、增量 CRL 解析及布谷鸟过滤器
│   ├── auth/                 # 统一认证封装、预计算池与批量验证引擎
│   ├── pki/                  # CA/RA 服务端逻辑、客户端封装及会话密钥推导
│   └── app/                  # 运行时示例 (main.c)
├── tests/                    # 单元测试与边界案例（59个公开API全覆盖）
├── CMakeLists.txt            # CMake 构建脚本
└── Makefile                  # 传统环境编译备用脚本
```

---

## 🚀 编译与运行

### 环境依赖

*   **编译器**: 支持 C11 标准 (GCC / Clang / MSVC)
*   **构建工具**: CMake (>= 3.14)
*   **外部依赖**: OpenSSL (>= 3.0) (`libcrypto`, `libssl`)

### 构建步骤

```bash
# 1. 生成构建目录 (默认 Release)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# 2. 编译目标二进制文件
cmake --build build -j 4

# 3. 运行本地自动化测试序列
ctest --test-dir build --output-on-failure
```

---

## 💻 编程示例

本项目提供分层的 API，以下代码展示了如何利用高阶层面的 `PKI Service` 与 `Client` API 完成"注册-请求-签发-验签"的完整流程：

```c
#include <stdio.h>
#include <string.h>
#include <sm2_pki_service.h>
#include <sm2_pki_client.h>

int main() {
    // 1. 初始化 PKI内存服务 (服务端 CA 角色)
    sm2_pki_service_ctx_t svc;
    const uint8_t issuer[] = "ROOT_CA";
    sm2_pki_service_init(&svc, issuer, sizeof(issuer)-1, 64, 300, 1000);

    // 2. 终端节点身份验证与证书请求
    const uint8_t device_id[] = "NODE_01";
    sm2_pki_identity_register(&svc, device_id, sizeof(device_id)-1, SM2_KU_DIGITAL_SIGNATURE);

    sm2_ic_cert_request_t req;
    sm2_private_key_t dev_temp_priv;
    sm2_pki_cert_request(&svc, device_id, sizeof(device_id)-1, &req, &dev_temp_priv);

    // 3. CA 分析请求并签发隐式证书
    sm2_ic_cert_result_t cert_res;
    sm2_pki_cert_issue(&svc, &req, &cert_res);

    // 4. 初始化终端节点 Client 上下文（同步 CA 公钥）
    sm2_ec_point_t ca_pub;
    sm2_pki_service_get_ca_public_key(&svc, &ca_pub);

    sm2_pki_client_ctx_t client;
    sm2_pki_client_init(&client, &ca_pub, &svc.rev_ctx);
    
    // 终端节点根据返回的重构数据，推演自身合法公私钥对
    sm2_pki_client_import_cert(&client, &cert_res, &dev_temp_priv, &ca_pub);

    // 5. 客户端利用自身私钥对应用层消息进行签名
    const uint8_t msg[] = "HELLO_PKI";
    sm2_auth_signature_t sig;
    sm2_pki_sign(&client, msg, sizeof(msg)-1, &sig);

    // 6. 其他接收方节点：验证发送者的证书与最终签名
    sm2_auth_request_t auth_req = {
        &client.cert, &client.public_key, msg, sizeof(msg)-1, &sig
    };
    size_t matched_ca_idx;
    if (sm2_pki_verify(&client, &auth_req, 1010, &matched_ca_idx) == SM2_PKI_SUCCESS) {
        printf("Signature and Implicit Certificate logic verified.\n");
    }

    // 资源回落与重置
    sm2_pki_client_cleanup(&client);
    sm2_pki_service_cleanup(&svc);
    
    return 0;
}
```

---

## 🤝 参与贡献

参与代码贡献（Issue 或 Pull Request）前，请遵循以下流程：
1. 参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 以了解项目的编码规范体系与提交流程，新增 C 代码需遵循 OpenSSL 的内置注释模式及 Allman 缩进。
2. 提交合并请求前，请通过本地 CMake 流程保证构建与所有 CTest 用例集顺利执行（0 Failed）。
3. 有关库版本的更迭及其底层机制变化，查阅 [CHANGELOG.md](CHANGELOG.md)。

---

## 📄 许可证

本项目源代码采用 [Apache License Version 2.0](LICENSE) 协议发布与授权。

---

## English Summary

`AeroPKI-Lite` is a highly contained, C11-based Public Key Infrastructure (PKI) subsystem explicitly built upon OpenSSL 3.0's EVP logic patterns. It structurally implements the Elliptic Curve Qu Vanstone (ECQV) implicit certificate generation schema intertwined seamlessly with the standard commercial cryptographic algorithms SM2/SM3/SM4. 

The project encapsulates standard features scaling up to: structural certification issuance, internal compact CBOR mapping processes, a dual-layer hybrid revocation approach supporting offline Cuckoo Filtration bounds aside online OCSP updates mapping scenarios and a standalone validation mechanism integrated with context precomputation sign pooling and key agreement modules.

By masking subset parameters and unifying explicit signatures towards pure implicit variants natively into points equations, it yields sizes as low as `67 Bytes` per certificate envelope on its output stream. Refer proactively towards `CONTRIBUTING.md` prior to codebase alterations.
