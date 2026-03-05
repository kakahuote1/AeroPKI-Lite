# INSTALL

## 1. 依赖

- C 编译器（GCC/Clang，支持 C11）
- OpenSSL 3.x（`libcrypto` / `libssl`）
- CMake 3.14+

## 2. Linux

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev

cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## 3. Windows（MSYS2 UCRT64）

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
                  mingw-w64-ucrt-x86_64-cmake \
                  mingw-w64-ucrt-x86_64-ninja \
                  mingw-w64-ucrt-x86_64-openssl

cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

## 4. 兼容入口

若已有 `make`，可使用：

```bash
make test
```

行为说明：
- 若检测到 `cmake`，自动走 `cmake + ctest`。
- 若未检测到 `cmake`，回退 legacy 编译测试链路。


## 5. Phase6 离线同步快速验证

```bash
cmake --build build_local -j 1
.\\build_local\\test_all.exe
```

重点看以下测试/指标：

- `test_revocation_sync_bidirectional_merge_converge`
- `test_revocation_sync_ttl_stale_refresh`
- `test_revocation_sync_fragment_and_rate_limit`
- `test_revocation_sync_metrics_rounds_bandwidth`
- `test_revocation_sync_bandwidth_reduction_vs_full`
- `test_revocation_sync_constrained_fpr_after_sync`

验收口径：

- 收敛轮次：`[SYNC-METRIC] rounds` 应满足 task 约束
- 带宽下降：`[SYNC-BW] ratio` 体现 delta 相对 full 的下降
- 受限参数误判率：`[SYNC-FPR-CONSTRAINED]` 应在阈值内
