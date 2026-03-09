# INSTALL

## 依赖

- C11 编译器
- OpenSSL 3.x
- CMake 3.14+

## Linux

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev

cmake -S . -B build
cmake --build build -j 1
ctest --test-dir build --output-on-failure
```

## Windows（MSYS2 UCRT64）

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
                  mingw-w64-ucrt-x86_64-cmake \
                  mingw-w64-ucrt-x86_64-ninja \
                  mingw-w64-ucrt-x86_64-openssl

cmake -S . -B build -G Ninja
cmake --build build -j 1
ctest --test-dir build --output-on-failure
```

## 快速验证

聚合验证：

```bash
./build/test_all.exe
```

按 suite 验证：

```bash
ctest --test-dir build --output-on-failure
```

当前构建与测试入口已经统一到 CMake/CTest，不再保留旧的 legacy 编译链路说明。

## Demo

```bash
cmake --build build --target sm2_test_cert_flow -j 1
./build/sm2_test_cert_flow.exe

cmake --build build --target sm2_test_merkle_flow -j 1
./build/sm2_test_merkle_flow.exe
```
