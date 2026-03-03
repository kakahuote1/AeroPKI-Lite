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

