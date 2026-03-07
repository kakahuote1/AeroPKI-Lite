# =========================================================================
# Aviation Lightweight PKI System - Build Configuration
# Platforms: Linux/macOS (default), Windows (MSYS2/MinGW)
# =========================================================================

CC = gcc
CFLAGS = -Wall -Wextra -I./include -D_POSIX_C_SOURCE=200809L -O2
LDFLAGS = -lssl -lcrypto

OUT_DIR = out
OBJ_DIR = $(OUT_DIR)/obj

TARGET_DEMO = $(OUT_DIR)/sm2_implicit_cert_demo.exe
TARGET_TEST = $(OUT_DIR)/run_tests.exe

CORE_SRCS = src/ecqv/ecqv.c src/revoke/revoke.c src/revoke/merkle.c src/revoke/merkle_cbor.c src/revoke/merkle_epoch.c src/revoke/merkle_k_anon.c src/auth/auth.c src/pki/crypto.c src/pki/service.c src/pki/client.c
DEMO_SRC = src/app/main.c
TEST_SRCS = tests/test_common.c tests/test_ecqv.c tests/test_revoke.c tests/test_merkle.c tests/test_auth.c tests/test_pki.c tests/test_main.c

CORE_OBJS = $(OBJ_DIR)/ecqv.o $(OBJ_DIR)/revoke.o $(OBJ_DIR)/merkle.o $(OBJ_DIR)/merkle_cbor.o $(OBJ_DIR)/merkle_epoch.o $(OBJ_DIR)/merkle_k_anon.o $(OBJ_DIR)/auth.o $(OBJ_DIR)/crypto.o $(OBJ_DIR)/service.o $(OBJ_DIR)/client.o
DEMO_OBJ = $(OBJ_DIR)/main.o
TEST_OBJS = $(OBJ_DIR)/test_common.o $(OBJ_DIR)/test_ecqv.o $(OBJ_DIR)/test_revoke.o $(OBJ_DIR)/test_merkle.o $(OBJ_DIR)/test_auth.o $(OBJ_DIR)/test_pki.o $(OBJ_DIR)/test_main.o

.PHONY: all run test legacy_test clean clean_linux help dirs

all: $(TARGET_DEMO)

dirs:
	@mkdir -p $(OUT_DIR)
	@mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/ecqv.o: src/ecqv/ecqv.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/revoke.o: src/revoke/revoke.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/merkle.o: src/revoke/merkle.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/merkle_cbor.o: src/revoke/merkle_cbor.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/merkle_epoch.o: src/revoke/merkle_epoch.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/merkle_k_anon.o: src/revoke/merkle_k_anon.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/auth.o: src/auth/auth.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/crypto.o: src/pki/crypto.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/service.o: src/pki/service.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/client.o: src/pki/client.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(DEMO_OBJ): $(DEMO_SRC) | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/test_%.o: tests/test_%.c | dirs
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET_DEMO): $(CORE_OBJS) $(DEMO_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TARGET_TEST): $(CORE_OBJS) $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

run: $(TARGET_DEMO)
	@echo [EXEC] Starting Demo...
	@./$(TARGET_DEMO)

legacy_test: $(TARGET_TEST)
	@echo [EXEC] Running Tests...
	@./$(TARGET_TEST)

test:
	@echo [EXEC] Running Tests...
	@if command -v cmake >/dev/null 2>&1; then \
		cmake -S . -B build && \
		cmake --build build && \
		ctest --test-dir build --output-on-failure; \
	else \
		echo [INFO] cmake not found, fallback to legacy build; \
		$(MAKE) legacy_test; \
	fi

clean:
	@echo [CLEAN] Removing artifacts...
	-@del /Q /S out\*.o 2>NUL
	-@del /Q /S out\*.exe 2>NUL
	-@del /Q /S src\*.o 2>NUL
	-@del /Q /S *.o 2>NUL
	-@del /Q /S *.exe 2>NUL

clean_linux:
	@echo [CLEAN] Removing artifacts (Linux/macOS)...
	rm -rf $(OUT_DIR) *.o *.exe

help:
	@echo Available targets: all, run, test, clean, clean_linux
