/**
 * @file sm2_implicit_cert.c
 * @brief ECQV 隐式证书算法核心实现
 * @details 基于 OpenSSL 实现了 SM2 曲线下的 ECQV 协议，包含点乘、大数运算及 CBOR 编解码。
 */

#include "sm2_implicit_cert.h"
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>

// ==========================================
// 内部静态辅助函数 (不暴露给外部)
// ==========================================

/**
 * @brief 二进制转 BIGNUM
 */
static BIGNUM* utils_bin_to_bn(const uint8_t *buf, size_t len) {
    return BN_bin2bn(buf, len, NULL);
}

/**
 * @brief BIGNUM 转定长二进制 (左补0)
 */
static void utils_bn_to_bin(const BIGNUM *bn, uint8_t *buf, size_t len) {
    int num_bytes = BN_num_bytes(bn);
    int offset = len - num_bytes;
    if (offset < 0) offset = 0;
    memset(buf, 0, len);
    BN_bn2bin(bn, buf + offset);
}

/**
 * @brief 获取 SM2 椭圆曲线群对象
 */
static EC_GROUP* utils_get_sm2_group() {
    return EC_GROUP_new_by_curve_name(NID_sm2);
}

/**
 * @brief 内部哈希计算：h = Hash(Cert_Encoding)
 * @note 这里的序列化仅用于哈希计算绑定，非传输格式
 */
static sm2_ic_error_t utils_calc_cert_hash(const sm2_implicit_cert_t *cert, BIGNUM *h_bn, const BIGNUM *order, BN_CTX *ctx) {
    uint8_t hash_buf[SM3_DIGEST_LENGTH];
    uint8_t buffer[1024]; 
    size_t offset = 0;
    
    // 简单序列化关键字段以进行哈希绑定
    buffer[offset++] = cert->type;
    // 序列号
    memcpy(buffer + offset, &cert->serial_number, 8); offset += 8;
    // 主体ID
    memcpy(buffer + offset, cert->subject_id, cert->subject_id_len); offset += cert->subject_id_len;
    // 有效期
    memcpy(buffer + offset, &cert->valid_from, 8); offset += 8;
    memcpy(buffer + offset, &cert->valid_duration, 8); offset += 8;
    // 密钥用途
    buffer[offset++] = cert->key_usage;
    // 公钥重构值 V
    memcpy(buffer + offset, cert->public_recon_key.x, 32); offset += 32;
    memcpy(buffer + offset, cert->public_recon_key.y, 32); offset += 32;
    
    // 计算 SM3
    if (sm2_ic_sm3_hash(buffer, offset, hash_buf) != SM2_IC_SUCCESS) return SM2_IC_ERR_CRYPTO;
    
    // 转为大数并模 n
    BN_bin2bn(hash_buf, SM3_DIGEST_LENGTH, h_bn);
    if (!BN_nnmod(h_bn, h_bn, order, ctx)) {
        return SM2_IC_ERR_CRYPTO;
    }
    return SM2_IC_SUCCESS;
}

// ==========================================
// 基础算法接口实现
// ==========================================

sm2_ic_error_t sm2_ic_generate_random(uint8_t *buf, size_t len) {
    if (RAND_bytes(buf, len) != 1) {
        return SM2_IC_ERR_CRYPTO;
    }
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_ic_sm3_hash(const uint8_t *input, size_t input_len, uint8_t *output) {
    unsigned int len = SM3_DIGEST_LENGTH;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return SM2_IC_ERR_MEMORY;

    const EVP_MD *md = EVP_sm3();
    if (md == NULL) {
        EVP_MD_CTX_free(mdctx);
        return SM2_IC_ERR_CRYPTO; 
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, input, input_len) != 1 ||
        EVP_DigestFinal_ex(mdctx, output, &len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return SM2_IC_ERR_CRYPTO;
    }
    EVP_MD_CTX_free(mdctx);
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_ic_sm2_point_mult(sm2_ec_point_t *point, const uint8_t *scalar, size_t scalar_len, const sm2_ec_point_t *base_point) {
    if (!point || !scalar) return SM2_IC_ERR_PARAM;

    EC_GROUP *group = utils_get_sm2_group();
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *k = utils_bin_to_bn(scalar, scalar_len);
    EC_POINT *R = EC_POINT_new(group);
    int res = 0;

    if (base_point == NULL) {
        // 计算 k * G
        res = EC_POINT_mul(group, R, k, NULL, NULL, ctx);
    } else {
        // 计算 k * P
        EC_POINT *P = EC_POINT_new(group);
        uint8_t buf[65];
        buf[0] = 0x04; // Uncompressed prefix
        memcpy(buf + 1, base_point->x, 32);
        memcpy(buf + 33, base_point->y, 32);
        EC_POINT_oct2point(group, P, buf, 65, ctx);

        res = EC_POINT_mul(group, R, NULL, P, k, ctx);
        EC_POINT_free(P);
    }

    if (res == 1) {
        uint8_t point_buf[65];
        EC_POINT_point2oct(group, R, POINT_CONVERSION_UNCOMPRESSED, point_buf, 65, ctx);
        memcpy(point->x, point_buf + 1, 32);
        memcpy(point->y, point_buf + 33, 32);
        res = SM2_IC_SUCCESS;
    } else {
        res = SM2_IC_ERR_CRYPTO;
    }

    BN_free(k); EC_POINT_free(R); EC_GROUP_free(group); BN_CTX_free(ctx);
    return res;
}

// ==========================================
// ECQV 核心业务流程实现
// ==========================================

sm2_ic_error_t sm2_ic_create_cert_request(sm2_ic_cert_request_t *request, const uint8_t *subject_id, size_t subject_id_len, uint8_t key_usage, sm2_private_key_t *temp_private_key) {
    if (!request || !subject_id || !temp_private_key) return SM2_IC_ERR_PARAM;
    if (subject_id_len > sizeof(request->subject_id)) return SM2_IC_ERR_PARAM;

    EC_GROUP *group = utils_get_sm2_group();
    BN_CTX *ctx = BN_CTX_new();
    
    // 1. 生成随机数 x (临时私钥)
    BIGNUM *x = BN_new();
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_rand_range(x, order);
    
    // 2. 计算 X = x * G
    EC_POINT *X = EC_POINT_new(group);
    EC_POINT_mul(group, X, x, NULL, NULL, ctx);
    
    // 3. 导出结果
    utils_bn_to_bin(x, temp_private_key->d, 32);
    
    uint8_t point_buf[65];
    EC_POINT_point2oct(group, X, POINT_CONVERSION_UNCOMPRESSED, point_buf, 65, ctx);
    memcpy(request->temp_public_key.x, point_buf + 1, 32);
    memcpy(request->temp_public_key.y, point_buf + 33, 32);
    
    memcpy(request->subject_id, subject_id, subject_id_len);
    request->subject_id_len = subject_id_len;
    request->key_usage = key_usage;

    BN_free(x); EC_POINT_free(X); EC_GROUP_free(group); BN_CTX_free(ctx);
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_ic_ca_generate_cert(sm2_ic_cert_result_t *result, const sm2_ic_cert_request_t *request, const uint8_t *issuer_id, size_t issuer_id_len, const sm2_private_key_t *ca_private_key, const sm2_ec_point_t *ca_public_key) {
    (void)ca_public_key; // 避免未使用参数警告
    if (!result || !request || !ca_private_key) return SM2_IC_ERR_PARAM;

    EC_GROUP *group = utils_get_sm2_group();
    BN_CTX *ctx = BN_CTX_new();
    const BIGNUM *order = EC_GROUP_get0_order(group);
    
    BIGNUM *k = BN_new();
    BIGNUM *d_ca = utils_bin_to_bn(ca_private_key->d, 32);
    EC_POINT *X = EC_POINT_new(group);
    EC_POINT *V = EC_POINT_new(group);
    BIGNUM *h = BN_new();
    BIGNUM *s = BN_new();
    EC_POINT *kG = EC_POINT_new(group);
    BIGNUM *tmp = BN_new();

    // 还原临时公钥 X
    uint8_t point_buf[65];
    point_buf[0] = 0x04;
    memcpy(point_buf + 1, request->temp_public_key.x, 32);
    memcpy(point_buf + 33, request->temp_public_key.y, 32);
    EC_POINT_oct2point(group, X, point_buf, 65, ctx);

    // 1. CA 生成 k
    BN_rand_range(k, order);

    // 2. 计算 V = X + k * G
    EC_POINT_mul(group, kG, k, NULL, NULL, ctx); 
    EC_POINT_add(group, V, X, kG, ctx);         

    // 3. 填充证书信息
    result->cert.type = SM2_CERT_TYPE_IMPLICIT;
    result->cert.serial_number = (uint64_t)time(NULL); // 生产环境应使用序列号生成器
    
    memcpy(result->cert.subject_id, request->subject_id, request->subject_id_len);
    result->cert.subject_id_len = request->subject_id_len;
    
    memcpy(result->cert.issuer_id, issuer_id, issuer_id_len);
    result->cert.issuer_id_len = issuer_id_len;
    
    result->cert.valid_from = (uint64_t)time(NULL);
    result->cert.valid_duration = 365 * 24 * 3600; // 默认一年
    result->cert.key_usage = request->key_usage;

    // 导出 V
    EC_POINT_point2oct(group, V, POINT_CONVERSION_UNCOMPRESSED, point_buf, 65, ctx);
    memcpy(result->cert.public_recon_key.x, point_buf + 1, 32);
    memcpy(result->cert.public_recon_key.y, point_buf + 33, 32);

    // 4. 计算 h = SM3(Cert)
    sm2_ic_error_t hash_ret = utils_calc_cert_hash(&result->cert, h, order, ctx);
    if (hash_ret != SM2_IC_SUCCESS) {
        goto clean_up;
    }

    // 5. 计算 S = (h * k + d_CA) mod n
    BN_mod_mul(tmp, h, k, order, ctx);      
    BN_mod_add(s, tmp, d_ca, order, ctx);   

    // 导出 S
    utils_bn_to_bin(s, result->private_recon_value, 32);
    hash_ret = SM2_IC_SUCCESS;

clean_up:
    EC_GROUP_free(group); BN_CTX_free(ctx); BN_free(k); BN_free(d_ca);
    EC_POINT_free(X); EC_POINT_free(V); BN_free(h); BN_free(s); 
    BN_free(tmp); EC_POINT_free(kG);
    
    return hash_ret;
}

sm2_ic_error_t sm2_ic_reconstruct_keys(sm2_private_key_t *private_key, sm2_ec_point_t *public_key, const sm2_ic_cert_result_t *cert_result, const sm2_private_key_t *temp_private_key, const sm2_ec_point_t *ca_public_key) {
    (void)ca_public_key;
    EC_GROUP *group = utils_get_sm2_group();
    BN_CTX *ctx = BN_CTX_new();
    const BIGNUM *order = EC_GROUP_get0_order(group);

    BIGNUM *x = utils_bin_to_bn(temp_private_key->d, 32);
    BIGNUM *s = utils_bin_to_bn(cert_result->private_recon_value, 32);
    BIGNUM *h = BN_new();
    BIGNUM *d_u = BN_new();
    BIGNUM *tmp = BN_new();
    EC_POINT *Q = EC_POINT_new(group);
    
    // 1. 计算 h = SM3(Cert)
    if (utils_calc_cert_hash(&cert_result->cert, h, order, ctx) != SM2_IC_SUCCESS) {
        EC_GROUP_free(group); BN_CTX_free(ctx); BN_free(x); BN_free(s);
        BN_free(h); BN_free(d_u); BN_free(tmp); EC_POINT_free(Q);
        return SM2_IC_ERR_CRYPTO;
    }

    // 2. 计算 d_U = (h * x + s) mod n
    BN_mod_mul(tmp, h, x, order, ctx);    
    BN_mod_add(d_u, tmp, s, order, ctx);  
    
    // 导出最终私钥
    utils_bn_to_bin(d_u, private_key->d, 32);

    // 3. 计算最终公钥 Q_U = d_U * G
    EC_POINT_mul(group, Q, d_u, NULL, NULL, ctx);
    
    // 导出最终公钥
    uint8_t point_buf[65];
    EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED, point_buf, 65, ctx);
    memcpy(public_key->x, point_buf + 1, 32);
    memcpy(public_key->y, point_buf + 33, 32);

    EC_GROUP_free(group); BN_CTX_free(ctx); BN_free(x); BN_free(s);
    BN_free(h); BN_free(d_u); BN_free(tmp); EC_POINT_free(Q);

    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_ic_verify_cert(const sm2_implicit_cert_t *cert, const sm2_ec_point_t *public_key, const sm2_ec_point_t *ca_public_key) {
    EC_GROUP *group = utils_get_sm2_group();
    BN_CTX *ctx = BN_CTX_new();
    const BIGNUM *order = EC_GROUP_get0_order(group);
    
    BIGNUM *h = BN_new();
    EC_POINT *Q_U = EC_POINT_new(group);   
    EC_POINT *P_CA = EC_POINT_new(group);  
    EC_POINT *V = EC_POINT_new(group);     
    EC_POINT *Calc_Q = EC_POINT_new(group); 
    EC_POINT *hV = EC_POINT_new(group);

    // 转换输入点
    uint8_t buf[65];
    buf[0] = 0x04;
    
    memcpy(buf+1, public_key->x, 32); memcpy(buf+33, public_key->y, 32);
    EC_POINT_oct2point(group, Q_U, buf, 65, ctx);

    memcpy(buf+1, ca_public_key->x, 32); memcpy(buf+33, ca_public_key->y, 32);
    EC_POINT_oct2point(group, P_CA, buf, 65, ctx);
    
    memcpy(buf+1, cert->public_recon_key.x, 32); memcpy(buf+33, cert->public_recon_key.y, 32);
    EC_POINT_oct2point(group, V, buf, 65, ctx);

    // 1. 计算 h = SM3(Cert)
    if (utils_calc_cert_hash(cert, h, order, ctx) != SM2_IC_SUCCESS) {
        EC_GROUP_free(group); BN_CTX_free(ctx); BN_free(h);
        EC_POINT_free(Q_U); EC_POINT_free(P_CA); EC_POINT_free(V); 
        EC_POINT_free(Calc_Q); EC_POINT_free(hV);
        return SM2_IC_ERR_CRYPTO;
    }

    // 2. 计算 Calc_Q = h * V + P_CA
    EC_POINT_mul(group, hV, NULL, V, h, ctx);     // hV = h * V
    EC_POINT_add(group, Calc_Q, hV, P_CA, ctx);   // Calc_Q = hV + P_CA

    // 3. 比较
    int ret = SM2_IC_ERR_VERIFY;
    if (EC_POINT_cmp(group, Q_U, Calc_Q, ctx) == 0) {
        ret = SM2_IC_SUCCESS;
    }

    EC_GROUP_free(group); BN_CTX_free(ctx); BN_free(h);
    EC_POINT_free(Q_U); EC_POINT_free(P_CA); EC_POINT_free(V); 
    EC_POINT_free(Calc_Q); EC_POINT_free(hV);
    
    return ret;
}

// ==========================================
// CBOR 编码与解码实现 (Zero-Dependency)
// ==========================================

/* CBOR 辅助：写入头部 */
static void utils_cbor_write_head(uint8_t *buf, size_t *offset, uint8_t major_type, uint64_t val) {
    uint8_t *p = buf + *offset;
    major_type <<= 5;
    
    if (val < 24) {
        *p = major_type | (uint8_t)val;
        (*offset)++;
    } else if (val <= 0xFF) {
        *p++ = major_type | 24;
        *p = (uint8_t)val;
        (*offset) += 2;
    } else if (val <= 0xFFFF) {
        *p++ = major_type | 25;
        *p++ = (uint8_t)(val >> 8);
        *p = (uint8_t)(val);
        (*offset) += 3;
    } else if (val <= 0xFFFFFFFF) {
        *p++ = major_type | 26;
        *p++ = (uint8_t)(val >> 24);
        *p++ = (uint8_t)(val >> 16);
        *p++ = (uint8_t)(val >> 8);
        *p = (uint8_t)(val);
        (*offset) += 5;
    } else {
        *p++ = major_type | 27;
        for (int i = 7; i >= 0; i--) {
            *p++ = (uint8_t)(val >> (i * 8));
        }
        (*offset) += 9;
    }
}

/* CBOR 辅助：读取头部 */
static sm2_ic_error_t utils_cbor_read_head(const uint8_t *buf, size_t len, size_t *offset, uint8_t expected_major, uint64_t *val) {
    if (*offset >= len) return SM2_IC_ERR_CBOR;
    
    uint8_t byte = buf[*offset];
    uint8_t major = byte >> 5;
    uint8_t info = byte & 0x1F;
    (*offset)++;
    
    if (major != expected_major) return SM2_IC_ERR_CBOR;
    
    if (info < 24) {
        *val = info;
    } else if (info == 24) {
        if (*offset + 1 > len) return SM2_IC_ERR_CBOR;
        *val = buf[(*offset)++];
    } else if (info == 25) {
        if (*offset + 2 > len) return SM2_IC_ERR_CBOR;
        *val = ((uint64_t)buf[*offset] << 8) | buf[*offset+1];
        (*offset) += 2;
    } else if (info == 26) {
        if (*offset + 4 > len) return SM2_IC_ERR_CBOR;
        *val = 0;
        for (int i=0; i<4; i++) *val = (*val << 8) | buf[(*offset)++];
    } else if (info == 27) {
        if (*offset + 8 > len) return SM2_IC_ERR_CBOR;
        *val = 0;
        for (int i=0; i<8; i++) *val = (*val << 8) | buf[(*offset)++];
    } else {
        return SM2_IC_ERR_CBOR;
    }
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_ic_cbor_encode_cert(uint8_t *output, size_t *output_len, const sm2_implicit_cert_t *cert) {
    if (!output || !output_len || !cert) return SM2_IC_ERR_PARAM;
    
    size_t offset = 0;
    if (*output_len < 256) return SM2_IC_ERR_MEMORY; 

    // CBOR 数组头：8个元素
    utils_cbor_write_head(output, &offset, 4, 8);

    // 1. Type (Int)
    utils_cbor_write_head(output, &offset, 0, cert->type);
    // 2. Serial (Int)
    utils_cbor_write_head(output, &offset, 0, cert->serial_number);
    // 3. SubjectID (Bytes)
    utils_cbor_write_head(output, &offset, 2, cert->subject_id_len);
    memcpy(output + offset, cert->subject_id, cert->subject_id_len); offset += cert->subject_id_len;
    // 4. IssuerID (Bytes)
    utils_cbor_write_head(output, &offset, 2, cert->issuer_id_len);
    memcpy(output + offset, cert->issuer_id, cert->issuer_id_len); offset += cert->issuer_id_len;
    // 5. ValidFrom (Int)
    utils_cbor_write_head(output, &offset, 0, cert->valid_from);
    // 6. Duration (Int)
    utils_cbor_write_head(output, &offset, 0, cert->valid_duration);
    // 7. KeyUsage (Int)
    utils_cbor_write_head(output, &offset, 0, cert->key_usage);
    // 8. PublicReconKey V (Bytes, 64 bytes)
    utils_cbor_write_head(output, &offset, 2, 64);
    memcpy(output + offset, cert->public_recon_key.x, 32);
    memcpy(output + offset + 32, cert->public_recon_key.y, 32);
    offset += 64;

    *output_len = offset;
    return SM2_IC_SUCCESS;
}

sm2_ic_error_t sm2_ic_cbor_decode_cert(sm2_implicit_cert_t *cert, const uint8_t *input, size_t input_len) {
    if (!cert || !input) return SM2_IC_ERR_PARAM;
    size_t offset = 0;
    uint64_t val = 0;

    // 0. Array(8)
    if (utils_cbor_read_head(input, input_len, &offset, 4, &val) != SM2_IC_SUCCESS || val != 8) return SM2_IC_ERR_CBOR;
    // 1. Type
    if (utils_cbor_read_head(input, input_len, &offset, 0, &val) != SM2_IC_SUCCESS) return SM2_IC_ERR_CBOR;
    cert->type = (uint8_t)val;
    // 2. Serial
    if (utils_cbor_read_head(input, input_len, &offset, 0, &val) != SM2_IC_SUCCESS) return SM2_IC_ERR_CBOR;
    cert->serial_number = val;
    // 3. SubjectID
    if (utils_cbor_read_head(input, input_len, &offset, 2, &val) != SM2_IC_SUCCESS) return SM2_IC_ERR_CBOR;
    cert->subject_id_len = (size_t)val;
    if (offset + cert->subject_id_len > input_len) return SM2_IC_ERR_CBOR;
    memcpy(cert->subject_id, input + offset, cert->subject_id_len); offset += cert->subject_id_len;
    // 4. IssuerID
    if (utils_cbor_read_head(input, input_len, &offset, 2, &val) != SM2_IC_SUCCESS) return SM2_IC_ERR_CBOR;
    cert->issuer_id_len = (size_t)val;
    if (offset + cert->issuer_id_len > input_len) return SM2_IC_ERR_CBOR;
    memcpy(cert->issuer_id, input + offset, cert->issuer_id_len); offset += cert->issuer_id_len;
    // 5. ValidFrom
    if (utils_cbor_read_head(input, input_len, &offset, 0, &val) != SM2_IC_SUCCESS) return SM2_IC_ERR_CBOR;
    cert->valid_from = val;
    // 6. Duration
    if (utils_cbor_read_head(input, input_len, &offset, 0, &val) != SM2_IC_SUCCESS) return SM2_IC_ERR_CBOR;
    cert->valid_duration = (uint64_t)val;
    // 7. KeyUsage
    if (utils_cbor_read_head(input, input_len, &offset, 0, &val) != SM2_IC_SUCCESS) return SM2_IC_ERR_CBOR;
    cert->key_usage = (uint8_t)val;
    // 8. V
    if (utils_cbor_read_head(input, input_len, &offset, 2, &val) != SM2_IC_SUCCESS || val != 64) return SM2_IC_ERR_CBOR;
    if (offset + 64 > input_len) return SM2_IC_ERR_CBOR;
    memcpy(cert->public_recon_key.x, input + offset, 32);
    memcpy(cert->public_recon_key.y, input + offset + 32, 32);
    offset += 64;

    return SM2_IC_SUCCESS;
}