/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SM2ECQV_REVOKE_H
#define SM2ECQV_REVOKE_H

#include "../sm2_revocation.h"

typedef sm2_revocation_ctx_t SM2_REV_CTX;
typedef sm2_rev_status_t SM2_REV_STATUS;
typedef sm2_rev_source_t SM2_REV_SOURCE;
typedef sm2_crl_delta_item_t SM2_REV_CRL_DELTA_ITEM;
typedef sm2_crl_delta_t SM2_REV_CRL_DELTA;
typedef sm2_ocsp_client_cfg_t SM2_REV_OCSP_CFG;
typedef sm2_ic_error_t SM2_REV_ERROR;

#define SM2_REV_SUCCESS SM2_IC_SUCCESS

#define SM2_REV_init sm2_revocation_init
#define SM2_REV_cleanup sm2_revocation_cleanup
#define SM2_REV_set_online sm2_revocation_set_online
#define SM2_REV_config_ocsp sm2_revocation_config_ocsp
#define SM2_REV_config_local_filter sm2_revocation_config_local_filter
#define SM2_REV_apply_crl_delta sm2_revocation_apply_crl_delta
#define SM2_REV_query sm2_revocation_query
#define SM2_REV_local_count sm2_revocation_local_count
#define SM2_REV_crl_version sm2_revocation_crl_version

#endif
