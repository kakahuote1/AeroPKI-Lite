/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

void run_test_revoke_core_suite(void);
void run_test_revoke_sync_suite(void);
void run_test_revoke_bft_suite(void);

void run_test_revoke_suite(void)
{
    run_test_revoke_core_suite();
    run_test_revoke_sync_suite();
    run_test_revoke_bft_suite();
}
