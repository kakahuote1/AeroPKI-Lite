/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("--- TinyPKI Test Suite ---\n");
    run_test_ecqv_suite();
    run_test_revoke_suite();
    run_test_merkle_suite();
    run_test_auth_suite();
    run_test_pki_suite();
    run_test_pki_internal_suite();
    printf("\nSummary: %d Run, %d Passed, %d Failed.\n", g_tests_run,
        g_tests_passed, g_tests_failed);
    return g_tests_failed == 0 ? 0 : -1;
}
