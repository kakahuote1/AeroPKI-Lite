/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

int main(void)
{
    return run_named_test_suite(
        "TinyPKI PKI Internal Suite", run_test_pki_internal_suite);
}
