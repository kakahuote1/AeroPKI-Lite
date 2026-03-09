/* SPDX-License-Identifier: Apache-2.0 */

#include "test_common.h"

int main(void)
{
    return run_named_test_suite("TinyPKI ECQV Suite", run_test_ecqv_suite);
}
