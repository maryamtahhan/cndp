/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2023 Intel Corporation
 */

#ifndef _TEST_H_
#define _TEST_H_

#include <stddef.h>        // for NULL, size_t
#include <sys/queue.h>
#include <hexdump.h>              // for cne_hexdump
#include <cne_common.h>           // for CNE_INIT, CNE_STR
#include <bsd/sys/queue.h>        // for TAILQ_ENTRY, TAILQ_HEAD
#include <stdio.h>                // for FILE, size_t
#include <stdlib.h>               // for NULL, EXIT_SUCCESS
#include <cne_log.h>

#define TEST_SUCCESS EXIT_SUCCESS
#define TEST_FAILED  -1
#define TEST_SKIPPED 77

/* Before including test.h file you can define
 * TEST_TRACE_FAILURE(_file, _line, _func) macro to better trace/debug test
 * failures. Mostly useful in test development phase. */
#ifndef TEST_TRACE_FAILURE
#define TEST_TRACE_FAILURE(_file, _line, _func)
#endif

#include <cne_test.h>        // for CNE_TEST_ASSERT, CNE_TEST_ASSERT_EQUAL

#define TEST_ASSERT CNE_TEST_ASSERT

#define TEST_ASSERT_EQUAL CNE_TEST_ASSERT_EQUAL

/* Compare two buffers (length in bytes) */
#define TEST_ASSERT_BUFFERS_ARE_EQUAL(a, b, len, msg, ...)                                 \
    do {                                                                                   \
        if (memcmp(a, b, len)) {                                                           \
            cne_printf("[yellow]TestCase %s() line %d [red]failed[]: " msg "\n", __func__, \
                       __LINE__, ##__VA_ARGS__);                                           \
            TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);                              \
            return TEST_FAILED;                                                            \
        }                                                                                  \
    } while (0)

/* Compare two buffers with offset (length and offset in bytes) */
#define TEST_ASSERT_BUFFERS_ARE_EQUAL_OFFSET(a, b, len, off, msg, ...)     \
    do {                                                                   \
        const uint8_t *_a_with_off = (const uint8_t *)a + off;             \
        const uint8_t *_b_with_off = (const uint8_t *)b + off;             \
        TEST_ASSERT_BUFFERS_ARE_EQUAL(_a_with_off, _b_with_off, len, msg); \
    } while (0)

/* Compare two buffers (length in bits) */
#define TEST_ASSERT_BUFFERS_ARE_EQUAL_BIT(a, b, len, msg, ...)                                 \
    do {                                                                                       \
        uint8_t _last_byte_a, _last_byte_b;                                                    \
        uint8_t _last_byte_mask, _last_byte_bits;                                              \
        TEST_ASSERT_BUFFERS_ARE_EQUAL(a, b, (len >> 3), msg);                                  \
        if (len % 8) {                                                                         \
            _last_byte_bits = len % 8;                                                         \
            _last_byte_mask = ~((1 << (8 - _last_byte_bits)) - 1);                             \
            _last_byte_a    = ((const uint8_t *)a)[len >> 3];                                  \
            _last_byte_b    = ((const uint8_t *)b)[len >> 3];                                  \
            _last_byte_a &= _last_byte_mask;                                                   \
            _last_byte_b &= _last_byte_mask;                                                   \
            if (_last_byte_a != _last_byte_b) {                                                \
                cne_printf("[yellow]TestCase %s() line %d [red]failed[]: " msg "\n", __func__, \
                           __LINE__, ##__VA_ARGS__);                                           \
                TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);                              \
                return TEST_FAILED;                                                            \
            }                                                                                  \
        }                                                                                      \
    } while (0)

/* Compare two buffers with offset (length and offset in bits) */
#define TEST_ASSERT_BUFFERS_ARE_EQUAL_BIT_OFFSET(a, b, len, off, msg, ...)                         \
    do {                                                                                           \
        uint8_t _first_byte_a, _first_byte_b;                                                      \
        uint8_t _first_byte_mask, _first_byte_bits;                                                \
        uint32_t _len_without_first_byte = (off % 8) ? len - (8 - (off % 8)) : len;                \
        uint32_t _off_in_bytes           = (off % 8) ? (off >> 3) + 1 : (off >> 3);                \
        const uint8_t *_a_with_off       = (const uint8_t *)a + _off_in_bytes;                     \
        const uint8_t *_b_with_off       = (const uint8_t *)b + _off_in_bytes;                     \
        TEST_ASSERT_BUFFERS_ARE_EQUAL_BIT(_a_with_off, _b_with_off, _len_without_first_byte, msg); \
        if (off % 8) {                                                                             \
            _first_byte_bits = 8 - (off % 8);                                                      \
            _first_byte_mask = (1 << _first_byte_bits) - 1;                                        \
            _first_byte_a    = *(_a_with_off - 1);                                                 \
            _first_byte_b    = *(_b_with_off - 1);                                                 \
            _first_byte_a &= _first_byte_mask;                                                     \
            _first_byte_b &= _first_byte_mask;                                                     \
            if (_first_byte_a != _first_byte_b) {                                                  \
                cne_printf("[yellow]TestCase %s() line %d [red]failed[]: " msg "\n", __func__,     \
                           __LINE__, ##__VA_ARGS__);                                               \
                TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);                                  \
                return TEST_FAILED;                                                                \
            }                                                                                      \
        }                                                                                          \
    } while (0)

#define TEST_ASSERT_NOT_EQUAL CNE_TEST_ASSERT_NOT_EQUAL

#define TEST_ASSERT_SUCCESS CNE_TEST_ASSERT_SUCCESS

#define TEST_ASSERT_FAIL CNE_TEST_ASSERT_FAIL

#define TEST_ASSERT_NULL CNE_TEST_ASSERT_NULL

#define TEST_ASSERT_NOT_NULL CNE_TEST_ASSERT_NOT_NULL

struct unit_test_case {
    int (*setup)(void);
    void (*teardown)(void);
    int (*testcase)(void);
    const char *name;
    unsigned enabled;
};

#define TEST_CASE(fn) {NULL, NULL, fn, #fn, 1}

#define TEST_CASE_NAMED(name, fn) {NULL, NULL, fn, name, 1}

#define TEST_CASE_ST(setup, teardown, testcase) {setup, teardown, testcase, #testcase, 1}

#define TEST_CASE_DISABLED(fn) {NULL, NULL, fn, #fn, 0}

#define TEST_CASE_ST_DISABLED(setup, teardown, testcase) {setup, teardown, testcase, #testcase, 0}

#define TEST_CASES_END() {NULL, NULL, NULL, NULL, 0}

static inline void
debug_hexdump(FILE *file, const char *title, const void *buf, size_t len)
{
    cne_hexdump(file, title, buf, len);
}

struct unit_test_suite {
    const char *suite_name;
    int (*setup)(void);
    void (*teardown)(void);
    struct unit_test_case unit_test_cases[];
};

int unit_test_suite_runner(struct unit_test_suite *suite);
extern int last_test_result;

#define RECURSIVE_ENV_VAR "CNE_TEST_RECURSIVE"

extern const char *prgname;

typedef int(test_callback)(void);
TAILQ_HEAD(test_commands_list, test_command);
struct test_command {
    TAILQ_ENTRY(test_command) next;
    const char *command;
    test_callback *callback;
};

void add_test_command(struct test_command *t);

/* Register a test function with its command string */
#define REGISTER_TEST_COMMAND(cmd, func)             \
    static struct test_command test_struct_##cmd = { \
        .command  = CNE_STR(cmd),                    \
        .callback = func,                            \
    };                                               \
    CNE_INIT(test_register_##cmd) { add_test_command(&test_struct_##cmd); }

#endif
