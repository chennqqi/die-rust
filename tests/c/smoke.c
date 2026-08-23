/*
 * smoke.c - C smoke test for diec-rust C ABI.
 *
 * This program builds the database, scans a 7-Zip header, and verifies
 * the result JSON contains "7-Zip". It demonstrates the complete
 * lifecycle: builder -> database -> scan -> result -> cleanup.
 *
 * Build (Windows MSVC):
 *   cl /I..\..\include smoke.c /link ..\..\target\debug\diec_ffi.lib
 *
 * Build (Linux/macOS):
 *   cc -I../../include smoke.c -L../../target/debug -ldiec_ffi -o smoke
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "diec.h"

static int check_status(const char *label, uint32_t status) {
    if (status != DIEC_STATUS_OK) {
        const uint8_t *name = NULL;
        uint64_t len = 0;
        diec_v1_status_name(status, &name, &len);
        fprintf(stderr, "FAIL: %s status=%u (%.*s)\n", label, status, (int)len, name);
        return 1;
    }
    printf("PASS: %s\n", label);
    return 0;
}

int main(void) {
    int failures = 0;

    /* ABI version check */
    uint32_t ver = diec_abi_version();
    if (ver != DIEC_ABI_V1_0) {
        fprintf(stderr, "FAIL: ABI version mismatch: %u\n", ver);
        return 1;
    }
    printf("PASS: ABI version = 0x%08x\n", ver);

    if (!diec_abi_is_compatible(DIEC_ABI_V1_0)) {
        fprintf(stderr, "FAIL: ABI not compatible with v1.0\n");
        return 1;
    }
    printf("PASS: ABI compatible with v1.0\n");

    /* Database builder */
    diec_v1_database_builder *builder = NULL;
    diec_v1_error *error = NULL;
    failures += check_status("database_builder_new",
        diec_v1_database_builder_new(&builder, &error));

    const char *db_path = getenv("DIEC_DB_PATH");
    if (!db_path || !*db_path) {
        db_path = "../../upstream/Detect-It-Easy/db";
    }
    uint64_t path_len = strlen(db_path);
    failures += check_status("database_builder_add_path",
        diec_v1_database_builder_add_path_utf8(builder, DIEC_DATABASE_KIND_MAIN,
            (const uint8_t *)db_path, path_len, 0, &error));

    /* Build database */
    diec_v1_database *database = NULL;
    failures += check_status("database_build",
        diec_v1_database_builder_build(builder, &database, &error));

    /* Free builder (database is independent) */
    diec_v1_database_builder_free(&builder);

    /* Scan 7-Zip header */
    uint8_t data[] = {
        0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    diec_v1_result *result = NULL;
    failures += check_status("scan_bytes",
        diec_v1_scan_bytes(database, data, sizeof(data), NULL, NULL,
            &result, &error));

    if (result) {
        /* Get JSON */
        const uint8_t *json = NULL;
        uint64_t json_len = 0;
        failures += check_status("result_json",
            diec_v1_result_json(result, &json, &json_len));

        if (json && json_len > 0) {
            /* Check if JSON contains "7-Zip" */
            int found = 0;
            for (uint64_t i = 0; i + 5 <= json_len; i++) {
                if (memcmp(json + i, "7-Zip", 5) == 0) {
                    found = 1;
                    break;
                }
            }
            if (found) {
                printf("PASS: result contains 7-Zip\n");
            } else {
                fprintf(stderr, "FAIL: result does not contain 7-Zip: %.*s\n",
                    (int)json_len, json);
                failures++;
            }
        }

        /* Get detection count */
        uint64_t count = 0;
        failures += check_status("result_detection_count",
            diec_v1_result_detection_count(result, &count));
        if (count > 0) {
            printf("PASS: detection count = %llu\n", (unsigned long long)count);
        } else {
            fprintf(stderr, "FAIL: detection count is 0\n");
            failures++;
        }

        diec_v1_result_free(&result);
    }

    /* Reusable scanner test: multiple scans sharing one runtime. */
    diec_v1_scanner *scanner = NULL;
    failures += check_status("scanner_new",
        diec_v1_scanner_new(database, &scanner, &error));

    if (scanner) {
        /* First scan via reusable scanner. */
        diec_v1_result *scan1 = NULL;
        failures += check_status("scanner_scan_bytes (1)",
            diec_v1_scanner_scan_bytes(scanner, data, sizeof(data), NULL, NULL,
                &scan1, &error));

        if (scan1) {
            const uint8_t *json1 = NULL;
            uint64_t json1_len = 0;
            diec_v1_result_json(scan1, &json1, &json1_len);
            if (json1 && json1_len > 0) {
                int found1 = 0;
                for (uint64_t i = 0; i + 5 <= json1_len; i++) {
                    if (memcmp(json1 + i, "7-Zip", 5) == 0) {
                        found1 = 1;
                        break;
                    }
                }
                if (found1) {
                    printf("PASS: scanner scan 1 contains 7-Zip\n");
                } else {
                    fprintf(stderr, "FAIL: scanner scan 1 no 7-Zip\n");
                    failures++;
                }
            }
            diec_v1_result_free(&scan1);
        }

        /* Second scan (runtime reused). */
        diec_v1_result *scan2 = NULL;
        failures += check_status("scanner_scan_bytes (2)",
            diec_v1_scanner_scan_bytes(scanner, data, sizeof(data), NULL, NULL,
                &scan2, &error));

        if (scan2) {
            uint64_t count2 = 0;
            diec_v1_result_detection_count(scan2, &count2);
            if (count2 > 0) {
                printf("PASS: scanner scan 2 count = %llu\n",
                    (unsigned long long)count2);
            } else {
                fprintf(stderr, "FAIL: scanner scan 2 count is 0\n");
                failures++;
            }
            diec_v1_result_free(&scan2);
        }

        diec_v1_scanner_free(&scanner);
    }

    /* Cleanup */
    diec_v1_database_free(&database);

    if (error) {
        diec_v1_error_free(&error);
    }

    if (failures > 0) {
        fprintf(stderr, "\n%d test(s) failed\n", failures);
        return 1;
    }

    printf("\nAll C smoke tests passed!\n");
    return 0;
}
