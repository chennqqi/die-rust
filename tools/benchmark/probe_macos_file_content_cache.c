#define _DARWIN_C_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef __APPLE__
#error "probe_macos_file_content_cache.c requires Darwin"
#endif

#ifndef F_NOCACHE
#error "Darwin F_NOCACHE is required"
#endif

#ifndef MS_INVALIDATE
#error "Darwin MS_INVALIDATE is required"
#endif

#define FIXTURE_BYTES (16U * 1024U * 1024U)

static void fail_errno(const char *operation) {
    int saved_errno = errno;
    fprintf(stderr, "%s: %s\n", operation, strerror(saved_errno));
    exit(2);
}

static void fail_message(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(2);
}

static void write_all(int descriptor, const unsigned char *buffer,
                      size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written =
            write(descriptor, buffer + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            fail_errno("write");
        }
        if (written == 0) {
            fail_message("write returned zero");
        }
        offset += (size_t)written;
    }
}

static size_t count_resident(void *mapping, size_t length,
                             size_t page_size,
                             unsigned char *vector) {
    size_t page_count = (length + page_size - 1U) / page_size;
    memset(vector, 0, page_count);
    if (mincore(mapping, length, (char *)vector) != 0) {
        fail_errno("mincore");
    }
    size_t resident = 0;
    for (size_t index = 0; index < page_count; index++) {
        if ((vector[index] & 1U) != 0U) {
            resident++;
        }
    }
    return resident;
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--temporary-directory") != 0) {
        fail_message(
            "usage: probe --temporary-directory EXISTING_DIRECTORY");
    }

    long raw_page_size = sysconf(_SC_PAGESIZE);
    if (raw_page_size <= 0) {
        fail_errno("sysconf(_SC_PAGESIZE)");
    }
    size_t page_size = (size_t)raw_page_size;
    size_t length = FIXTURE_BYTES;
    if (length % page_size != 0U) {
        fail_message("fixture size is not page aligned");
    }
    size_t page_count = length / page_size;
    if (page_count == 0U || page_count > 1048576U) {
        fail_message("fixture page count is outside the reviewed bound");
    }

    char template_path[PATH_MAX];
    int formatted = snprintf(template_path, sizeof(template_path),
                             "%s/die-cache-probe.XXXXXX", argv[2]);
    if (formatted < 0 || (size_t)formatted >= sizeof(template_path)) {
        fail_message("temporary fixture path is too long");
    }
    int descriptor = mkstemp(template_path);
    if (descriptor < 0) {
        fail_errno("mkstemp");
    }
    if (unlink(template_path) != 0) {
        fail_errno("unlink temporary fixture");
    }

    size_t block_size = 1024U * 1024U;
    unsigned char *block = malloc(block_size);
    if (block == NULL) {
        fail_message("cannot allocate write block");
    }
    for (size_t index = 0; index < block_size; index++) {
        block[index] = (unsigned char)((index * 131U + 17U) & 0xffU);
    }
    for (size_t offset = 0; offset < length; offset += block_size) {
        write_all(descriptor, block, block_size);
    }
    free(block);
    if (fsync(descriptor) != 0) {
        fail_errno("fsync temporary fixture");
    }

    void *mapping =
        mmap(NULL, length, PROT_READ, MAP_SHARED, descriptor, 0);
    if (mapping == MAP_FAILED) {
        fail_errno("mmap temporary fixture");
    }
    unsigned char *vector = calloc(page_count, 1U);
    if (vector == NULL) {
        fail_message("cannot allocate mincore vector");
    }

    volatile uint64_t checksum = 0;
    const unsigned char *bytes = mapping;
    for (size_t offset = 0; offset < length; offset += page_size) {
        checksum += bytes[offset];
    }
    size_t warm_resident =
        count_resident(mapping, length, page_size, vector);

    if (fcntl(descriptor, F_NOCACHE, 1) != 0) {
        fail_errno("fcntl(F_NOCACHE, 1)");
    }
    size_t after_f_nocache =
        count_resident(mapping, length, page_size, vector);
    if (fcntl(descriptor, F_NOCACHE, 0) != 0) {
        fail_errno("fcntl(F_NOCACHE, 0)");
    }

    int msync_flags = MS_SYNC | MS_INVALIDATE;
    if (msync(mapping, length, msync_flags) != 0) {
        fail_errno("msync(MS_SYNC | MS_INVALIDATE)");
    }
    size_t after_msync =
        count_resident(mapping, length, page_size, vector);

    printf("schema_version\t1\n");
    printf("page_size\t%zu\n", page_size);
    printf("fixture_bytes\t%zu\n", length);
    printf("logical_pages\t%zu\n", page_count);
    printf("warm_resident_pages\t%zu\n", warm_resident);
    printf("after_f_nocache_resident_pages\t%zu\n", after_f_nocache);
    printf("msync_flags\t%d\n", msync_flags);
    printf("after_msync_invalidate_resident_pages\t%zu\n",
           after_msync);
    printf("checksum\t%llu\n", (unsigned long long)checksum);
    printf("temporary_fixture_unlinked_before_probe\t1\n");
    printf("benchmark_files_touched\t0\n");
    printf("system_cache_flush_executed\t0\n");

    free(vector);
    if (munmap(mapping, length) != 0) {
        fail_errno("munmap temporary fixture");
    }
    if (close(descriptor) != 0) {
        fail_errno("close temporary fixture");
    }
    return 0;
}
