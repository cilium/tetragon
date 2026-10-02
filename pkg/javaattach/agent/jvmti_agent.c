// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

#include <jni.h>
#include <jvmti.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_MANIFEST_SIZE (64u * 1024u * 1024u)
#define MAX_PATCHES 32u
#define MAX_CLASS_SIZE (16u * 1024u * 1024u)
#define SIGNATURE_MAX 1024u
#define HEADER "TGPAT01\n"
#define AT_FDCWD (-100)

typedef struct {
    char *signature;
    unsigned char *bytes;
    uint32_t size;
} patch_entry;

static void copy_bytes(void *dst, const void *src, size_t size) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < size; i++) d[i] = s[i];
}

static int bytes_equal(const void *left, const void *right, size_t size) {
    const unsigned char *a = (const unsigned char *)left;
    const unsigned char *b = (const unsigned char *)right;
    for (size_t i = 0; i < size; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static int strings_equal(const char *left, const char *right) {
    if (left == NULL || right == NULL) return 0;
    while (*left != '\0' && *left == *right) { left++; right++; }
    return *left == *right;
}

static uint16_t read_u16(const unsigned char *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t read_u32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

#if defined(__x86_64__)
static long raw_openat(long dirfd, const char *path, long flags) {
    long result;
    register long r10 __asm__("r10") = 0;
    __asm__ volatile("syscall" : "=a"(result) : "a"(257), "D"(dirfd), "S"(path), "d"(flags), "r"(r10) : "rcx", "r11", "memory");
    return result;
}
static long raw_read(long fd, void *buffer, size_t size) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(0), "D"(fd), "S"(buffer), "d"(size) : "rcx", "r11", "memory");
    return result;
}
static long raw_close(long fd) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(3), "D"(fd) : "rcx", "r11", "memory");
    return result;
}
#elif defined(__aarch64__)
static long raw_openat(long dirfd, const char *path, long flags) {
    register long x0 __asm__("x0") = dirfd;
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = flags;
    register long x3 __asm__("x3") = 0;
    register long x8 __asm__("x8") = 56;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    return x0;
}
static long raw_read(long fd, void *buffer, size_t size) {
    register long x0 __asm__("x0") = fd;
    register long x1 __asm__("x1") = (long)buffer;
    register long x2 __asm__("x2") = (long)size;
    register long x8 __asm__("x8") = 63;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}
static long raw_close(long fd) {
    register long x0 __asm__("x0") = fd;
    register long x8 __asm__("x8") = 57;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}
#else
#error "JVMTI helper supports only x86_64 and aarch64 Linux"
#endif

static unsigned char *allocate(jvmtiEnv *jvmti, size_t size) {
    unsigned char *result = NULL;
    if (size == 0 || (*jvmti)->Allocate(jvmti, (jlong)size, &result) != JVMTI_ERROR_NONE) return NULL;
    return result;
}

static void release(jvmtiEnv *jvmti, unsigned char *memory) {
    if (memory != NULL) (*jvmti)->Deallocate(jvmti, memory);
}

static int read_file(jvmtiEnv *jvmti, const char *path, unsigned char **data_out, size_t *size_out) {
    long fd = raw_openat(AT_FDCWD, path, 0);
    if (fd < 0) return -1;
    size_t capacity = 4096;
    size_t length = 0;
    unsigned char *data = allocate(jvmti, capacity);
    if (data == NULL) { raw_close(fd); return -1; }
    for (;;) {
        if (length == capacity) {
            if (capacity >= MAX_MANIFEST_SIZE) { release(jvmti, data); raw_close(fd); return -1; }
            size_t next_capacity = capacity * 2;
            if (next_capacity > MAX_MANIFEST_SIZE) next_capacity = MAX_MANIFEST_SIZE;
            unsigned char *next = allocate(jvmti, next_capacity);
            if (next == NULL) { release(jvmti, data); raw_close(fd); return -1; }
            copy_bytes(next, data, length);
            release(jvmti, data);
            data = next;
            capacity = next_capacity;
        }
        long count = raw_read(fd, data + length, capacity - length);
        if (count < 0) { release(jvmti, data); raw_close(fd); return -1; }
        if (count == 0) break;
        length += (size_t)count;
        if (length > MAX_MANIFEST_SIZE) { release(jvmti, data); raw_close(fd); return -1; }
    }
    raw_close(fd);
    *data_out = data;
    *size_out = length;
    return 0;
}

static void free_entries(jvmtiEnv *jvmti, patch_entry *entries, uint32_t count) {
    if (entries == NULL) return;
    for (uint32_t i = 0; i < count; i++) {
        release(jvmti, (unsigned char *)entries[i].signature);
        release(jvmti, entries[i].bytes);
    }
    release(jvmti, (unsigned char *)entries);
}

static int parse_manifest(jvmtiEnv *jvmti, const char *path, patch_entry **entries_out, uint32_t *count_out) {
    unsigned char *data = NULL;
    size_t length = 0;
    if (read_file(jvmti, path, &data, &length) != 0) return -1;
    if (length < 12 || length > MAX_MANIFEST_SIZE || !bytes_equal(data, HEADER, 8)) {
        release(jvmti, data);
        return -1;
    }
    uint32_t count = read_u32(data + 8);
    if (count == 0 || count > MAX_PATCHES) { release(jvmti, data); return -1; }
    patch_entry *entries = (patch_entry *)allocate(jvmti, sizeof(*entries) * count);
    if (entries == NULL) { release(jvmti, data); return -1; }
    for (uint32_t i = 0; i < count; i++) {
        entries[i].signature = NULL;
        entries[i].bytes = NULL;
        entries[i].size = 0;
    }
    size_t offset = 12;
    for (uint32_t i = 0; i < count; i++) {
        if (length - offset < 6) goto fail;
        uint16_t signature_size = read_u16(data + offset);
        uint32_t class_size = read_u32(data + offset + 2);
        offset += 6;
        if (signature_size < 3 || signature_size > SIGNATURE_MAX || class_size < 8 || class_size > MAX_CLASS_SIZE ||
            length - offset < (size_t)signature_size + class_size) goto fail;
        entries[i].signature = (char *)allocate(jvmti, (size_t)signature_size + 1);
        entries[i].bytes = allocate(jvmti, class_size);
        if (entries[i].signature == NULL || entries[i].bytes == NULL) goto fail;
        copy_bytes(entries[i].signature, data + offset, signature_size);
        entries[i].signature[signature_size] = '\0';
        offset += signature_size;
        copy_bytes(entries[i].bytes, data + offset, class_size);
        entries[i].size = class_size;
        offset += class_size;
    }
    if (offset != length) goto fail;
    release(jvmti, data);
    *entries_out = entries;
    *count_out = count;
    return 0;

fail:
    free_entries(jvmti, entries, count);
    release(jvmti, data);
    return -1;
}

JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    (void)reserved;
    if (options == NULL || options[0] == '\0') return JNI_ERR;

    jvmtiEnv *jvmti = NULL;
    if ((*vm)->GetEnv(vm, (void **)&jvmti, JVMTI_VERSION_1_2) != JNI_OK || jvmti == NULL) return JNI_ERR;

    patch_entry *entries = NULL;
    uint32_t patch_count = 0;
    if (parse_manifest(jvmti, options, &entries, &patch_count) != 0) return JNI_ERR;

    jvmtiCapabilities capabilities;
    for (size_t i = 0; i < sizeof(capabilities); i++) ((unsigned char *)&capabilities)[i] = 0;
    capabilities.can_redefine_classes = 1;
    jvmtiError error = (*jvmti)->AddCapabilities(jvmti, &capabilities);
    if (error != JVMTI_ERROR_NONE) { free_entries(jvmti, entries, patch_count); return JNI_ERR; }

    jint loaded_count = 0;
    jclass *loaded = NULL;
    error = (*jvmti)->GetLoadedClasses(jvmti, &loaded_count, &loaded);
    if (error != JVMTI_ERROR_NONE) { free_entries(jvmti, entries, patch_count); return JNI_ERR; }

    jvmtiClassDefinition *definitions = (jvmtiClassDefinition *)allocate(jvmti, sizeof(*definitions) * (size_t)loaded_count);
    unsigned char *found = allocate(jvmti, patch_count);
    if (definitions == NULL || found == NULL) {
        release(jvmti, (unsigned char *)definitions);
        release(jvmti, found);
        (*jvmti)->Deallocate(jvmti, (unsigned char *)loaded);
        free_entries(jvmti, entries, patch_count);
        return JNI_ERR;
    }
    for (uint32_t i = 0; i < patch_count; i++) found[i] = 0;

    jint definition_count = 0;
    for (jint i = 0; i < loaded_count; i++) {
        char *signature = NULL;
        char *generic = NULL;
        error = (*jvmti)->GetClassSignature(jvmti, loaded[i], &signature, &generic);
        if (error != JVMTI_ERROR_NONE || signature == NULL) continue;
        for (uint32_t p = 0; p < patch_count; p++) {
            if (strings_equal(signature, entries[p].signature)) {
                definitions[definition_count].klass = loaded[i];
                definitions[definition_count].class_byte_count = (jint)entries[p].size;
                definitions[definition_count].class_bytes = entries[p].bytes;
                definition_count++;
                found[p] = 1;
            }
        }
        if (signature != NULL) (*jvmti)->Deallocate(jvmti, (unsigned char *)signature);
        if (generic != NULL) (*jvmti)->Deallocate(jvmti, (unsigned char *)generic);
    }
    (*jvmti)->Deallocate(jvmti, (unsigned char *)loaded);

    int missing = 0;
    for (uint32_t i = 0; i < patch_count; i++) if (!found[i]) missing = 1;
    release(jvmti, found);
    if (missing || definition_count == 0) {
        release(jvmti, (unsigned char *)definitions);
        free_entries(jvmti, entries, patch_count);
        return JNI_ERR;
    }

    error = (*jvmti)->RedefineClasses(jvmti, definition_count, definitions);
    release(jvmti, (unsigned char *)definitions);
    free_entries(jvmti, entries, patch_count);
    return error == JVMTI_ERROR_NONE ? JNI_OK : JNI_ERR;
}
