#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
// Link libraries automatically for MSVC (Visual Studio)
#pragma comment(lib, "advapi32.lib")
#endif

#define PATH_BUF_SIZE 8192
#define FILE_BUF_SIZE (64 * 1024)
#define VERSION "0.0.1"

// --- Data Structures ---
typedef struct {
    char *path;
    unsigned __int64 size;
    unsigned long crc;
    BYTE md5[16];
    int crc_calculated;
    int md5_calculated;
} FileInfo;

typedef struct {
    FileInfo **files;
    size_t count;
    size_t capacity;
} FileList;

// --- CRC32 Implementation ---
unsigned long crc_table[256];
int crc_initialized = 0;

void init_crc32() {
    unsigned long crc;
    for (int i = 0; i < 256; i++) {
        crc = i;
        for (int j = 0; j < 8; j++) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
        }
        crc_table[i] = crc;
    }
    crc_initialized = 1;
}

unsigned long update_crc32(unsigned long crc, const BYTE *buf, size_t len) {
    if (!crc_initialized) init_crc32();
    crc = ~crc;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc_table[(crc & 0xFF) ^ buf[i]];
    }
    return ~crc;
}

// --- Hashing Wrappers ---

unsigned long get_file_crc(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    unsigned char buffer[FILE_BUF_SIZE];
    unsigned long crc = 0;
    size_t n;

    while ((n = fread(buffer, 1, FILE_BUF_SIZE, f)) > 0) {
        crc = update_crc32(crc, buffer, n);
    }
    fclose(f);
    return crc;
}

int get_file_md5(const char *path, BYTE *output) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    FILE *f = 0;
    int success = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return 0;
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) goto cleanup;

    f = fopen(path, "rb");
    if (!f) goto cleanup;

    unsigned char buffer[FILE_BUF_SIZE];
    size_t n;
    while ((n = fread(buffer, 1, FILE_BUF_SIZE, f)) > 0) {
        if (!CryptHashData(hHash, buffer, (DWORD)n, 0)) goto cleanup;
    }

    DWORD hashLen = 16;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, output, &hashLen, 0)) goto cleanup;
    success = 1;

cleanup:
    if (f) fclose(f);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return success;
}

// --- List Management ---

void list_add(FileList *list, char *path, unsigned __int64 size) {
    if (list->count == list->capacity) {
        list->capacity = (list->capacity == 0) ? 1024 : list->capacity * 2;
        list->files = realloc(list->files, list->capacity * sizeof(FileInfo*));
    }
    FileInfo *fi = malloc(sizeof(FileInfo));
    fi->path = _strdup(path);
    fi->size = size;
    fi->crc_calculated = 0;
    fi->md5_calculated = 0;
    list->files[list->count++] = fi;
}

// --- Directory Scanning ---

void scan_dir(const char *basePath, FileList *list) {
    char searchPath[PATH_BUF_SIZE];
    snprintf(searchPath, PATH_BUF_SIZE, "%s\\*", basePath);

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(searchPath, &fd);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

        char fullPath[PATH_BUF_SIZE];
        snprintf(fullPath, PATH_BUF_SIZE, "%s\\%s", basePath, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_dir(fullPath, list);
        } else {
            unsigned __int64 fileSize = ((unsigned __int64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            list_add(list, fullPath, fileSize);
        }
    } while (FindNextFile(hFind, &fd));

    FindClose(hFind);
}

// --- Comparators ---

int cmp_size(const void *a, const void *b) {
    FileInfo *fa = *(FileInfo**)a;
    FileInfo *fb = *(FileInfo**)b;
    if (fa->size < fb->size) return -1;
    if (fa->size > fb->size) return 1;
    return 0;
}

int cmp_crc(const void *a, const void *b) {
    FileInfo *fa = *(FileInfo**)a;
    FileInfo *fb = *(FileInfo**)b;
    if (fa->crc < fb->crc) return -1;
    if (fa->crc > fb->crc) return 1;
    return 0;
}

int cmp_md5(const void *a, const void *b) {
    FileInfo *fa = *(FileInfo**)a;
    FileInfo *fb = *(FileInfo**)b;
    return memcmp(fa->md5, fb->md5, 16);
}

// --- Main ---

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("dedup %s\n", VERSION);
        printf("Usage: dedup <directory>\n");
        return 1;
    }

    FileList list = {0};
    printf("Scanning %s...\n", argv[1]);
    scan_dir(argv[1], &list);

    printf("Found %zu files. Sorting by size...\n", list.count);
    qsort(list.files, list.count, sizeof(FileInfo*), cmp_size);

    size_t i = 0;
    while (i < list.count) {
        size_t j = i + 1;
        while (j < list.count && list.files[j]->size == list.files[i]->size) j++;

        if (j - i > 1) {
            for (size_t k = i; k < j; k++) {
                printf("\r[CRC] %s", list.files[k]->path);
                list.files[k]->crc = get_file_crc(list.files[k]->path);
            }

            qsort(&list.files[i], j - i, sizeof(FileInfo*), cmp_crc);

            size_t p = i;
            while (p < j) {
                size_t q = p + 1;
                while (q < j && list.files[q]->crc == list.files[p]->crc) q++;

                if (q - p > 1) {
                    for (size_t k = p; k < q; k++) {
                        printf("\r[MD5] %s", list.files[k]->path);
                        get_file_md5(list.files[k]->path, list.files[k]->md5);
                    }

                    qsort(&list.files[p], q - p, sizeof(FileInfo*), cmp_md5);

                    size_t x = p;
                    while (x < q) {
                        size_t y = x + 1;
                        while (y < q && memcmp(list.files[y]->md5, list.files[x]->md5, 16) == 0) y++;

                        if (y - x > 1) {
                            printf("\nMATCH:\n");
                            for (size_t k = x; k < y; k++) {
                                printf("   %s\n", list.files[k]->path);
                            }
                            printf("----------------------------------------\n");
                        }
                        x = y;
                    }
                }
                p = q;
            }
        }
        i = j;
    }
    printf("\nDone.\n");
    return 0;
}
