#include <stddef.h>
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
#define VERSION "0.0.2"

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

typedef enum {
    FORMAT_TEXT,
    FORMAT_JSON
} OutputFormat;

typedef struct {
    FILE *stream;
    OutputFormat format;
    int first_json_entry; // To handle JSON commas correctly
} OutputContext;

// --- Helper: Progress Display ---
// prints: [Stage] 10/500 (2.0%) C:\path\to\file.txt      <-- spaces to clear leftovers
void print_progress(size_t current, size_t total, const char *stage, const char *path) {
    double percent = (double)current / total * 100.0;

    // \r moves cursor to start of line
    // print the info, then 40 spaces to overwrite any previous long text
    // rely on the user's terminal being wide enough to not wrap often
    printf("\r[%s] %zu/%zu (%.1f%%) %s                                        ",
           stage, current, total, percent, path);
    fflush(stdout); // Force update immediately
}

void clear_progress_line() {
    // Overwrite the entire line with spaces, then return to start
    printf("\r                                                                                \r");
}

// --- JSON helper ---
void json_escape_print(FILE *stream, const char *str) {
    fputc('"', stream);
    while (*str) {
        switch (*str) {
            case '\\': fprintf(stream, "\\\\"); break;
            case '"': fprintf(stream, "\\\""); break;
            case '\b': fprintf(stream, "\\b"); break;
            case '\f': fprintf(stream, "\\f"); break;
            case '\n': fprintf(stream, "\\n"); break;
            case '\r': fprintf(stream, "\\r"); break;
            case '\t': fprintf(stream, "\\t"); break;
            default:
                if ((unsigned char)*str < 32) fprintf(stream, "\\u%04x", *str);
                else fputc(*str, stream);
        }
        str++;
    }
    fputc('"', stream);
}

// --- Output helper ---
void report_duplicates(OutputContext *ctx, FileInfo **group, size_t count) {
    if (ctx->format == FORMAT_TEXT) {
        fprintf(ctx->stream, "MATCH:\n");
        for (size_t i = 0; i < count; i++) {
            fprintf(ctx->stream, "   %s\n", group[i]->path);
        }
        fprintf(ctx->stream, "----------------------------------------\n");
    }
    else if (ctx->format == FORMAT_JSON) {
        if (!ctx->first_json_entry) {
            fprintf(ctx->stream, ",\n");
        }
        ctx->first_json_entry = 0;

        fprintf(ctx->stream, "  [\n");
        for (size_t i = 0; i < count; i++) {
            fprintf(ctx->stream, "    ");
            json_escape_print(ctx->stream, group[i]->path);
            if (i < count - 1) fprintf(ctx->stream, ",");
            fprintf(ctx->stream, "\n");
        }
        fprintf(ctx->stream, "  ]");
    }
}

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
        printf("Usage: dedup <directory> [-o <output_file>]\n");
        return 1;
    }
    char *dir_path = NULL;
    char *out_path = NULL;

    // arg parsing
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0)) {
            if (i + 1 < argc) {
                out_path = argv[++i];
            } else {
                fprintf(stderr, "Error: --output requires a filename.\n");
                return 1;
            }
        } else if (argv[i][0] == '-') {
                fprintf(stderr, "Unknown option: %s\n", argv[i]);
                return 1;
        } else {
            dir_path = argv[i];
        }
    }
    if (!dir_path) {
        printf("Directory path is required.\n");
        return 1;
    }

    // setup output context
    OutputContext out_ctx = {0};
    out_ctx.stream = stdout;
    out_ctx.format = FORMAT_TEXT;
    out_ctx.first_json_entry = 1;
    if (out_path) {
        out_ctx.stream = fopen(out_path, "w");
        if (!out_ctx.stream) {
            perror("Error opening output file");
            return 1;
        }

        // detect JSON extension
        char *ext = strrchr(out_path, '.');
        if (ext && _stricmp(ext, ".json") == 0) { // _stricmp for case-insensitive comparison (Windows)
            out_ctx.format = FORMAT_JSON;
        }
    }

    FileList list = {0};
    printf("Scanning %s...\n", dir_path);
    scan_dir(dir_path, &list);

    printf("Found %zu files. Sorting by size...\n", list.count);
    qsort(list.files, list.count, sizeof(FileInfo*), cmp_size);

    if (out_ctx.format == FORMAT_JSON) {
        fprintf(out_ctx.stream, "[\n");
    }

    size_t i = 0;
    while (i < list.count) {
        size_t j = i + 1;
        while (j < list.count && list.files[j]->size == list.files[i]->size) j++;

        if (j - i > 1) {
            // Processing Size Group
            for (size_t k = i; k < j; k++) {
                // PASS GLOBAL INDEX (k+1) TO PROGRESS
                print_progress(k + 1, list.count, "CRC", list.files[k]->path);
                list.files[k]->crc = get_file_crc(list.files[k]->path);
            }

            qsort(&list.files[i], j - i, sizeof(FileInfo*), cmp_crc);

            size_t p = i;
            while (p < j) {
                size_t q = p + 1;
                while (q < j && list.files[q]->crc == list.files[p]->crc) q++;

                if (q - p > 1) {
                    // Processing CRC Group
                    for (size_t k = p; k < q; k++) {
                        print_progress(k + 1, list.count, "MD5", list.files[k]->path);
                        get_file_md5(list.files[k]->path, list.files[k]->md5);
                    }

                    qsort(&list.files[p], q - p, sizeof(FileInfo*), cmp_md5);

                    size_t x = p;
                    while (x < q) {
                        size_t y = x + 1;
                        while (y < q && memcmp(list.files[y]->md5, list.files[x]->md5, 16) == 0) y++;

                        if (y - x > 1) {
                            // Match Found
                            clear_progress_line();

                            report_duplicates(&out_ctx, &list.files[x], y - x);

                            if (out_path) {
                                printf("\rFound match group... (logged to file)    ");
                                fflush(stdout);
                            }
                        }
                        x = y;
                    }
                }
                p = q;
            }
        }
        i = j;
    }

    if (out_ctx.format == FORMAT_JSON) {
        fprintf(out_ctx.stream, "\n]\n");
    }

    clear_progress_line();
    printf("Done.\n");
    if (out_path) {
        printf("Output written to %s", out_path);
        fclose(out_ctx.stream);
    }

    // cleanup memory
    for (size_t i=0; i<list.count; i++) {
        free(list.files[i]->path);
        free(list.files[i]);
    }
    free(list.files);

    return 0;
}
