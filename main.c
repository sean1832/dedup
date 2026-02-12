#include <stddef.h>
#include <wchar.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <io.h>

#ifdef _MSC_VER
// Link libraries automatically for MSVC (Visual Studio)
#pragma comment(lib, "advapi32.lib")
#endif

#define PATH_BUF_SIZE 8192
#define FILE_BUF_SIZE (64 * 1024)
#define VERSION L"0.0.4"

// --- Data Structures ---
typedef struct {
    wchar_t *path;
    unsigned __int64 size;
    BYTE md5[16]; // store partial MD5 first, then overwrite with full if needed
    int error;
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
void print_progress(size_t current, size_t total, const wchar_t *stage, const wchar_t *path) {
    double percent = (double)current / total * 100.0;

    // %ls for wide strings in wprintf/printf
    wprintf(L"\r[%ls] %zu/%zu (%.1f%%) %ls", stage, current, total, percent, path);
    // Add padding to clear long previous paths
    wprintf(L"                                        ");
    // Move cursor back for the next update
    wprintf(L"\r[%ls] %zu/%zu (%.1f%%) %ls", stage, current, total, percent, path);
    fflush(stdout); // Force update immediately
}

void clear_progress_line() {
    // Overwrite the entire line with spaces, then return to start
    wprintf(L"\r                                                                                \r");
    fflush(stdout);
}

// --- JSON helper ---
void json_escape_print(FILE *stream, const wchar_t *str) {
    // convert wide string to UTF-8 for JSON output
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
    char *utf8_str = malloc(utf8_len);
    if (!utf8_str) return; // handle malloc failure
    WideCharToMultiByte(CP_UTF8, 0, str, -1, utf8_str, utf8_len, NULL, NULL);

    fputc('"', stream);
    char *ptr = utf8_str;
    while (*ptr) {
        switch (*ptr) {
            case '\\': fprintf(stream, "\\\\"); break;
            case '"': fprintf(stream, "\\\""); break;
            case '\b': fprintf(stream, "\\b"); break;
            case '\f': fprintf(stream, "\\f"); break;
            case '\n': fprintf(stream, "\\n"); break;
            case '\r': fprintf(stream, "\\r"); break;
            case '\t': fprintf(stream, "\\t"); break;
            default:
                if ((unsigned char)*ptr < 32) fprintf(stream, "\\u%04x", *ptr);
                else fputc(*ptr, stream);
        }
        ptr++;
    }
    fputc('"', stream);
    free(utf8_str);
}

// Helper to print UTF-8 to file (avoids fwprintf/binary stream issues)
void print_utf8_to_stream(FILE *stream, const wchar_t *str) {
    int utf8_len = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
    char *utf8_str = malloc(utf8_len);
    if (!utf8_str) return;
    WideCharToMultiByte(CP_UTF8, 0, str, -1, utf8_str, utf8_len, NULL, NULL);
    fprintf(stream, "%s", utf8_str);
    free(utf8_str);
}

// --- Output helper ---
void report_duplicates(OutputContext *ctx, FileInfo **group, size_t count) {
    if (ctx->format == FORMAT_TEXT) {
        if (ctx->stream == stdout) {
            // Console output (let CRT handle wide chars)
            wprintf(L"MATCH:\n");
            for (size_t i = 0; i < count; i++) {
                wprintf(L"   %ls\n", group[i]->path);
            }
            wprintf(L"----------------------------------------\n");
        } else {
            // File output (force UTF-8 on binary stream)
            fprintf(ctx->stream, "MATCH:\n");
            for (size_t i = 0; i < count; i++) {
                fprintf(ctx->stream, "   ");
                print_utf8_to_stream(ctx->stream, group[i]->path);
                fprintf(ctx->stream, "\n");
            }
            fprintf(ctx->stream, "----------------------------------------\n");
        }
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

// --- Hashing Wrappers ---

// Compute MD5 hash of a file. If first_n_bytes > 0, only hash that many bytes (for partial hashing).
int get_file_md5(HCRYPTPROV hProv, const wchar_t *path, BYTE *output, unsigned long long first_n_bytes) {
    HCRYPTHASH hHash = 0;
    FILE *f = 0;
    int success = 0;

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) return 0;

    f = _wfopen(path, L"rb");
    if (!f) goto cleanup;

    unsigned char buffer[FILE_BUF_SIZE];
    size_t n;
    unsigned long long total_read = 0;

    while ((n = fread(buffer, 1, FILE_BUF_SIZE, f)) > 0) {
        if (first_n_bytes > 0 && total_read + n > first_n_bytes) {
            n = (size_t)(first_n_bytes - total_read);
        }
        
        if (!CryptHashData(hHash, buffer, (DWORD)n, 0)) goto cleanup;
        total_read += n;

        if (first_n_bytes > 0 && total_read >= first_n_bytes) break;
    }

    DWORD hashLen = 16;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, output, &hashLen, 0)) goto cleanup;
    success = 1;

cleanup:
    if (f) fclose(f);
    if (hHash) CryptDestroyHash(hHash);
    // hProv is managed by caller
    return success;
}

// --- List Management ---

void list_add(FileList *list, wchar_t *path, unsigned __int64 size) {
    if (list->count == list->capacity) {
        list->capacity = (list->capacity == 0) ? 1024 : list->capacity * 2;
        list->files = realloc(list->files, list->capacity * sizeof(FileInfo*));
    }
    FileInfo *fi = calloc(1, sizeof(FileInfo));
    fi->path = _wcsdup(path);
    fi->size = size;
    list->files[list->count++] = fi;
}

// --- Directory Scanning ---

void scan_dir(const wchar_t *basePath, FileList *list) {
    wchar_t searchPath[PATH_BUF_SIZE];
    swprintf(searchPath, PATH_BUF_SIZE, L"%ls\\*", basePath);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath, &fd);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

        // Skip reparse points (symlinks/junctions) to avoid infinite loops
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

        wchar_t fullPath[PATH_BUF_SIZE];
        swprintf(fullPath, PATH_BUF_SIZE, L"%ls\\%ls", basePath, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_dir(fullPath, list);
        } else {
            unsigned __int64 fileSize = ((unsigned __int64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            list_add(list, fullPath, fileSize);
        }
    } while (FindNextFileW(hFind, &fd));

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

int cmp_md5(const void *a, const void *b) {
    FileInfo *fa = *(FileInfo**)a;
    FileInfo *fb = *(FileInfo**)b;

    // Sort errors to the end and ensure they don't match each other
    if (fa->error && !fb->error) return 1;
    if (!fa->error && fb->error) return -1;
    if (fa->error && fb->error) return (fa > fb) ? 1 : -1;

    return memcmp(fa->md5, fb->md5, 16);
}

// --- Main ---

int wmain(int argc, wchar_t **argv) {
    // swith STDOUT to Unicode Mode
    _setmode(_fileno(stdout), _O_U16TEXT);

    if (argc < 2) {
        wprintf(L"dedup %s\n", VERSION);
        wprintf(L"Usage: dedup <directory> [-o <output_file>]\n");
        return 1;
    }
    wchar_t *dir_path = NULL;
    wchar_t *out_path = NULL;

    // arg parsing
    for (int i = 1; i < argc; i++) {
        if ((wcscmp(argv[i], L"-o") == 0 || wcscmp(argv[i], L"--output") == 0)) {
            if (i + 1 < argc) {
                out_path = argv[++i];
            } else {
                fwprintf(stderr, L"Error: --output requires a filename.\n");
                return 1;
            }
        } else if (argv[i][0] == '-') {
                fwprintf(stderr, L"Unknown option: %s\n", argv[i]);
                return 1;
        } else {
            dir_path = argv[i];
        }
    }
    if (!dir_path) {
        wprintf(L"Directory path is required.\n");
        return 1;
    }

    // setup output context
    OutputContext out_ctx = {0};
    out_ctx.stream = stdout;
    out_ctx.format = FORMAT_TEXT;
    out_ctx.first_json_entry = 1;
    if (out_path) {
        out_ctx.stream = _wfopen(out_path, L"wb");
        if (!out_ctx.stream) {
            perror("Error opening output file");
            return 1;
        }

        // detect JSON extension
        wchar_t *ext = wcsrchr(out_path, '.');
        if (ext && _wcsicmp(ext, L".json") == 0) { // _wcsicmp for case-insensitive comparison (Windows)
            out_ctx.format = FORMAT_JSON;
        }
    }

    FileList list = {0};
    wprintf(L"Scanning %ls...\n", dir_path);
    scan_dir(dir_path, &list);

    wprintf(L"Found %zu files. Sorting by size...\n", list.count);
    qsort(list.files, list.count, sizeof(FileInfo*), cmp_size);

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fwprintf(stderr, L"Error acquiring crypto context: %d\n", GetLastError());
        return 1;
    }

    if (out_ctx.format == FORMAT_JSON) {
        fprintf(out_ctx.stream, "[\n");
    }

    // --- Main Processing Loop ---
    // Pass 1: Group by Size
    size_t i = 0;
    while (i < list.count) {
        size_t j = i + 1;
        while (j < list.count && list.files[j]->size == list.files[i]->size) j++;

        // if file size group has more than 1 file, process further
        if (j - i > 1) {
            // Pass 2: compute partial MD5 of first 64KB
            for (size_t k = i; k < j; k++) {
                print_progress(k + 1, list.count, L"Pre-Scan", list.files[k]->path);
                if (!get_file_md5(hProv, list.files[k]->path, list.files[k]->md5, FILE_BUF_SIZE)) { // first 64KB
                    list.files[k]->error = 1; // mark error, will be sorted to end and not match anything
                }
            }

            // sort by partial MD5
            qsort(&list.files[i], j - i, sizeof(FileInfo*), cmp_md5);

            // group by partial MD5
            size_t p = i;
            while (p < j) {
                size_t q = p + 1;
                while (q<j&&memcmp(list.files[q]->md5, list.files[p]->md5, 16) == 0){
                    q++; // group with same partial MD5
                }

                // if group has more than 1 file, compute full MD5 and compare
                if (q - p > 1) {
                    // Pass 3: compute full MD5 for this group
                    for (size_t k = p; k < q; k++) {
                        if (list.files[k]->error) continue; // skip error files

                        // Optimization: if file is small enough, partial hash IS full hash
                        if (list.files[k]->size <= FILE_BUF_SIZE) continue;

                        print_progress(k + 1, list.count, L"Full-Scan", list.files[k]->path);
                        if (!get_file_md5(hProv, list.files[k]->path, list.files[k]->md5, 0)) {
                            list.files[k]->error = 1;
                        }
                    }

                    // sort by full MD5
                    qsort(&list.files[p], q - p, sizeof(FileInfo*), cmp_md5);

                    // group by full MD5 and report matches
                    size_t x = p;
                    while (x < q) {
                        size_t y = x + 1;
                        while (y < q && memcmp(list.files[y]->md5, list.files[x]->md5, 16) == 0) y++;
                        
                        // Check if valid group (no errors)
                        if (list.files[x]->error) {
                            x = y;
                            continue;
                        }

                        if (y - x > 1) {
                            // Match Found
                            clear_progress_line();

                            report_duplicates(&out_ctx, &list.files[x], y - x);

                            if (out_path) {
                                wprintf(L"\rFound match group... (logged)    ");
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
    wprintf(L"Done.\n");
    if (out_path) {
        wprintf(L"Output written to %ls", out_path);
        fclose(out_ctx.stream);
    }

    // cleanup memory
    for (size_t i=0; i<list.count; i++) {
        free(list.files[i]->path);
        free(list.files[i]);
    }
    free(list.files);

    if (hProv) CryptReleaseContext(hProv, 0);

    return 0;
}
