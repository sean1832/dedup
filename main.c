
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>
#include <winnt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Explicitly define NTSTATUS if not defined
#ifndef _NTDEF_
typedef LONG NTSTATUS;
#define _NTDEF_
#endif

#define XXH_INLINE_ALL
#include "xxhash.h"

#define PATH_BUF_SIZE 8192
#define FILE_BUF_SIZE (64 * 1024)
#define VERSION L"0.1.0"

// --- Data Structures ---
typedef struct {
  wchar_t *path;
  unsigned __int64 size;
  BYTE hash[16]; // generic hash buffer (fixed to 16 bytes for 128-bit XXH3)
  int error;

  // File ID metadata
  DWORD volume_serial;
  DWORD file_index_high;
  DWORD file_index_low;
  int id_populated; // flag to indicate if file ID has been populated
} FileInfo;

// --- Hashing Wrappers ---

// Initialize hash context. Returns 1 on success, 0 on failure.
int hash_init(XXH3_state_t **state) {
  *state = XXH3_createState();
  if (*state == NULL)
    return 0;
  if (XXH3_128bits_reset(*state) == XXH_ERROR) {
    XXH3_freeState(*state);
    return 0;
  }
  return 1;
}

// Update hash with data. Returns 1 on success, 0 on failure.
int hash_update(XXH3_state_t *state, const void *data, size_t len) {
  if (XXH3_128bits_update(state, data, len) == XXH_ERROR)
    return 0;
  return 1;
}

// Finalize hash and write to output. Cleans up context.
// Returns 1 on success, 0 on failure.
int hash_finalize(XXH3_state_t **state, BYTE *out) {
  XXH128_hash_t hash = XXH3_128bits_digest(*state);
  memcpy(out, &hash, 16);
  XXH3_freeState(*state);
  *state = NULL;
  return 1;
}

typedef struct {
  FileInfo **files;
  size_t count;
  size_t capacity;
} FileList;

typedef enum { FORMAT_TEXT, FORMAT_JSON } OutputFormat;

typedef struct {
  FILE *stream;
  OutputFormat format;
  int first_json_entry; // To handle JSON commas correctly
} OutputContext;

// --- Helper: Progress Display ---
// prints: [Stage] 10/500 (2.0%) C:\path\to\file.txt
// leftovers
void print_progress(size_t current, size_t total, const wchar_t *stage,
                    const wchar_t *path) {
  double percent = (double)current / total * 100.0;

  // %ls for wide strings in wprintf/printf
  wprintf(L"\r[%ls] %zu/%zu (%.1f%%) %ls", stage, current, total, percent,
          path);
  // Add padding to clear long previous paths
  wprintf(L"                                        ");
  // Move cursor back for the next update
  wprintf(L"\r[%ls] %zu/%zu (%.1f%%) %ls", stage, current, total, percent,
          path);
  fflush(stdout); // Force update immediately
}

void clear_progress_line() {
  // Overwrite the entire line with spaces, then return to start
  wprintf(L"\r                                                                 "
          L"               \r");
  fflush(stdout);
}

// --- JSON helper ---
void json_escape_print(FILE *stream, const wchar_t *str) {
  // convert wide string to UTF-8 for JSON output
  int utf8_len = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
  char *utf8_str = malloc(utf8_len);
  if (!utf8_str)
    return; // handle malloc failure
  WideCharToMultiByte(CP_UTF8, 0, str, -1, utf8_str, utf8_len, NULL, NULL);

  fputc('"', stream);
  char *ptr = utf8_str;
  while (*ptr) {
    switch (*ptr) {
    case '\\':
      fprintf(stream, "\\\\");
      break;
    case '"':
      fprintf(stream, "\\\"");
      break;
    case '\b':
      fprintf(stream, "\\b");
      break;
    case '\f':
      fprintf(stream, "\\f");
      break;
    case '\n':
      fprintf(stream, "\\n");
      break;
    case '\r':
      fprintf(stream, "\\r");
      break;
    case '\t':
      fprintf(stream, "\\t");
      break;
    default:
      if ((unsigned char)*ptr < 32)
        fprintf(stream, "\\u%04x", *ptr);
      else
        fputc(*ptr, stream);
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
  if (!utf8_str)
    return;
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
  } else if (ctx->format == FORMAT_JSON) {
    if (!ctx->first_json_entry) {
      fprintf(ctx->stream, ",\n");
    }
    ctx->first_json_entry = 0;

    fprintf(ctx->stream, "  [\n");
    for (size_t i = 0; i < count; i++) {
      fprintf(ctx->stream, "    ");
      json_escape_print(ctx->stream, group[i]->path);
      if (i < count - 1)
        fprintf(ctx->stream, ",");
      fprintf(ctx->stream, "\n");
    }
    fprintf(ctx->stream, "  ]");
  }
}

// Compute Hash of a file. If first_n_bytes > 0, only hash that many bytes (for
// partial hashing).
int get_file_hash(const wchar_t *path, BYTE *output, unsigned long long first_n_bytes) {
  FILE *f = _wfopen(path, L"rb");
  if (!f)
    return 0;

  XXH3_state_t *state = NULL;
  if (!hash_init(&state)) {
    fclose(f);
    return 0;
  }

  unsigned char buffer[FILE_BUF_SIZE];
  size_t n;
  unsigned long long total_read = 0;
  int success = 0;

  while ((n = fread(buffer, 1, FILE_BUF_SIZE, f)) > 0) {
    if (first_n_bytes > 0 && total_read + n > first_n_bytes) {
      n = (size_t)(first_n_bytes - total_read);
    }

    if (!hash_update(state, buffer, n))
      goto cleanup;
    total_read += n;

    if (first_n_bytes > 0 && total_read >= first_n_bytes)
      break;
  }

  if (hash_finalize(&state, output)) {
    success = 1;
    // ctx is already cleaned up by finalize
  } else {
    // finalize failed
  }

cleanup:
  if (!success && state) {
    XXH3_freeState(state);
  }

  fclose(f);
  return success;
}

// --- List Management ---

void list_add(FileList *list, wchar_t *path, unsigned __int64 size) {
  if (list->count == list->capacity) {
    list->capacity = (list->capacity == 0) ? 1024 : list->capacity * 2;
    list->files = realloc(list->files, list->capacity * sizeof(FileInfo *));
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

  if (hFind == INVALID_HANDLE_VALUE)
    return;

  do {
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
      continue;

    // Skip reparse points (symlinks/junctions) to avoid infinite loops
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
      continue;

    wchar_t fullPath[PATH_BUF_SIZE];
    swprintf(fullPath, PATH_BUF_SIZE, L"%ls\\%ls", basePath, fd.cFileName);

    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
      scan_dir(fullPath, list);
    } else {
      unsigned __int64 fileSize =
          ((unsigned __int64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
      list_add(list, fullPath, fileSize);
    }
  } while (FindNextFileW(hFind, &fd));

  FindClose(hFind);
}

int populate_file_id(FileInfo *fi) {
    if (fi->id_populated) return 1;

    // open handle with 0 access rights to read metadata without locking or trigger IO reads
    HANDLE hFile = CreateFileW(fi->path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fi->error = 1;
        return 0;
    }

    BY_HANDLE_FILE_INFORMATION fileInfo;
    if (GetFileInformationByHandle(hFile, &fileInfo)) {
        fi->volume_serial = fileInfo.dwVolumeSerialNumber;
        fi->file_index_high = fileInfo.nFileIndexHigh;
        fi->file_index_low = fileInfo.nFileIndexLow;
        fi->id_populated = 1;
    } else {
        fi->error = 1;
    }

    CloseHandle(hFile);
    return fi->id_populated;
}


// --- Hardlinks ---

// Replace duplicate with hardlink to source. Returns 1 on success, 0 on failure.
int create_hardlink_replacement(const wchar_t *source, const wchar_t *duplicate) {
    wchar_t temp_path[PATH_BUF_SIZE];
    if (swprintf(temp_path, PATH_BUF_SIZE, L"%ls.dedup_temp", duplicate) < 0) {
        fwprintf(stderr, L"Error creating temp path for %ls: %lu\n", duplicate, GetLastError());
        return 0; // Failed to create temp path
    }
    if (!MoveFileW(duplicate, temp_path)) {
        fwprintf(stderr, L"Error moving original file to temp path for %ls: %lu\n", duplicate, GetLastError());
        return 0; // Failed to move original file to temp path
    }
    if (!CreateHardLinkW(duplicate, source, NULL)) {
        fwprintf(stderr, L"Error creating hardlink from %ls to %ls: %lu\n", source, duplicate, GetLastError());

        // rollback: move temp file back to original location
        if (!MoveFileW(temp_path, duplicate)) {
            fwprintf(stderr, L"CRITICAL: Failed to rollback after hardlink failure for %ls: %lu\n", duplicate, GetLastError());
        }
        return 0; // Failed to create hardlink
    }

    // success, delete the temp file
    if (!DeleteFileW(temp_path)) {
        fwprintf(stderr, L"Warning: Failed to delete temp file %ls after hardlink creation: %lu\n", temp_path, GetLastError());
    }
    return 1; // Success
}

// --- Comparators ---

int cmp_size(const void *a, const void *b) {
  FileInfo *fa = *(FileInfo **)a;
  FileInfo *fb = *(FileInfo **)b;
  if (fa->size < fb->size)
    return -1;
  if (fa->size > fb->size)
    return 1;
  return 0;
}

int cmp_hash(const void *a, const void *b) {
  FileInfo *fa = *(FileInfo **)a;
  FileInfo *fb = *(FileInfo **)b;

  // Sort errors to the end and ensure they don't match each other
  if (fa->error && !fb->error)
    return 1;
  if (!fa->error && fb->error)
    return -1;
  if (fa->error && fb->error)
    return (fa > fb) ? 1 : -1;

  return memcmp(fa->hash, fb->hash, 16);
}

// --- Help message ---
void print_help() {
    wprintf(L"dedup %ls\n", VERSION);
    wprintf(L"Usage: dedup <directory> [OPTIONS]\n");
    wprintf(L"Options:\n");
    wprintf(L"  -o, --output <file>   Write output to file (JSON if .json extension)\n");
    wprintf(L"  -l, --hardlink        Replace duplicates with hardlinks (destructive!)\n");

    wprintf(L"  -s, --silent          Silent mode\n");
    wprintf(L"  -h, --help            Show this help message\n");
}

// --- Main ---
int wmain(int argc, wchar_t **argv) {
  // swith STDOUT to Unicode Mode
  _setmode(_fileno(stdout), _O_U16TEXT);

  if (argc < 2) {
    print_help();
    return 1;
  }
  wchar_t *dir_path = NULL;
  wchar_t *out_path = NULL;
  BOOL hardlink_mode = FALSE;

  // arg parsing
  for (int i = 1; i < argc; i++) {
    if ((wcscmp(argv[i], L"-o") == 0 || wcscmp(argv[i], L"--output") == 0)) {
      if (i + 1 < argc) {
        out_path = argv[++i];
      } else {
        fwprintf(stderr, L"Error: --output requires a filename.\n");
        return 1;
      }
    } else if (wcscmp(argv[i], L"-l") == 0 || wcscmp(argv[i], L"--hardlink") == 0) {
        // if silent mode is enabled, don't show the prompt.
        if (wcscmp(argv[i], L"-s") != 0 && wcscmp(argv[i], L"--silent") != 0) {
            wprintf(L"WARNING: Hardlink mode is destructive! This will replace duplicate files with hardlinks to save space, but it will DELETE the duplicates. Make sure you have a backup before using this option.\n");
            wprintf(L"Do you want to proceed? (y/N): ");
            wchar_t response = getwchar();
            if (response != L'y' && response != L'Y') {
                wprintf(L"Aborting.\n");
                return 0;
            }
        }
        hardlink_mode = TRUE;
    } else if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"--help") == 0) {
        print_help();
        return 0;
    } else if (argv[i][0] == '-') {
        fwprintf(stderr, L"Unknown option: %s\n", argv[i]);
        print_help();
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
    if (ext && _wcsicmp(ext, L".json") == 0) {
      // _wcsicmp for case-insensitive comparison (Windows)
      out_ctx.format = FORMAT_JSON;
    }
  }

  FileList list = {0};
  wprintf(L"Scanning %ls...\n", dir_path);
  scan_dir(dir_path, &list);

  wprintf(L"Found %zu files. Sorting by size...\n", list.count);
  qsort(list.files, list.count, sizeof(FileInfo *), cmp_size);

  if (out_ctx.format == FORMAT_JSON) {
    fprintf(out_ctx.stream, "[\n");
  }

  // --- Main Processing Loop ---
  // Pass 1: Group by Size
  size_t i = 0;
  while (i < list.count) {
    size_t j = i + 1;
    while (j < list.count && list.files[j]->size == list.files[i]->size)
      j++;

    // if file size group has more than 1 file, process further
    if (j - i > 1) {
      // Pass 2: compute partial Hash of first 64KB
      for (size_t k = i; k < j; k++) {
        print_progress(k + 1, list.count, L"Pre-Scan", list.files[k]->path);
        if (!get_file_hash(list.files[k]->path,
                           list.files[k]->hash, FILE_BUF_SIZE)) { // first 64KB
          list.files[k]->error =
              1; // mark error, will be sorted to end and not match anything
        }
      }

      // sort by partial Hash
      qsort(&list.files[i], j - i, sizeof(FileInfo *), cmp_hash);

      // group by partial Hash
      size_t p = i;
      while (p < j) {
        size_t q = p + 1;
        while (q < j &&
               memcmp(list.files[q]->hash, list.files[p]->hash, 16) == 0) {
          q++; // group with same partial Hash
        }

        // if group has more than 1 file, compute full Hash and compare
        if (q - p > 1) {
          // Pass 3: compute full Hash for this group
          for (size_t k = p; k < q; k++) {
            if (list.files[k]->error)
              continue; // skip error files

            // Optimization: if file is small enough, partial hash IS full hash
            if (list.files[k]->size <= FILE_BUF_SIZE)
              continue;

            print_progress(k + 1, list.count, L"Full-Scan",
                           list.files[k]->path);
            if (!get_file_hash(list.files[k]->path,
                               list.files[k]->hash, 0)) {
              list.files[k]->error = 1;
            }
          }

          // sort by full Hash
          qsort(&list.files[p], q - p, sizeof(FileInfo *), cmp_hash);

          // group by full Hash and report matches
          size_t x = p;
          while (x < q) {
            size_t y = x + 1;
            while (y < q &&
                   memcmp(list.files[y]->hash, list.files[x]->hash, 16) == 0)
              y++;

            // Check if valid group (no errors)
            if (list.files[x]->error) {
              x = y;
              continue;
            }

            if (y - x > 1) {
              // Match Found
              clear_progress_line();
              report_duplicates(&out_ctx, &list.files[x], y - x);
              // hardlink
              if (hardlink_mode) {
                  if (!populate_file_id(list.files[x])) {
                    fwprintf(stderr, L"Failed to populate file ID for %ls. Skipping hardlinking for this group.\n", list.files[x]->path);
                    continue;
                  }

                  // Replace duplicates with hardlinks to the first file in the group
                  for (size_t k = x + 1; k < y; k++) {
                      if (!populate_file_id(list.files[k])) {
                          fwprintf(stderr, L"Failed to read metadata for duplicate %ls\n", list.files[k]->path);
                          continue;
                      }

                      // checking existing hardlink, if exist continue
                      if (list.files[x]->volume_serial == list.files[k]->volume_serial &&
                          list.files[x]->file_index_high == list.files[k]->file_index_high &&
                          list.files[x]->file_index_low == list.files[k]->file_index_low) {
                              wprintf(L"Skipped: %ls is already hardlinked to source.\n", list.files[k]->path);
                              continue;
                          }
                      // volume boundary check
                      if (list.files[x]->volume_serial != list.files[k]->volume_serial) {
                          fwprintf(stderr, L"Skipped: %ls and %ls reside on different volume.\n", list.files[x]->path, list.files[k]->path);
                          continue;
                      }

                      // create hardlink replacement
                      if (!create_hardlink_replacement(list.files[x]->path, list.files[k]->path)){
                          fwprintf(stderr, L"Failed to replace %ls\n", list.files[k]->path);
                      } else {
                          wprintf(L"Replace %ls with hardlink to %ls\n", list.files[x]->path, list.files[k]->path);
                      }
                  }
              }

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
  for (size_t i = 0; i < list.count; i++) {
    free(list.files[i]->path);
    free(list.files[i]);
  }
  free(list.files);

  return 0;
}
