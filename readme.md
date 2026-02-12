# dedup

A high-performance CLI tool for identifying duplicate files within a directory tree. It implements a three-stage filter to minimize I/O and CPU usage:

1. **File Size**: Filters unique file sizes instantly.
2. **Partial MD5**: Perform partial MD5 hash on files with matching sizes.
3. **Full MD5**: Performs full MD5 hash on files with matching sizes and Partial MD5 checksums.

## Usage

```sh
dedup.exe <directory> [-o <output_file>]
```

**Example Output:**

```text
Scanning test...
Found 3 files. Sorting by size...
[MD5] test\b.txt
MATCH:
   test\b.txt
   test\a.txt
----------------------------------------

Done.
```

## Build

### GCC (MinGW)

Run the standard makefile:

```sh
make
```

or build with command line:

```sh
gcc -O3 -s -flto -DNDEBUG -Wall -municode -o dedup.exe main.c -ladvapi32
```

### Visual Studio (MSVC)

Run the NMAKE file from the Developer Command Prompt:

```sh
nmake -f Makefile.nmake
```

or build with command line:

```sh
cl /O2 /GL /DNDEBUG /W3 /nologo main.c /Fe:dedup.exe
```
