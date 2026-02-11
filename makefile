# hardcode the path to MinGW bin folder
MINGW_BIN = C:\msys64\mingw64\bin

# standard settings
CC = gcc
# -O3: Max speed
# -s: Strip debug symbols (Smallest binary)
# -flto: Link Time Optimization (Faster code layout)
# -DNDEBUG: Disable debug macros
CFLAGS = -O3 -s -flto -DNDEBUG -Wall -municode
LIBS = -ladvapi32

# Separate directory and target for cleaner logic
OUT_DIR = bin
TARGET = $(OUT_DIR)/dedup.exe
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	@echo [SETUP] Creating output directory if missing...
	@if not exist $(OUT_DIR) mkdir $(OUT_DIR)
	@echo ----------------------------------------------------------
	@echo [FIX] Temporarily setting PATH to include: $(MINGW_BIN)
	@echo ----------------------------------------------------------
	set PATH=$(MINGW_BIN);%PATH% && $(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	@if exist $(TARGET) del /Q "$(OUT_DIR)\dedup.exe"
	@if exist $(OUT_DIR) rmdir $(OUT_DIR)
	@echo Cleaned up.
