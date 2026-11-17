#!/usr/bin/env bash
# build.sh — DQMEA cross-compile from Linux to Windows .exe
# Requires: mingw-w64 (x86_64-w64-mingw32-g++)
# Run from project root: ./build.sh
#
# Usage:
#   ./build.sh            # incremental build (only changed files)
#   ./build.sh --clean    # full rebuild (wipes build/obj/)
#   ./build.sh --verbose  # show full compiler output

set -euo pipefail

# ────────────────────────────────────────────────────────────────
# Colors
# ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[0;33m'
CYN='\033[0;36m'; DIM='\033[2m'; NC='\033[0m'

log()  { echo -e "${GRN}[+]${NC} $*"; }
warn() { echo -e "${YEL}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }
step() { echo -e "${CYN}[*]${NC} $*"; }

# ────────────────────────────────────────────────────────────────
# Parse args
# ────────────────────────────────────────────────────────────────
CLEAN=0
VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        --clean)   CLEAN=1 ;;
        --verbose) VERBOSE=1 ;;
        -h|--help)
            echo "usage: $0 [--clean] [--verbose]"
            exit 0
            ;;
        *)
            err "unknown flag: $arg"
            exit 1
            ;;
    esac
done

# ────────────────────────────────────────────────────────────────
# Locate project root
# ────────────────────────────────────────────────────────────────
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT/src"
OUT="$ROOT/output"
OBJ="$ROOT/build/obj"
RES="$ROOT/resources"

mkdir -p "$OUT" "$OBJ"

# ────────────────────────────────────────────────────────────────
# Check toolchain
# ────────────────────────────────────────────────────────────────
CXX="${CXX:-x86_64-w64-mingw32-g++}"
STRIP="${STRIP:-x86_64-w64-mingw32-strip}"
WINDRES="${WINDRES:-x86_64-w64-mingw32-windres}"

if ! command -v "$CXX" &>/dev/null; then
    err "mingw-w64 not found. Install it:"
    echo "    Debian/Ubuntu: sudo apt install mingw-w64"
    echo "    Fedora:        sudo dnf install mingw64-gcc-c++"
    echo "    Arch:          sudo pacman -S mingw-w64-gcc"
    exit 1
fi

log "compiler: $($CXX --version | head -1)"

# ────────────────────────────────────────────────────────────────
# Clean
# ────────────────────────────────────────────────────────────────
if [[ $CLEAN -eq 1 ]]; then
    step "clean: wiping $OBJ and $OUT/DQMEA.exe"
    rm -rf "$OBJ"/*
    rm -f  "$OUT/DQMEA.exe" "$OUT/DQMEA.exe.strip"
    mkdir -p "$OBJ"
fi

# ────────────────────────────────────────────────────────────────
# Flags
# ────────────────────────────────────────────────────────────────
CXXFLAGS=(
    -std=c++20
    -O2
    -DNDEBUG
    -DUNICODE
    -D_UNICODE
    -DWIN32_LEAN_AND_MEAN
    -fno-exceptions
    -fno-rtti
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-cast-function-type
    -Wno-unknown-pragmas
    -Wno-missing-field-initializers
    -I"$SRC"
)

LDFLAGS=(
    -static
    -static-libgcc
    -static-libstdc++
    -mwindows
    -lbcrypt
    -lws2_32
    -lshlwapi
    -ladvapi32
    -luser32
    -lgdi32
    -lole32
    -loleaut32
    -lwbemuuid
    -lpsapi
    -lwininet
    -lshell32
    -lnetapi32
    -lmpr
    -liphlpapi
)

# ────────────────────────────────────────────────────────────────
# Source discovery
# ────────────────────────────────────────────────────────────────
mapfile -t SOURCES < <(find "$SRC" -name '*.cpp' -type f | sort)

if [[ ${#SOURCES[@]} -eq 0 ]]; then
    err "no .cpp files found under $SRC"
    exit 1
fi
log "found ${#SOURCES[@]} source files"

# ────────────────────────────────────────────────────────────────
# Compile
# ────────────────────────────────────────────────────────────────
step "compiling..."
FAIL=0
BUILT=0
SKIPPED=0

for src in "${SOURCES[@]}"; do
    rel="${src#$SRC/}"
    obj="$OBJ/${rel%.cpp}.o"
    mkdir -p "$(dirname "$obj")"

    # Incremental: skip if obj newer than src
    if [[ -f "$obj" && "$obj" -nt "$src" ]]; then
        echo -e "  ${DIM}[skip]${NC} $rel"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    echo -e "  ${CYN}[cc]${NC}   $rel"
    if [[ $VERBOSE -eq 1 ]]; then
        if ! "$CXX" "${CXXFLAGS[@]}" -c "$src" -o "$obj"; then
            err "failed: $rel"
            FAIL=1
        else
            BUILT=$((BUILT + 1))
        fi
    else
        ERRFILE=$(mktemp)
        if ! "$CXX" "${CXXFLAGS[@]}" -c "$src" -o "$obj" 2>"$ERRFILE"; then
            err "failed: $rel"
            cat "$ERRFILE" | sed 's/^/      /'
            FAIL=1
        else
            if [[ -s "$ERRFILE" ]]; then
                grep -v '^$' "$ERRFILE" | sed "s/^/      ${YEL}warn${NC}  /"
            fi
            BUILT=$((BUILT + 1))
        fi
        rm -f "$ERRFILE"
    fi
done

if [[ $FAIL -ne 0 ]]; then
    err "compilation failed"
    exit 1
fi

if [[ $BUILT -eq 0 ]]; then
    log "nothing to compile — all objects up to date"
fi

# ────────────────────────────────────────────────────────────────
# Resource compilation (optional — icon / version info)
# ────────────────────────────────────────────────────────────────
RES_OBJ=()
if [[ -f "$RES/dqmea.rc" ]] && command -v "$WINDRES" &>/dev/null; then
    rc_obj="$OBJ/dqmea.res.o"
    if [[ ! -f "$rc_obj" || "$RES/dqmea.rc" -nt "$rc_obj" ]]; then
        step "compiling resources..."
        "$WINDRES" -I"$RES" "$RES/dqmea.rc" "$rc_obj"
    fi
    RES_OBJ=("$rc_obj")
else
    if [[ -f "$RES/dqmea.rc" ]]; then
        warn "dqmea.rc exists but windres not found — skipping"
    fi
fi

# ────────────────────────────────────────────────────────────────
# Link
# ────────────────────────────────────────────────────────────────
step "linking..."
mapfile -t OBJS < <(find "$OBJ" -name '*.o' -type f | sort)

if [[ ${#OBJS[@]} -eq 0 ]]; then
    err "no object files to link"
    exit 1
fi

LINK_START=$(date +%s%N)

if ! "$CXX" "${OBJS[@]}" "${RES_OBJ[@]}" "${LDFLAGS[@]}" \
     -o "$OUT/DQMEA.exe"; then
    err "link failed"
    exit 1
fi

LINK_END=$(date +%s%N)
LINK_MS=$(( (LINK_END - LINK_START) / 1000000 ))

if [[ ! -f "$OUT/DQMEA.exe" ]]; then
    err "link produced no output"
    exit 1
fi

# ────────────────────────────────────────────────────────────────
# Strip
# ────────────────────────────────────────────────────────────────
if command -v "$STRIP" &>/dev/null; then
    cp "$OUT/DQMEA.exe" "$OUT/DQMEA.exe.strip"
    "$STRIP" "$OUT/DQMEA.exe.strip"
fi

# ────────────────────────────────────────────────────────────────
# Summary
# ────────────────────────────────────────────────────────────────
SIZE_RAW=$(stat -c%s "$OUT/DQMEA.exe" 2>/dev/null || stat -f%z "$OUT/DQMEA.exe")
SIZE_STRIPPED=0
if [[ -f "$OUT/DQMEA.exe.strip" ]]; then
    SIZE_STRIPPED=$(stat -c%s "$OUT/DQMEA.exe.strip" 2>/dev/null || stat -f%z "$OUT/DQMEA.exe.strip")
    mv "$OUT/DQMEA.exe.strip" "$OUT/DQMEA.exe"
fi

echo
echo -e "${GRN}══════════════════════════════════════════${NC}"
echo -e "${GRN}  BUILD OK${NC}"
echo -e "${GRN}══════════════════════════════════════════${NC}"
printf "  %-12s %s\n" "binary:"   "$OUT/DQMEA.exe"
printf "  %-12s %s KB\n" "size:" "$((SIZE_RAW / 1024))"
if [[ $SIZE_STRIPPED -gt 0 ]]; then
    printf "  %-12s %s KB\n" "stripped:" "$((SIZE_STRIPPED / 1024))"
fi
printf "  %-12s %s\n" "type:" "$(file "$OUT/DQMEA.exe" 2>/dev/null | cut -d: -f2- | xargs)"
printf "  %-12s %s built, %s skipped\n" "objects:" "$BUILT" "$SKIPPED"
printf "  %-12s %s ms\n" "link:" "$LINK_MS"
echo -e "${GRN}══════════════════════════════════════════${NC}"