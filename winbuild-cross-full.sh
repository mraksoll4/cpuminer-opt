#!/bin/bash
#
# Script for building Windows binaries release package using mingw.
# Builds all dependencies and creates release package with different CPU optimizations.

set -e  # Stop on error

mkdir -p $HOME/usr/lib

# Define variables
export HOME_DIR="$HOME"
export LOCAL_LIB="$HOME_DIR/usr/lib"
export MINGW_LIB="/usr/x86_64-w64-mingw32/lib"
export GCC_MINGW_LIB="/usr/lib/gcc/x86_64-w64-mingw32/9.3-win32"
export DEFAULT_CFLAGS="-maes -O3 -Wall"
export DEFAULT_CFLAGS_OLD="-O3 -Wall"

# Save the initial working directory
INITIAL_DIR="$(pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}Starting build process...${NC}"

# Create directories
mkdir -p "$LOCAL_LIB"

# Install required packages
echo -e "${GREEN}Installing required packages...${NC}"
sudo apt-get update
sudo apt-get install -y build-essential automake autoconf pkg-config libssl-dev
sudo apt-get install -y libgmp-dev libcurl4-openssl-dev libjansson-dev
sudo apt-get install -y mingw-w64 libz-mingw-w64-dev

# Build CURL
echo -e "${GREEN}Building CURL...${NC}"
cd "$LOCAL_LIB"
wget https://github.com/curl/curl/releases/download/curl-7_68_0/curl-7.68.0.tar.gz
tar xzf curl-7.68.0.tar.gz
cd curl-7.68.0

# Configure and build curl for Windows
./configure --host=x86_64-w64-mingw32 \
    --with-winssl \
    --enable-shared \
    --disable-static \
    --prefix="$LOCAL_LIB/curl" \
    --without-zlib

make -j$(nproc)
make install

# Build GMP
echo -e "${GREEN}Building GMP...${NC}"
cd "$LOCAL_LIB"
wget https://gmplib.org/download/gmp/gmp-6.2.0.tar.xz
tar xf gmp-6.2.0.tar.xz
cd gmp-6.2.0

# Configure and build GMP
./configure --host=x86_64-w64-mingw32 \
    --enable-static \
    --disable-shared \
    --prefix="$LOCAL_LIB/gmp"

make -j$(nproc)
make install

# Set up environment for cpuminer build
export PATH="$LOCAL_LIB/curl/bin:$PATH"
export PKG_CONFIG_PATH="$LOCAL_LIB/curl/lib/pkgconfig:$PKG_CONFIG_PATH"
export LDFLAGS="-L$LOCAL_LIB/curl/lib -L$LOCAL_LIB/gmp/lib"
export CPPFLAGS="-I$LOCAL_LIB/curl/include -I$LOCAL_LIB/gmp/include"
export CONFIGURE_ARGS="--with-curl=$LOCAL_LIB/curl --host=x86_64-w64-mingw32"

# Return to the initial working directory
cd "$INITIAL_DIR"

# Create release directory and copy DLLs
echo -e "${GREEN}Creating release directory and copying DLLs...${NC}"
rm -rf release
mkdir -p release

# Copy documentation
cp README.txt release/ 2>/dev/null || echo "README.txt not found"
cp README.md release/ 2>/dev/null || echo "README.md not found"
cp RELEASE_NOTES release/ 2>/dev/null || echo "RELEASE_NOTES not found"
cp verthash-help.txt release/ 2>/dev/null || echo "verthash-help.txt not found"

# Copy required DLLs
cp "$MINGW_LIB/zlib1.dll" release/
cp "$MINGW_LIB/libwinpthread-1.dll" release/
cp "$GCC_MINGW_LIB/libstdc++-6.dll" release/
cp "$GCC_MINGW_LIB/libgcc_s_seh-1.dll" release/
cp "$LOCAL_LIB/curl/bin/libcurl-4.dll" release/

# Link GMP header
ln -sf "$LOCAL_LIB/gmp/include/gmp.h" ./gmp.h

# Function to build a specific version
build_version() {
    local cflags="$1"
    local output_name="$2"
    
    echo -e "${GREEN}Building $output_name...${NC}"
    make clean || echo "clean"
    rm -f config.status
    CFLAGS="$cflags" ./configure $CONFIGURE_ARGS
    make -j$(nproc)
    strip -s cpuminer.exe
    mv cpuminer.exe "release/$output_name"
}

# Generate build files
./autogen.sh

# Build all versions
build_version "-march=icelake-client $DEFAULT_CFLAGS" "cpuminer-avx512-sha-vaes.exe"
build_version "-march=skylake-avx512 $DEFAULT_CFLAGS" "cpuminer-avx512.exe"
build_version "-mavx2 -msha -mvaes $DEFAULT_CFLAGS" "cpuminer-avx2-sha-vaes.exe"
build_version "-march=znver1 $DEFAULT_CFLAGS" "cpuminer-avx2-sha.exe"
build_version "-march=core-avx2 $DEFAULT_CFLAGS" "cpuminer-avx2.exe"
build_version "-march=corei7-avx -maes $DEFAULT_CFLAGS_OLD" "cpuminer-avx.exe"
build_version "-march=westmere -maes $DEFAULT_CFLAGS_OLD" "cpuminer-aes-sse42.exe"
build_version "-msse2 $DEFAULT_CFLAGS_OLD" "cpuminer-sse2.exe"

# Generate hashes and save to file
echo -e "${GREEN}Generating hash sums...${NC}"
cd release
sha256sum * > hashes.txt
cat hashes.txt
cd "$INITIAL_DIR"

# Create release archive
echo -e "${GREEN}Creating release archive...${NC}"
zip -r cpuminer-windows-x64.zip release/

echo -e "${GREEN}Build complete! Release package created as cpuminer-windows-x64.zip${NC}"
