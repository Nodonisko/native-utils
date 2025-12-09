#!/bin/bash

# Build script for generating Botan cpp files for different architectures
# This script creates optimized builds for iOS and Android target architectures

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BOTAN_DIR="$PROJECT_ROOT/cpp/botan"
BOTAN_GENERATED_DIR="$PROJECT_ROOT/cpp/botan_generated"
OUTPUT_DIR="$PROJECT_ROOT/cpp"

echo "🚀 Building Botan amalgamation files..."
echo "Project root: $PROJECT_ROOT"
echo "Botan directory: $BOTAN_DIR"
echo "Generated files directory: $BOTAN_GENERATED_DIR"
echo "Output directory: $OUTPUT_DIR"

# Create botan_generated directory if it doesn't exist
mkdir -p "$BOTAN_GENERATED_DIR"

# Configuration variables
BOTAN_MODULES="keccak,hmac,sha2_32,sha2_64,ed25519"
COMMON_FLAGS="--amalgamation --minimized-build --disable-cc-tests"

echo "📦 Using modules: $BOTAN_MODULES"

# Check if Botan submodule exists
if [ ! -d "$BOTAN_DIR" ]; then
    echo "❌ Error: Botan submodule not found at $BOTAN_DIR"
    echo "Please run: git submodule add https://github.com/randombit/botan.git cpp/botan"
    exit 1
fi

# Navigate to Botan directory
cd "$BOTAN_DIR"

# Check if configure.py exists
if [ ! -f "configure.py" ]; then
    echo "❌ Error: configure.py not found in Botan directory"
    exit 1
fi

# Function to build Botan for a specific configuration
build_botan() {
    local cpu_arch="$1"
    local os_type="$2"
    local build_name="$3"
    local description="$4"
    
    echo "$description"
    ./configure.py \
        --cpu="$cpu_arch" \
        --os="$os_type" \
        $COMMON_FLAGS \
        --enable-modules="$BOTAN_MODULES" \
        --name-amalgamation="$build_name" \
        --with-build-dir="$BOTAN_GENERATED_DIR"
    
    # Check if files were generated in the botan directory
    if [ ! -f "${build_name}.cpp" ] || [ ! -f "${build_name}.h" ]; then
        echo "❌ Error: $build_name files not generated"
        exit 1
    fi
    
    # Move generated files to botan_generated directory
    mv "${build_name}.cpp" "$BOTAN_GENERATED_DIR/"
    mv "${build_name}.h" "$BOTAN_GENERATED_DIR/"
    
    echo "✅ $build_name files generated successfully"
}

# Build different configurations with proper OS flags
build_botan "armv8-a" "ios" "botan_ios_arm64" "📱 Generating iOS ARM64 optimized build..."
build_botan "arm64" "android" "botan_android_arm64" "🤖 Generating Android ARM64 optimized build..."
build_botan "generic" "generic" "botan_generic" "📟 Generating generic portable build (for simulators and x86)..."

# Remove build artifacts we don't need
rm -rf "$BOTAN_GENERATED_DIR/build"
rm -f "$BOTAN_GENERATED_DIR/Makefile"
rm -f "$BOTAN_GENERATED_DIR"/*.txt
rm -f "$BOTAN_GENERATED_DIR"/*.log

echo "✅ Botan amalgamation files generated successfully!"

