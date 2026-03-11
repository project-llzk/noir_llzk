# Noir -> LLZK

A tool to compile Noir to LLZK via ACIR.

## Prerequisites

- **Rust** (edition 2024)
- **LLVM 20** with MLIR support
- **zstd** (LLVM 20's MLIR libraries depend on libzstd for bitcode compression)
- **[plc-mlir](https://github.com/Veridise/pcl-mlir)** built locally (for PCL/MLIR libraries)

### macOS (Homebrew)

```sh
brew install llvm@20 zstd
```

### Building PCL

Clone and build the `pcl-mlir` component at a known-good commit:

```sh
git clone https://github.com/Veridise/pcl-mlir.git
cd pcl-mlir && git checkout a82620c4dabf6e51ceda66bba2abb19f7f74ac7d && cd ..
```

Make sure Homebrew's LLVM 20 tools are on your `PATH` and tell CMake where to find
the LLVM/MLIR CMake configs (Homebrew installs them outside the default search paths):

```sh
export PATH="$PATH:/opt/homebrew/opt/llvm@20/bin"
export CMAKE_PREFIX_PATH="$(llvm-config --cmakedir):$(llvm-config --cmakedir)/../mlir"
```

Build with CMake, using Homebrew's Clang (required for ABI compatibility with the
LLVM 20 libraries and for C++20 / Clang-specific coverage flags):

```sh
mkdir -p pcl-mlir/build
cmake -S pcl-mlir -B pcl-mlir/build \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=OFF \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_COMPILER=clang
cmake --build pcl-mlir/build
```

Note the path to `pcl-mlir` — you'll need it for the environment variables below.

## Build

### Environment variables

The following environment variables must be set before building:

| Variable | Description |
|---|---|
| `MLIR_SYS_200_PREFIX` | LLVM 20 installation prefix |
| `TABLEGEN_200_PREFIX` | LLVM 20 installation prefix (same as above) |
| `LIBCLANG_PATH` | Path to `libclang` shared library |
| `LLZK_PCL_ROOT` | Path to `pcl-mlir` source directory |
| `LLZK_PCL_PREFIX` | Path to `pcl-mlir/build` output directory |


 If MLIR's and LLVM's installation is not on standard paths set them here.
 For example, for a homebrew version of LLVM on macOS use this path.
`export RUSTFLAGS='-L /opt/homebrew/lib/'`
 This variable may need to be configured on macOS as well. If building fails try setting it.
`export LIBCLANG_PATH=$MLIR_SYS_200_PREFIX/lib`

### Compile

```sh
cargo build
```