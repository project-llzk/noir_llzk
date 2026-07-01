# Noir -> LLZK

A tool to compile Noir to LLZK via ACIR.

## Build

The recommended way to build this project is with the nix flake, which includes
pinned versions of the dependencies and builds them automatically.

### Prerequisites

- Nix (currently tested with versions 2.24 and 2.31)

#### Nix installation

Install Nix with the official installer:

```sh
curl -L https://nixos.org/nix/install | sh
```

After installation, restart your shell or source the Nix profile script so
`nix` is on your `PATH`.

### Nix operations

Build the default package:

```sh
nix build -L
```

Open a development shell with the pinned toolchain:

```sh
nix develop
```

From inside `nix develop`, run the usual Cargo commands:

```sh
cargo build
cargo test
```

You can also run a one-off command without entering an interactive shell:

```sh
nix develop -c cargo build
nix develop -c cargo test
```

Dependencies can be updated with, e.g.:

```sh
nix flake update llzk-rs-pkgs
```

### Manual setup

If you are not using Nix, you can still build manually with the dependencies
below.

#### Prerequisites

- **Rust** (edition 2024)
- **LLVM 20** with MLIR support
- **zstd** (LLVM 20's MLIR libraries depend on libzstd for bitcode compression)
- **[plc-mlir](https://github.com/Veridise/pcl-mlir)** built locally (for PCL/MLIR libraries)

#### macOS (Homebrew)

```sh
brew install llvm@20 zstd
```

Set the MLIR prefix path (used by the cmake commands below and by Cargo during build):

```sh
export MLIR_SYS_200_PREFIX=$(brew --prefix llvm@20)
```

#### Building PCL

Clone and build the `pcl-mlir` component at a known-good commit:

```sh
git clone https://github.com/Veridise/pcl-mlir.git
cd pcl-mlir && git checkout 55cf619b032314198aacafc305871fb66b12b70e && cd ..
```

Build with CMake:

```sh
cmake -S pcl-mlir -B pcl-mlir/build \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=OFF \
  -DCMAKE_PREFIX_PATH=$MLIR_SYS_200_PREFIX
cmake --build pcl-mlir/build
```

Note the path to `pcl-mlir` — you'll need it for the environment variables below.

#### Building LLZK

The [LLZK library](https://github.com/project-llzk/llzk-lib) must be built and installed separately.
The Rust bindings ([llzk-rs](https://github.com/Veridise/llzk-rs)) expect the `LLZK_SYS_10_PREFIX`
environment variable to point to the LLZK installation prefix.

Clone at the commit used by the `llzk-rs` v1 release:

```sh
git clone https://github.com/project-llzk/llzk-lib.git
cd llzk-lib && git checkout 030c16eeba535c5592d5cefc564a9101a3e2dc20 && cd ..
```

Build and install with CMake:

```sh
cd llzk-lib
cmake -B build -S . \
  -DCMAKE_INSTALL_PREFIX=$(pwd)/build/install \
  -DCMAKE_PREFIX_PATH=$MLIR_SYS_200_PREFIX
cmake --build build
cmake --install build
cd ..
```

Then set the `LLZK_SYS_10_PREFIX` environment variable to point to the install location:

```sh
export LLZK_SYS_10_PREFIX=$(pwd)/llzk-lib/build/install
```
#### Environment variables

The following environment variables must be set before building:

| Variable | Description |
|---|---|
| `MLIR_SYS_200_PREFIX` | LLVM 20 installation prefix |
| `TABLEGEN_200_PREFIX` | LLVM 20 installation prefix (same as above) |
| `LIBCLANG_PATH` | Path to `libclang` shared library |
| `LLZK_SYS_10_PREFIX` | Path to the LLZK installation prefix (see above) |
| `LLZK_PCL_ROOT` | Path to `pcl-mlir` source directory |
| `LLZK_PCL_PREFIX` | Path to `pcl-mlir/build` output directory |


 If MLIR's and LLVM's installation is not on standard paths set them here.
 For example, for a homebrew version of LLVM on macOS use this path.
`export RUSTFLAGS='-L /opt/homebrew/lib/'`
 This variable may need to be configured on macOS as well. If building fails try setting it.
`export LIBCLANG_PATH=$MLIR_SYS_200_PREFIX/lib`

#### Compile

```sh
cargo build
```

## Tests

The test suite is split by what each layer is meant to validate:

- `library/src/tests/blackboxes/` contains lowering and shape tests for ACIR
  blackbox opcodes. These check things like witness collection, input
  validation, helper emission, helper sharing, compute/constrain wiring, and
  LLZK module verification. They do not execute the generated LLZK.
- `library/src/tests/integration_tests.rs` compiles real Noir fixture programs
  with `nargo`, translates the resulting ACIR to LLZK, and verifies the module.
  These tests exercise the full compile/translate pipeline, but still do not
  execute the generated LLZK.
- `library/src/tests/e2e/blackboxes/` contains semantic blackbox tests. These
  translate ACIR to LLZK and execute the result with
  [`llzk_interpreter`](https://github.com/reilabs/llzk-interpreter).
- `library/src/blackboxes/` contains the module-level LLZK helper
  implementations used by both ACIR and Brillig lowering. Tests there build
  small helper modules and execute them directly with
  [`llzk_interpreter`](https://github.com/reilabs/llzk-interpreter).

Use the regular test target for unit, lowering/shape, and Noir fixture
integration coverage:

```sh
nix develop -c make test
```

If you are already inside `nix develop`, or are using a manual setup, run:

```sh
make test
```

Use the e2e target when you need to check emitted LLZK behavior:

```sh
nix develop -c make e2e
```

If you are already inside `nix develop`, or are using a manual setup, run:

```sh
make e2e
```
