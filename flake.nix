{
  inputs = {
    llzk-pkgs.url = "github:project-llzk/llzk-nix-pkgs";
    nixpkgs.follows = "llzk-pkgs/nixpkgs";
    flake-utils.follows = "llzk-pkgs/flake-utils";
    noir-src = {
      url = "github:noir-lang/noir/v1.0.0-beta.19";
      flake = false;
    };
    llzk-rs-pkgs = {
      url = "git+https://github.com/project-llzk/llzk-rs";
      inputs = {
        nixpkgs.follows = "llzk-pkgs/nixpkgs";
        flake-utils.follows = "llzk-pkgs/flake-utils";
        llzk-pkgs.follows = "llzk-pkgs";
      };
    };
    llzk-lib.follows = "llzk-rs-pkgs/llzk-lib";
    release-helpers.follows = "llzk-rs-pkgs/llzk-lib/release-helpers";
    rust-overlay.follows = "llzk-rs-pkgs/rust-overlay";
  };

  # Custom colored bash prompt
  nixConfig.bash-prompt = "\\[\\e[0;32m\\][noir]\\[\\e[m\\] \\[\\e[38;5;244m\\]\\w\\[\\e[m\\] % ";

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      noir-src,
      release-helpers,
      llzk-pkgs,
      llzk-lib,
      llzk-rs-pkgs,
      rust-overlay,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (import rust-overlay)
            llzk-pkgs.overlays.default
            llzk-lib.overlays.default
            llzk-rs-pkgs.overlays.default
            release-helpers.overlays.default
          ];
        };

        projectSrc = builtins.path {
          path = ./.;
          name = "noir-to-llzk-src";
          filter =
            path: type:
            let
              base = builtins.baseNameOf path;
            in
            !(
              base == ".git"
              || base == "target"
              || base == "result"
              || base == "build-tools"
            );
        };

        # Lit tests need FileCheck but directly adding the LLVM `bin` dir to the path causes
        # linking problems in `llzk-sys`. Instead, create a symlink in a new directory for the path.
        createFileCheckSymlink = ''
          mkdir -p $PWD/build-tools
          ln -sf "${pkgs.llzk-llvmPackages.llvm}/bin/FileCheck" $PWD/build-tools/FileCheck
          ln -sf "${pkgs.llzk}/bin/llzk-opt" $PWD/build-tools/llzk-opt
          export PATH="$PWD/build-tools:$PATH"
        '';

        setupWritableNoirHome = ''
          export HOME="$TMPDIR/home"
          export XDG_CACHE_HOME="$TMPDIR/xdg-cache"
          mkdir -p "$HOME" "$HOME/nargo" "$XDG_CACHE_HOME"
        '';

        noirCli = pkgs.rustPlatform.buildRustPackage {
          pname = "nargo";
          version = "1.0.0-beta.19";
          src = noir-src;
          GIT_COMMIT = "74d6be658e1ad252f87943292ba09bdd4da80bd4";
          GIT_DIRTY = "false";

          nativeBuildInputs = [ pkgs.git ];

          cargoLock = {
            lockFile = noir-src + "/Cargo.lock";
            allowBuiltinFetchGit = true;
          };

          cargoBuildFlags = [
            "-p"
            "nargo_cli"
            "--bin"
            "nargo"
          ];

          doCheck = false;

          installPhase = ''
            runHook preInstall
            nargo_bin="$(find target -path '*/release/nargo' -type f | head -n 1)"
            install -Dm755 "$nargo_bin" $out/bin/nargo
            runHook postInstall
          '';
        };
      in
      {
        packages = flake-utils.lib.flattenTree {
          noir-cli = noirCli;
          default = pkgs.rustPlatform.buildRustPackage (
            {
              pname = "noir-to-llzk";
              version = "0.1.0";
              src = projectSrc;

              nativeBuildInputs = pkgs.llzkSharedEnvironment.nativeBuildInputs ++ [
                noirCli
              ];
              buildInputs = pkgs.llzkSharedEnvironment.devBuildInputs;
              cargoLock = {
                lockFile = projectSrc + "/Cargo.lock";
                allowBuiltinFetchGit = true;
              };
              preBuild = createFileCheckSymlink;
              preCheck = ''
                ${createFileCheckSymlink}
                ${setupWritableNoirHome}
                echo "Using $(command -v nargo) during nix build checks"
                nargo --version
              '';
            }
            // pkgs.llzkSharedEnvironment.env
            // pkgs.llzkSharedEnvironment.pkgSettings
          );
        };

        devShells = flake-utils.lib.flattenTree {
          default = pkgs.mkShell (
            {
              nativeBuildInputs = pkgs.llzkSharedEnvironment.nativeBuildInputs;
              buildInputs = pkgs.llzkSharedEnvironment.devBuildInputs ++ [
                noirCli
                pkgs.rust-bin.stable.latest.default
              ];

              shellHook = ''
                ## Bail out of pipes where any command fails
                set -uo pipefail
                ${createFileCheckSymlink}
                ${setupWritableNoirHome}
                export PATH="${noirCli}/bin:$PATH"
                echo "Welcome to the noir-to-llzk devshell!"
                echo "Using $(command -v nargo)"
                nargo --version
              '';
            }
            // pkgs.llzkSharedEnvironment.env
            // pkgs.llzkSharedEnvironment.devSettings
          );
        };
      }
    );
}
