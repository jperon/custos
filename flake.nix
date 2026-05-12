{
  description = "Flake pour un projet LuaJIT + MoonScript";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.luajit
            pkgs.luajitPackages.moonscript
            pkgs.luajitPackages.luarocks
            pkgs.git
            pkgs.make
          ];

          shellHook = ''
            if ! luarocks show moor > /dev/null 2>&1; then
              echo "Installation du rock moor via luarocks..."
              luarocks install moor
            fi
            echo "Environnement prêt pour custos !"
          '';
        };
      }
    );
}
