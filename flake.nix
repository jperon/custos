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
        luajit = pkgs.luajit.withPackages (ps: with ps; [
          argparse
          busted
          dkjson
          inspect
          lua-cjson
          luacheck
          luacov
          luafilesystem
          luaposix
          luarocks-nix
          luasec
          luasocket
          luautf8
          luaunit
          moonscript
          penlight
        ]);
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            luajit
            pkgs.git
            pkgs.gnumake
            pkgs.mbedtls
            pkgs.openssl
            pkgs.xxhash
          ];

          shellHook = ''
            export LD_LIBRARY_PATH="${pkgs.xxhash}/lib:$LD_LIBRARY_PATH"
            if ! luarocks show moor > /dev/null 2>&1; then
              echo "Installation du rock moor via luarocks..."
              luarocks install moor
            fi
            # Détecte les .lua compilés parasites dans src/ (ils ont un .moon correspondant).
            # La seule source de vérité est le .moon ; le .lua doit être dans lua/, pas src/.
            stale=$(find src/ -name "*.lua" ! -path "src/lib/*" 2>/dev/null \
              | while read f; do [ -f "''${f%.lua}.moon" ] && echo "$f"; done)
            if [ -n "$stale" ]; then
              echo "AVERTISSEMENT : .lua compilés parasites dans src/ — supprimer et recompiler via moonc :"
              echo "$stale"
            fi
            echo "Environnement prêt pour custos !"
          '';
        };
      }
    );
}
