{
  description = "Flake pour un projet LuaJIT + MoonScript";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
  flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ (self: super: {
          wolfssl = super.stdenv.mkDerivation {
            pname = "wolfssl";
            version = "5.6.6";
            src = super.fetchurl {
              url = "https://github.com/wolfSSL/wolfssl/archive/v5.6.6-stable.tar.gz";
              sha256 = "sha256-PSymctQcLC+mZ4hagNb6A8PpHw9Pcvh67yvJR+jIcjc=";
            };
            nativeBuildInputs = [ super.autoreconfHook super.pkg-config ];
            # certgen/keygen/certext/ecc + ALT_NAMES sont requis par px5g
            # (génération de clés et certificats auto-signés avec SAN).
            configureFlags = [
              "--enable-shared"
              "--enable-static"
              "--enable-keygen"
              "--enable-certgen"
              "--enable-certreq"
              "--enable-certext"
              "--enable-ecc"
              "--enable-opensslextra"
            ];
            CFLAGS = "-DWOLFSSL_ALT_NAMES -DFP_MAX_BITS=8192";
          };

          # px5g-wolfssl : générateur de clés/certificats X.509 (OpenWrt).
          # Binaire nommé `px5g` (PROVIDES:=px5g dans le paquet OpenWrt).
          px5g = super.stdenv.mkDerivation {
            pname = "px5g-wolfssl";
            # Épinglé sur un commit précis (et non refs/heads/main) pour la
            # reproductibilité : le contenu ne bougera pas sous nos pieds.
            version = "openwrt-6aad5ab";
            src = super.fetchurl {
              url = "https://github.com/openwrt/openwrt/raw/6aad5ab0992fefd88ce612bc0484e0115a004572/package/utils/px5g-wolfssl/px5g-wolfssl.c";
              sha256 = "sha256-KXeb029kv008dEfsJcQJdJY7s/ndZCHvKjMycTO/kyI=";
            };
            dontUnpack = true;
            buildInputs = [ self.wolfssl ];
            buildPhase = ''
              $CC -DWOLFSSL_ALT_NAMES -o px5g "$src" -lwolfssl
            '';
            installPhase = ''
              install -Dm755 px5g "$out/bin/px5g"
            '';
          };
        }) ];
      };

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
          pkgs.libnetfilter_queue
          pkgs.nftables
          pkgs.wolfssl
          pkgs.px5g
          pkgs.mbedtls
          pkgs.openssl
          pkgs.xxhash
          
          # Dépendances pour Copilot/Bash
          pkgs.bash
          pkgs.glibc
          pkgs.pkg-config
        ];

        shellHook = ''
          export LD_LIBRARY_PATH="${pkgs.xxhash}/lib:${pkgs.libnetfilter_queue}/lib:${pkgs.nftables}/lib:${pkgs.wolfssl}/lib:$LD_LIBRARY_PATH"
          
          # FHS pour Copilot et autres outils qui cherchent bash au chemin standard
          export BASH_PATH="${pkgs.bash}/bin/bash"
          export PATH="${pkgs.bash}/bin:$PATH"
          
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
