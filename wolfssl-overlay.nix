{ self: super: {
  wolfssl = super.stdenv.mkDerivation {
    pname = "wolfssl";
    version = "5.6.6";
    src = super.fetchurl {
      url = "https://www.wolfssl.com/download/wolfssl-5.6.6.tar.gz";
      # Replace with actual sha256 of the tarball
      sha256 = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    };
    nativeBuildInputs = [ super.pkg-config ];
    buildInputs = [ super.openssl ];
    configureFlags = [ "--disable-shared" "--enable-static" ];
    installPhase = ''
      mkdir -p $out/lib $out/include
      make install DESTDIR=$out PREFIX=""
    '';
  };
}}
