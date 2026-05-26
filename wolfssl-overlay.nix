{ self, super }: {
  wolfssl = super.stdenv.mkDerivation {
    pname = "wolfssl";
    version = "5.6.6";
    src = super.fetchurl {
      url = "https://github.com/wolfSSL/wolfssl/archive/v5.6.6-stable.tar.gz";
      sha256 = "sha256-PSymctQcLC+mZ4hagNb6A8PpHw9Pcvh67yvJR+jIcjc=";
    };
    nativeBuildInputs = [ super.autoreconfHook super.pkg-config ];
    configureFlags = [ "--disable-shared" "--enable-static" ];
    installPhase = ''
      mkdir -p $out/lib $out/include
      make install DESTDIR=$out PREFIX=""
    '';
  };
}
