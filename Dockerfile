# CustosVirginum DNS Filter — Docker image for nDPI 4.x
# Multi-stage build to keep final image minimal
# Default: nDPI 4.2 on Debian bookworm

# Build stage: compile MoonScript → Lua
FROM debian:bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    luarocks \
    luajit \
    lua5.3 \
    lua5.3-dev \
    make \
    gcc \
    libndpi-dev \
    libnetfilter-queue-dev \
    libnftnl-dev \
    libmnl-dev \
    && luarocks install moonscript \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source
COPY . .

# Compile MoonScript to Lua
RUN make clean && make

# Runtime stage: minimal image
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    luajit \
    libndpi4.2 \
    libnetfilter-queue1 \
    libnftnl11 \
    libmnl0 \
    nftables \
    iproute2 \
    dnsmasq \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -s /bin/bash custos

WORKDIR /app

# Copy compiled Lua files and resources
COPY --from=builder /app/lua ./lua
COPY --from=builder /app/nft-rules ./nft-rules
COPY --from=builder /app/setup.sh ./

# Set permissions
RUN chown -R custos:custos /app && chmod +x /app/setup.sh

# USER custos

# Expose that we need privileged mode for NFQUEUE
LABEL description="CustosVirginum DNS Filter with nDPI 4.x"
LABEL version="1.0-ndpi4"
LABEL license="MIT"

ENTRYPOINT ["/app/setup.sh"]
