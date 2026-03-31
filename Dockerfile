# CustosVirginum DNS Filter — Docker image
# Multi-stage build to keep final image minimal

# Build stage: compile MoonScript → Lua
FROM alpine:3.19 AS builder

# Install build dependencies
RUN apk add --no-cache \
    moonscript=1.2.4-r4 \
    luajit=2.1.1713483783-r0 \
    make=4.4.1-r2 \
    gcc=13.2.1_git20240309-r0 \
    musl-dev=1.2.5-r1

# Install runtime dependencies (for tests)
RUN apk add --no-cache \
    libndpi-dev=4.2-2.1-r2 \
    libnetfilter_queue-dev=1.0.5-r1 \
    libnftnl-dev=1.2.6-r0 \
    libmnl-dev=1.0.5-r2

WORKDIR /app

# Copy source
COPY . .

# Compile MoonScript to Lua
RUN make clean && make

# Runtime stage: minimal image
FROM alpine:3.19 AS runtime

# Install only runtime dependencies
RUN apk add --no-cache \
    luajit=2.1.1713483783-r0 \
    libndpi=4.2-2.1-r2 \
    libnetfilter_queue=1.0.5-r1 \
    libnftnl=1.2.6-r0 \
    libmnl=1.0.5-r2 \
    nftables=1.0.9-r1 \
    iproute2=6.6.0-r1

# Create app user
RUN adduser -D -s /bin/sh custos

WORKDIR /app

# Copy compiled Lua files and resources
COPY --from=builder /app/lua ./lua
COPY --from=builder /app/nft-rules ./nft-rules
COPY --from=builder /app/setup.sh ./

# Set permissions
RUN chown -R custos:custos /app

USER custos

# Expose that we need privileged mode for NFQUEUE
LABEL description="CustosVirginum DNS Filter with nDPI integration"
LABEL version="1.0"
LABEL license="MIT"

ENTRYPOINT ["/app/setup.sh"]
