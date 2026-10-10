#!/bin/sh
# Package release tarballs for Linux amd64 and arm64
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

mkdir -p release-assets

for ARCH in amd64 arm64; do
    if [ ! -f "dist/${ARCH}/netrix" ]; then
        printf 'Error: dist/%s/netrix does not exist. Build binaries first.\n' "$ARCH" >&2
        exit 1
    fi

    PKG_DIR="pkg-${ARCH}/relay"
    rm -rf "pkg-${ARCH}"
    mkdir -p "${PKG_DIR}/scripts" "${PKG_DIR}/docs"

    cp "dist/${ARCH}/netrix" "${PKG_DIR}/netrix"
    cp -r scripts/* "${PKG_DIR}/scripts/"
    rm -f "${PKG_DIR}/scripts/package-release.sh"
    cp -r docs/* "${PKG_DIR}/docs/"
    if [ -d guides ]; then
        cp -r guides "${PKG_DIR}/"
    fi
    cp README.md LICENSE "${PKG_DIR}/"

    BIN_HASH=$(sha256sum "dist/${ARCH}/netrix" | awk '{print $1}')

    cat << EOF > "${PKG_DIR}/install.sh"
#!/bin/sh
# Offline installer for bundled relay core
set -eu
dir=\$(CDPATH= cd -- "\$(dirname -- "\$0")" && pwd)
exec python3 "\$dir/scripts/netrix-manager.py" install --binary "\$dir/netrix" --sha256 "${BIN_HASH}" "\$@"
EOF
    chmod +x "${PKG_DIR}/install.sh" "${PKG_DIR}/scripts/"* "${PKG_DIR}/netrix"

    tar -czf "release-assets/relay-linux-${ARCH}.tar.gz" -C "pkg-${ARCH}" relay
    printf '[✓] Packaged release-assets/relay-linux-%s.tar.gz\n' "$ARCH"
done

cd release-assets
sha256sum relay-linux-*.tar.gz > SHA256SUMS
printf '\n[SHA256 Manifest]\n'
cat SHA256SUMS
