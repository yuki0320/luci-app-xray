#!/bin/sh

set -eu

BASE_URL="${XRAY_GEODATA_URL:-https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download}"
ASSET_DIR="/usr/share/xray"
TMP_DIR="$(mktemp -d /tmp/xray-geodata.XXXXXX)"

cleanup() {
	rm -rf "$TMP_DIR"
}

download_asset() {
	local name="$1"
	local url="${BASE_URL}/${name}"
	local target="${ASSET_DIR}/${name}"
	local tmp="${TMP_DIR}/${name}"

	echo "Downloading ${name} from ${url}"
	if ! wget -q -T 30 -O "$tmp" "$url"; then
		echo "Failed to download ${name}" >&2
		return 1
	fi

	if [ ! -s "$tmp" ]; then
		echo "Downloaded ${name} is empty" >&2
		return 1
	fi

	mkdir -p "$ASSET_DIR"
	cp "$tmp" "$target"
	chmod 0644 "$target"
	echo "Installed ${target}"
}

trap cleanup EXIT

download_asset geoip.dat
download_asset geosite.dat

if [ -x /etc/init.d/xray_core ]; then
	/etc/init.d/xray_core restart >/dev/null 2>&1 || true
fi

echo "GeoData updated from Loyalsoldier/v2ray-rules-dat."
