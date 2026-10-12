#!/usr/bin/env bash
# Download the AIT Alert Data Set (AIT-ADS), CC-BY-4.0, into track1/data/ (gitignored).
# Source: https://zenodo.org/records/8263181
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="$here/data"
url="https://zenodo.org/records/8263181/files/ait_ads.zip?download=1"
md5_expected="43db6b1f0996e0024befd617706c50e9"
zip="$dest/ait_ads.zip"

mkdir -p "$dest"

if [ ! -f "$zip" ]; then
  echo "Downloading AIT-ADS from zenodo.org/records/8263181 ..."
  curl -fL --retry 3 -o "$zip.part" "$url"
  mv "$zip.part" "$zip"
fi

if command -v md5sum >/dev/null 2>&1; then
  md5_actual="$(md5sum "$zip" | awk '{print $1}')"
else
  md5_actual="$(md5 -q "$zip")"
fi

if [ "$md5_actual" != "$md5_expected" ]; then
  echo "Checksum mismatch: expected $md5_expected, got $md5_actual" >&2
  exit 1
fi

unzip -oq "$zip" -d "$dest"
echo "AIT-ADS ready in $dest"
