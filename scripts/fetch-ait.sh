#!/usr/bin/env bash
# Download the AIT Alert Data Set (CC-BY-4.0) into track1/data/.
# That directory is gitignored. Do not commit ait_ads.zip (96 MB) or the extracted JSON.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/data"
ZIP="$DEST/ait_ads.zip"
URL="https://zenodo.org/records/8263181/files/ait_ads.zip?download=1"
LABELS_URL="https://zenodo.org/records/8263181/files/labels.csv?download=1"
EXPECTED_MD5="43db6b1f0996e0024befd617706c50e9"

mkdir -p "$DEST"

checksum() {
  if command -v md5 >/dev/null 2>&1; then
    md5 -q "$1"
  elif command -v md5sum >/dev/null 2>&1; then
    md5sum "$1" | awk '{print $1}'
  else
    echo ""
  fi
}

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "fetch-ait.sh needs $1 on PATH" >&2
    exit 1
  fi
}
need curl
need unzip

if [ ! -f "$ZIP" ] || [ "$(checksum "$ZIP")" != "$EXPECTED_MD5" ]; then
  echo "Downloading AIT-ADS from Zenodo (about 96 MB)…"
  curl -L --fail --retry 3 -o "$ZIP.partial" "$URL"
  mv "$ZIP.partial" "$ZIP"
fi

got="$(checksum "$ZIP")"
if [ -n "$got" ] && [ "$got" != "$EXPECTED_MD5" ]; then
  echo "Checksum mismatch for ait_ads.zip (got $got, expected $EXPECTED_MD5)" >&2
  exit 1
fi

unzip -n "$ZIP" -d "$DEST/extract"
mkdir -p "$DEST/ait_ads"
find "$DEST/extract" -type f \( -name '*_wazuh.json' -o -name '*_aminer.json' \) -exec cp -n {} "$DEST/ait_ads/" \;
curl -L --fail --retry 3 -o "$DEST/labels.csv" "$LABELS_URL"
echo "AIT-ADS is in $DEST (gitignored)."
echo "Curated demo samples stay in track1/samples/ and do not need this download."
