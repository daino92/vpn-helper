#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGING_PYTHON="${VPNHELPER_PACKAGING_PYTHON:-$ROOT_DIR/.build/packaging-venv/bin/python}"
NATIVE_OPENCONNECT="${VPNHELPER_OPENCONNECT_SOURCE:-/opt/homebrew/bin/openconnect}"
CA_BUNDLE="${VPNHELPER_CA_SOURCE:-/opt/homebrew/opt/ca-certificates/share/ca-certificates/cacert.pem}"
RUNTIME_DIR="$ROOT_DIR/.build/vpn-runtime"
DERIVED_DIR="$ROOT_DIR/.build/bundled-derived-data"
if [[ ! -x "$PACKAGING_PYTHON" ]]; then
    echo "Create a dedicated packaging venv and install script/packaging/requirements.txt first (see docs/bundled-runtime.md)." >&2
    exit 1
fi
"$PACKAGING_PYTHON" -B "$ROOT_DIR/script/packaging/package_runtime.py" --openconnect "$NATIVE_OPENCONNECT" --ca-bundle "$CA_BUNDLE" --output "$RUNTIME_DIR"
xcodebuild -project "$ROOT_DIR/VPNHelper.xcodeproj" -scheme VPNHelper -configuration Release -destination 'platform=macOS' -derivedDataPath "$DERIVED_DIR" build
BUILD_PRODUCT="$DERIVED_DIR/Build/Products/Release/VPNHelper.app"
ARTIFACT_DIR="$ROOT_DIR/.build/artifacts"
APP_BUNDLE="$ARTIFACT_DIR/VPNHelper.app"
mkdir -p "$ARTIFACT_DIR"
# Finalize a separate artifact, never the normal Xcode build product or an
# installed app. Recreating this known output avoids stale runtime files.
rm -rf "$APP_BUNDLE"
/usr/bin/ditto "$BUILD_PRODUCT" "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/Resources"
/usr/bin/ditto "$RUNTIME_DIR" "$APP_BUNDLE/Contents/Resources/VPNRuntime"
/usr/bin/codesign --force --sign - --timestamp=none --preserve-metadata=entitlements,flags,runtime "$APP_BUNDLE"
/usr/bin/codesign --verify --deep --strict "$APP_BUNDLE"
echo "Built: $APP_BUNDLE"
