#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${TMPDIR:-/tmp}/VPNHelper-derived-data"
MODE="${1:-run}"
case "$MODE" in run|--debug|--logs|--telemetry|--verify) ;; *) echo "Usage: $0 [--debug|--logs|--telemetry|--verify]" >&2; exit 2 ;; esac
pkill -x VPNHelper >/dev/null 2>&1 || true
xcodebuild -project "$ROOT_DIR/VPNHelper.xcodeproj" -scheme VPNHelper -configuration Debug -destination 'platform=macOS' -derivedDataPath "$BUILD_DIR" build
APP_BUNDLE="$BUILD_DIR/Build/Products/Debug/VPNHelper.app"
if [[ "$MODE" == --debug ]]; then
    exec lldb -- "$APP_BUNDLE/Contents/MacOS/VPNHelper"
fi
/usr/bin/open -n "$APP_BUNDLE"
case "$MODE" in
    --logs) exec /usr/bin/log stream --info --style compact --predicate 'process == "VPNHelper"' ;;
    --telemetry) exec /usr/bin/log stream --info --style compact --predicate 'subsystem == "com.dainocorp.VPNHelper"' ;;
    --verify) sleep 1; pgrep -x VPNHelper >/dev/null ;;
esac
