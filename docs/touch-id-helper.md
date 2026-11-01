# Touch ID and privileged VPN operations

The checkpoint before this change is commit `818e3a8` on `main`. The implementation branch is `feature/touch-id-helper`.

## Connection flow

1. The app authenticates with the VPN server as the logged-in user and requests an OTP.
2. After the OTP succeeds, an enabled helper connection checks the toolchain and protocol version.
3. `LocalAuthentication.deviceOwnerAuthentication` asks for Touch ID or the Mac account password.
4. Only after authentication succeeds does the signed app request the root daemon to start the tunnel.
5. The helper receives the session cookie over XPC and sends it to openconnect through stdin. It never writes the cookie or a password to disk.

Cancelling authentication never falls through to privileged execution. Disconnecting an existing tunnel does not require another authentication prompt. Network repair requires fresh device-owner authentication.

If the helper is not enabled, the existing `sudo` / native password prompt remains available. An error or cancellation after selecting helper authentication does not silently switch to sudo. Use **Connection log → Diagnostics (…) → Use password authentication** to switch back while disconnected.

## Deployment prerequisites

The current local build is ad-hoc signed and cannot enable the helper. No launch daemon, PAM changes, sudoers changes, signing identity, or managed toolchain are installed by the tests or build.

To enable the helper:

- Use a Release build signed with an Apple Development or Developer ID certificate, a valid Team ID, Hardened Runtime and library validation. Debugger access, disabled library validation, injected DYLD variables and unsigned executable memory entitlements are refused.
- Install the app at `/Applications/VPNHelper.app`.
- Deploy a vetted, relocated toolchain at `/Library/PrivilegedHelperTools/com.dainocorp.VPNHelper.tools`. Every file and parent directory must be root-owned, without group/other write permissions. Symbolic links are refused.
- Provide standalone, hardened, signed `openconnect` and `vpn-slice` executables. Their signing identifiers must be `com.dainocorp.VPNHelper.openconnect` and `com.dainocorp.VPNHelper.vpn-slice`, signed by the app's Apple Developer team. The Python-based vpn-slice must be packaged as a standalone executable; copying its Homebrew launcher is insufficient. Relocate dependencies into the protected toolchain and sign embedded dynamic libraries with the same team so library validation remains enabled. Python resources must also live in the protected tree; user site packages are disabled.
- The existing user-owned Homebrew installation must remain unchanged. It is used only by the explicitly password-authorized legacy connection, never by the persistent daemon.
- While disconnected, choose **Set up Touch ID…** from Diagnostics. Approve the background helper in macOS System Settings if requested, then finish setup. This initial macOS approval may require an administrator password.

The Xcode embed phase copies the daemon plist into `Contents/Library/LaunchDaemons`. `SMAppService` runs the same signed app executable with `--privileged-helper`; this branch starts only the XPC listener, not SwiftUI, Keychain access, or the askpass UI.

## Trust boundary

Both sides pin XPC messages to the exact executable CDHash, bundle identifier and Apple Developer team. The same executable is used by the GUI and daemon. This excludes differently built debug apps from a signed release connection. The client also checks the daemon's root UID. The daemon accepts only the current console user when that user is an administrator.

The app is the trusted policy agent for device-owner authentication. The daemon does not accept an arbitrary client's boolean claim about Touch ID. It accepts only the pinned, hardened executable, whose start/repair paths require LocalAuthentication. The daemon independently validates operation parameters, restricts the server and DNS override, and exposes no general shell execution or caller-selected executable path.

The daemon owns its Process object and records the owning XPC session. It never reads a caller-writable PID file. A disconnected client triggers cleanup of its tunnel. SIGINT is followed by timed SIGTERM/SIGKILL if required. XPC replies are bounded and resume continuations once; a timeout invalidates the connection so a late tunnel start cannot remain attached to an unresponsive client.

Re-run setup after changing the signed executable. The exact-build pin intentionally rejects an older running daemon. Setup checks readiness first and re-registers an outdated daemon. It is unavailable during an active connection.

## Validation and limits

Unit tests cover session/server/fingerprint restrictions, ad-hoc/debug signing rejection, and the guarantee that cancelled authentication does not execute its privileged operation. Builds verify the embedded daemon configuration.

A successful build or mocked authentication test does not verify physical Touch ID, SMAppService approval, root tunnel startup, or network cleanup. These require the signed app and protected toolchain above, and an interactive VPN session. The installed working application is not replaced by this experimental branch.
