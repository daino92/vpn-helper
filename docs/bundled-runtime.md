# Bundled VPN runtime prototype

Branch: `feature/bundled-vpn-runtime`, based on `develop`. This work does not include or activate the privileged helper from the separate Touch ID branch.

## Runtime selection

- A packaged app always uses its bundled OpenConnect and vpn-slice together. It does not compare versions against Homebrew or select whichever is newest.
- Both authentication and tunnel creation keep the same selected runtime. The script path is shell-quoted, including when the app's location contains spaces or apostrophes.
- A present but damaged, incomplete or incompatible bundled runtime is an error. There is no silent fallback to an external executable.
- A plain developer build without a runtime uses a complete system pair from `/opt/homebrew` or `/usr/local`. It never combines tools from different prefixes.
- No app setting currently switches a packaged app to system mode. Such an option can be added explicitly if there is a real need.

Bundled subprocesses use a system-only PATH and remove inherited Python/DYLD overrides. Authentication and tunnel setup use the bundled Mozilla CA file with `--no-system-trust --cafile`; they do not depend on Homebrew's mutable certificate file. A private corporate CA would need an explicit trust configuration in a future change.

## Build locally

The current prototype imports a local OpenConnect executable and recursively copies its non-system dylibs. It rewrites only the copies' load commands to use bundle-relative paths. Source files are hashed before/after packaging to detect unexpected modifications. The installed vpn-slice is not used or modified: the same pinned version is installed in a separate build venv and frozen with PyInstaller in one-directory mode. Python is included in the artifact; end users do not need a Python or Homebrew installation.

Use a dedicated build venv. The following commands create files only under `.build`, apart from downloads and Xcode's normal build services:

```sh
python3 -m venv .build/packaging-venv
.build/packaging-venv/bin/python -m pip install --no-cache-dir -r script/packaging/requirements.txt
./script/build_bundled_app.sh
```

Build-time overrides:

- `VPNHELPER_PACKAGING_PYTHON`: the dedicated venv's Python executable.
- `VPNHELPER_OPENCONNECT_SOURCE`: local OpenConnect source binary, default `/opt/homebrew/bin/openconnect`.
- `VPNHELPER_CA_SOURCE`: unmodified factory CA bundle, default `/opt/homebrew/opt/ca-certificates/share/ca-certificates/cacert.pem`.

No `brew install`, upgrade, unlink, uninstall, `sudo`, signing-certificate installation, or changes to system tools are performed. Packaging dependencies are pinned in `script/packaging/requirements.txt`. No generated runtime binaries are committed to Git.

The result is `.build/artifacts/VPNHelper.app`. It is not installed in `/Applications` or launched automatically. The runtime is embedded under `Contents/Resources/VPNRuntime`, with native libraries, the frozen Python application, a CA bundle, an inventory and license notices. A manifest records versions, architecture, file hashes and internal symbolic links.

Ordinary Xcode builds omit the runtime. The packaging script copies the plain build into a separate `.build/artifacts/VPNHelper.app`, adds the runtime there, and re-signs the artifact after the copy. No Xcode script sandbox setting is weakened, and the normal build product is not modified. Recreating the artifact prevents leftover files from an older runtime.

## Verify without opening a VPN

```sh
.build/packaging-venv/bin/python -B script/packaging/verify_app.py \
  --app .build/artifacts/VPNHelper.app
```

Verification checks app/nested signatures, manifest hashes, native load commands, runtime versions with a system-only PATH, and relocation to a directory containing spaces and an apostrophe. It checks dynamic loader traces for Homebrew libraries when available. It does not authenticate to a VPN, invoke sudo, repair DNS, or alter routes. Unit tests cover pair selection, corruption, incompatible architecture and containment.

## Release limitations

This is a local, ad-hoc-signed, host-architecture prototype. It is not a notarized distributable release. Test on a clean Mac/VM without Homebrew before claiming full independence, and test a real connect/disconnect/OTP cycle separately. Importing existing bottles retains optional compile-time feature settings; a production pipeline should build a minimal pinned OpenConnect from verified sources and exercise the required Fortinet/TLS features.

`licenses/` and `components.json` inventory the imported packages. Before redistributing binaries, supply corresponding source/build materials and meet the licenses of OpenConnect, vpn-slice, Python and all dependencies. Notices alone do not satisfy every LGPL/GPL obligation. Upstream references:

- https://www.infradead.org/openconnect/licence.html
- https://github.com/dlenski/vpn-slice/blob/master/LICENSE.txt
- https://pyinstaller.org/en/stable/license.html

Bundle hashes detect corruption; they do not replace trusted code signing. A release needs proper nested signing and notarization as appropriate. Integrating this payload with the future root helper requires a separate signed, protected deployment design. This prototype does not relax that branch's security checks.
