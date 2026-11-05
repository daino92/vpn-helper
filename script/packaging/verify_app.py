#!/usr/bin/env python3
"""Offline smoke tests. No VPN login, sudo, DNS or route modification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile


def run(arguments, **kwargs):
    return subprocess.run([str(item) for item in arguments], check=True, text=True, **kwargs)


def check_files(runtime):
    manifest = json.loads((runtime / "manifest.json").read_text())
    root = runtime.resolve()
    for relative, expected in manifest["files"].items():
        path = runtime / relative
        if not path.resolve().is_relative_to(root):
            raise RuntimeError(f"Escaping runtime file: {relative}")
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            raise RuntimeError(f"Runtime integrity failure: {relative}")
    for relative, target in manifest.get("symlinks", {}).items():
        path = runtime / relative
        if os.readlink(path) != target or not path.resolve().is_relative_to(root):
            raise RuntimeError(f"Runtime symlink failure: {relative}")
    return manifest


def macho_files(runtime):
    for path in runtime.rglob("*"):
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as stream:
                if stream.read(4) in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
                    yield path


def check_load_commands(runtime):
    count = 0
    for path in macho_files(runtime):
        libraries = run(["/usr/bin/otool", "-L", path], stdout=subprocess.PIPE).stdout
        for line in libraries.splitlines()[1:]:
            reference = line.strip().split(" (compatibility", 1)[0]
            if reference.startswith(("/opt/homebrew/", "/usr/local/")):
                raise RuntimeError(f"External Homebrew dependency: {path}: {reference}")
        commands = run(["/usr/bin/otool", "-l", path], stdout=subprocess.PIPE).stdout
        for block in commands.split("Load command ")[1:]:
            if re.search(r"\bcmd LC_RPATH\b", block):
                match = re.search(r"\bpath (.+) \(offset", block)
                if match and match.group(1).startswith(("/opt/homebrew/", "/usr/local/")):
                    raise RuntimeError(f"External Homebrew rpath: {path}: {match.group(1)}")
        count += 1
    return count


def smoke(runtime):
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "DYLD_PRINT_LIBRARIES": "1"}
    versions = {}
    for name, relative in (("openconnect", "bin/openconnect"), ("vpn-slice", "bin/vpn-slice/vpn-slice")):
        result = run([runtime / relative, "--version"], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        loaded = [line for line in result.stderr.splitlines() if line.startswith("dyld[")]
        if any("/opt/homebrew/" in line or "/usr/local/" in line for line in loaded):
            raise RuntimeError(f"{name} loaded a Homebrew library.")
        versions[name] = result.stdout.splitlines()[0]
    command = shlex.quote(str(runtime / "bin/vpn-slice/vpn-slice")) + " --version"
    run(["/bin/sh", "-c", command], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    return versions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=Path, required=True)
    args = parser.parse_args()
    app = args.app.resolve(strict=True)
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app])
    runtime = app / "Contents/Resources/VPNRuntime"
    manifest = check_files(runtime)
    count = check_load_commands(runtime)
    versions = smoke(runtime)
    with tempfile.TemporaryDirectory(prefix="VPN runtime's relocation test ") as temporary:
        moved = Path(temporary) / "VPN Helper's Copy.app"
        shutil.copytree(app, moved, symlinks=True)
        run(["/usr/bin/codesign", "--verify", "--deep", "--strict", moved])
        moved_runtime = moved / "Contents/Resources/VPNRuntime"
        check_files(moved_runtime)
        smoke(moved_runtime)
    print(json.dumps({"app": str(app), "versions": versions, "manifest_architecture": manifest["architecture"], "native_files_checked": count, "relocation_with_spaces_and_apostrophe": "passed", "system_vpn_tools_invoked": False}, indent=2))


if __name__ == "__main__":
    main()
