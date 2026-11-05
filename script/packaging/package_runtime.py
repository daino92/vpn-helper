#!/usr/bin/env python3
"""Import copies of local tools into a relocatable, locally signed VPN runtime.

Homebrew is a read-only source. All install_name_tool/codesign operations target
new regular files in a temporary staging directory, never the original paths.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
SYSTEM_PREFIXES = ("/usr/lib/", "/System/Library/")


def run(arguments, **options):
    return subprocess.run([str(argument) for argument in arguments], check=True, text=True, **options)


def capture(arguments):
    return run(arguments, stdout=subprocess.PIPE).stdout.strip()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def is_macho(path):
    with path.open("rb") as stream:
        return stream.read(4) in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")


def dependencies(path):
    lines = capture(["/usr/bin/otool", "-L", path]).splitlines()[1:]
    return [line.strip().split(" (compatibility", 1)[0] for line in lines if line.startswith("\t")]


def resolve_dependency(reference, loader, executable):
    if reference.startswith(SYSTEM_PREFIXES):
        return None
    if reference.startswith("@loader_path/"):
        candidate = loader.parent / reference[len("@loader_path/"):]
    elif reference.startswith("@executable_path/"):
        candidate = executable.parent / reference[len("@executable_path/"):]
    elif reference.startswith("@rpath/"):
        raise RuntimeError(f"Unsupported source rpath {reference} in {loader}; use a rebuilt/relocated input instead of guessing a search path.")
    else:
        candidate = Path(reference)
    if not candidate.is_absolute() or not candidate.is_file():
        raise RuntimeError(f"Unresolved dependency {reference} in {loader}")
    return candidate.resolve()


def import_openconnect(source, destination, source_hashes):
    mapping = {source: destination / "bin/openconnect"}
    queue = [source]
    references = {}
    while queue:
        current = queue.pop()
        source_hashes[current] = digest(current)
        references[current] = {}
        for reference in dependencies(current):
            dependency = resolve_dependency(reference, current, source)
            if dependency is None:
                continue
            references[current][reference] = dependency
            if dependency == current:
                continue
            if dependency not in mapping:
                target = destination / "lib" / dependency.name
                if target in mapping.values():
                    raise RuntimeError(f"Library name collision: {dependency.name}")
                mapping[dependency] = target
                queue.append(dependency)
    for original, copied in mapping.items():
        copied.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, copied, follow_symlinks=True)
        copied.chmod(0o755)
        removed = subprocess.run(["/usr/bin/codesign", "--remove-signature", str(copied)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if removed.returncode and "not signed at all" not in removed.stderr:
            raise RuntimeError(removed.stderr)
    for original, copied in mapping.items():
        arguments = ["/usr/bin/install_name_tool"]
        if copied.suffix == ".dylib":
            arguments += ["-id", "@loader_path/" + copied.name]
        for reference, dependency in references[original].items():
            if dependency == original:
                continue
            relative = os.path.relpath(mapping[dependency], copied.parent)
            arguments += ["-change", reference, "@loader_path/" + relative]
        if len(arguments) > 1:
            run(arguments + [copied])
    return mapping


def build_vpn_slice(destination, work):
    work.mkdir(parents=True)
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYINSTALLER_CONFIG_DIR"] = str(work / "cache")
    run([
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir",
        "--name", "vpn-slice", "--distpath", work / "dist", "--workpath", work / "work",
        "--specpath", work, "--collect-submodules", "vpn_slice", "--collect-submodules", "dns",
        "--hidden-import", "setproctitle", "--copy-metadata", "vpn-slice",
        "--copy-metadata", "dnspython", "--copy-metadata", "setproctitle", HERE / "vpn_slice_entry.py"
    ], env=environment, cwd=work)
    shutil.copytree(work / "dist/vpn-slice", destination / "bin/vpn-slice", symlinks=True)


def formula_root(path):
    parts = path.resolve().parts
    if "Cellar" in parts:
        index = parts.index("Cellar")
        return Path(*parts[:index + 3])
    return None


def collect_notices(destination, sources):
    notices = destination / "licenses"
    components = []
    roots = {root for source in sources if (root := formula_root(source)) is not None}
    python_root = formula_root(Path(sys.base_prefix))
    if python_root:
        roots.add(python_root)
    for root in sorted(roots):
        name = root.parent.name + "-" + root.name
        components.append({"component": root.parent.name, "version": root.name})
        for candidate in root.rglob("*"):
            if candidate.is_file() and re.match(r"^(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE)([._-].*)?$", candidate.name, re.I):
                relative = candidate.relative_to(root)
                target = notices / name / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(candidate, target)
    for name in ("vpn-slice", "dnspython", "setproctitle", "pyinstaller"):
        distribution = importlib.metadata.distribution(name)
        components.append({"component": name, "version": distribution.version})
        for relative in distribution.files or []:
            if re.match(r"^(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE)([._-].*)?$", Path(relative).name, re.I):
                source = Path(distribution.locate_file(relative))
                if source.is_file():
                    resource = Path(relative)
                    if resource.is_absolute() or ".." in resource.parts:
                        resource = Path("external") / hashlib.sha256(str(relative).encode()).hexdigest()[:12] / resource.name
                    target = notices / (name + "-" + distribution.version) / resource
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
    (destination / "components.json").write_text(json.dumps(components, indent=2) + "\n")
    (destination / "DISTRIBUTION-NOTES.txt").write_text(
        "Local packaging prototype, not a distribution-compliance certificate.\n"
        "Before redistribution, supply corresponding source/build materials and fulfill the licenses of every component, including LGPL/GPL dependencies.\n"
        "components.json and licenses/ inventory the imported components.\n"
    )


def verify_and_sign(destination, identity):
    files = [path for path in destination.rglob("*") if path.is_file() and not path.is_symlink()]
    for path in files:
        if not is_macho(path):
            continue
        for reference in dependencies(path):
            if reference.startswith(SYSTEM_PREFIXES):
                continue
            if not reference.startswith("@loader_path/") and not reference.startswith("@executable_path/") and not reference.startswith("@rpath/"):
                raise RuntimeError(f"Non-relocated library dependency in {path}: {reference}")
            if reference.startswith("@loader_path/"):
                resolved = (path.parent / reference[len("@loader_path/"):]).resolve()
                if not resolved.is_relative_to(destination.resolve()) or not resolved.is_file():
                    raise RuntimeError(f"Missing or escaping dependency in {path}: {reference}")
    # PyInstaller has already relocated/signed its own runtime. Sign the native
    # OpenConnect copies after their load commands have been rewritten.
    for path in sorted((destination / "lib").glob("*.dylib")) + [destination / "bin/openconnect"]:
        run(["/usr/bin/codesign", "--force", "--sign", identity, "--timestamp=none", path])
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"}
    openconnect = run([destination / "bin/openconnect", "--version"], env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
    vpn_slice = run([destination / "bin/vpn-slice/vpn-slice", "--version"], env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
    if "fortinet" not in openconnect.lower() or "0.16.1" not in vpn_slice:
        raise RuntimeError("Bundled tool version/protocol checks failed.")
    return {"openconnect": openconnect.splitlines()[0].removeprefix("OpenConnect version "), "vpn-slice": importlib.metadata.version("vpn-slice"), "python": platform.python_version()}


def write_manifest(destination, versions):
    files, symlinks = {}, {}
    for path in sorted(destination.rglob("*")):
        relative = path.relative_to(destination).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            if Path(target).is_absolute() or not path.resolve().is_relative_to(destination.resolve()) or not path.resolve().exists():
                raise RuntimeError(f"Non-relocatable symbolic link: {path} -> {target}")
            symlinks[relative] = target
        elif path.is_file():
            files[relative] = digest(path)
    manifest = {"format": "vpnhelper-runtime", "schemaVersion": 1, "architecture": platform.machine(), "versions": versions, "files": files, "symlinks": symlinks}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--openconnect", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ca-bundle", type=Path, required=True)
    args = parser.parse_args()
    source = args.openconnect.resolve(strict=True)
    ca_bundle = args.ca_bundle.resolve(strict=True)
    output = args.output.resolve()
    if source.is_relative_to(output) or ca_bundle.is_relative_to(output) or str(output).startswith(("/opt/homebrew", "/usr/local", "/Applications")):
        raise RuntimeError("Output must be a separate build directory, not a system/application installation.")
    if output.exists():
        try:
            previous = json.loads((output / "manifest.json").read_text())
        except (OSError, ValueError):
            raise RuntimeError("Refusing to replace a directory that is not a generated runtime.") from None
        if previous.get("format") != "vpnhelper-runtime" or previous.get("schemaVersion") != 1:
            raise RuntimeError("Refusing to replace an unrelated directory/manifest.")
    # Lock versions before creating an artifact. The script never runs pip.
    for line in (HERE / "requirements.txt").read_text().splitlines():
        if line and not line.startswith("#"):
            name, version = line.split("==")
            if importlib.metadata.version(name) != version:
                raise RuntimeError(f"Install the pinned packaging requirements in a dedicated venv: {name}=={version}")
    output.parent.mkdir(parents=True, exist_ok=True)
    source_hashes = {}
    with tempfile.TemporaryDirectory(prefix="vpn-runtime-stage-", dir=output.parent) as temporary:
        work = Path(temporary)
        runtime = work / "vpn-runtime"
        runtime.mkdir()
        mapping = import_openconnect(source, runtime, source_hashes)
        source_hashes[ca_bundle] = digest(ca_bundle)
        (runtime / "share").mkdir()
        shutil.copyfile(ca_bundle, runtime / "share/ca-certificates.pem")
        build_vpn_slice(runtime, work / "python-build")
        collect_notices(runtime, list(mapping) + [ca_bundle])
        versions = verify_and_sign(runtime, "-")
        write_manifest(runtime, versions)
        for original, original_hash in source_hashes.items():
            if digest(original) != original_hash:
                raise RuntimeError(f"Source changed during packaging: {original}")
        if output.exists():
            shutil.rmtree(output)
        shutil.move(runtime, output)
    print(json.dumps({"output": str(output), "versions": versions, "unchanged_native_sources": len(source_hashes)}, indent=2))


if __name__ == "__main__":
    main()
