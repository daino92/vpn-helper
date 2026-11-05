import CryptoKit
import Foundation
import Testing
@testable import VPNHelper

@MainActor
struct VPNRuntimeTests {
    @Test func bundledPairWinsOverExistingSystemTools() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        try fixture.makeSystemPair()
        try fixture.makeBundle()
        let selected = try fixture.resolver.resolve()
        #expect(selected.source == .bundled)
        #expect(selected.openconnect.path.hasPrefix(fixture.bundle.path))
        #expect(selected.vpnSlice.path.hasPrefix(fixture.bundle.path))
        #expect(selected.certificateArguments.contains("--no-system-trust"))
    }

    @Test func absentBundleUsesOneCompleteSystemPrefix() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        try fixture.makeSystemPair()
        let selected = try fixture.resolver.resolve()
        #expect(selected.source == .system)
        #expect(selected.openconnect.path == fixture.system.appendingPathComponent("bin/openconnect").path)
        #expect(selected.certificateBundle == nil)
    }

    @Test func incompleteBundleNeverFallsBackToSystem() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        try fixture.makeBundle()
        try fixture.makeSystemPair()
        try FileManager.default.removeItem(at: fixture.bundle.appendingPathComponent("bin/vpn-slice/vpn-slice"))
        #expect(throws: VPNRuntimeResolver.RuntimeError.self) { try fixture.resolver.resolve() }
    }

    @Test func modifiedBundledExecutableIsRejected() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        try fixture.makeBundle()
        try fixture.makeSystemPair()
        try Data("modified".utf8).write(to: fixture.bundle.appendingPathComponent("bin/openconnect"))
        #expect(throws: VPNRuntimeResolver.RuntimeError.self) { try fixture.resolver.resolve() }
    }

    @Test func twoIncompleteSystemPrefixesAreNotMixed() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        let other = fixture.root.appendingPathComponent("other-prefix")
        try fixture.writeExecutable(fixture.system.appendingPathComponent("bin/openconnect"))
        try fixture.writeExecutable(other.appendingPathComponent("bin/vpn-slice"))
        let resolver = VPNRuntimeResolver(bundledDirectory: fixture.bundle, systemPrefixes: [fixture.system, other])
        #expect(throws: VPNRuntimeResolver.RuntimeError.self) { try resolver.resolve() }
    }

    @Test func incompatibleArchitectureIsRejected() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        try fixture.makeBundle(architecture: "unsupported-test-architecture")
        #expect(throws: VPNRuntimeResolver.RuntimeError.self) { try fixture.resolver.resolve() }
    }

    @Test func symlinkEscapeAndUnsafeManifestPathsAreRejected() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        try fixture.makeBundle()
        let executable = fixture.bundle.appendingPathComponent("bin/openconnect")
        let external = fixture.root.appendingPathComponent("external")
        try fixture.writeExecutable(external)
        try FileManager.default.removeItem(at: executable)
        try FileManager.default.createSymbolicLink(at: executable, withDestinationURL: external)
        #expect(throws: VPNRuntimeResolver.RuntimeError.self) { try fixture.resolver.resolve() }
        try fixture.makeBundle(extraFiles: ["../external": "hash"])
        #expect(throws: VPNRuntimeResolver.RuntimeError.self) { try fixture.resolver.resolve() }
    }

    @Test func internalSymlinkWorksAndRuntimeRootSymlinkIsRejected() throws {
        let fixture = try Fixture()
        defer { fixture.remove() }
        try fixture.makeBundle()
        let alias = fixture.bundle.appendingPathComponent("share/alias.pem")
        try FileManager.default.createSymbolicLink(atPath: alias.path, withDestinationPath: "ca-certificates.pem")
        let manifestURL = fixture.bundle.appendingPathComponent("manifest.json")
        var manifest = try JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as! [String: Any]
        manifest["symlinks"] = ["share/alias.pem": "ca-certificates.pem"]
        try JSONSerialization.data(withJSONObject: manifest).write(to: manifestURL)
        #expect(try fixture.resolver.resolve().source == .bundled)
        let link = fixture.root.appendingPathComponent("linked-runtime")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: fixture.bundle)
        let resolver = VPNRuntimeResolver(bundledDirectory: link, systemPrefixes: [fixture.system])
        #expect(throws: VPNRuntimeResolver.RuntimeError.self) { try resolver.resolve() }
    }

    @Test func bundledEnvironmentAndScriptPathsAreIsolated() {
        let runtime = VPNRuntime(source: .bundled, openconnect: URL(fileURLWithPath: "/App/bin/openconnect"), vpnSlice: URL(fileURLWithPath: "/My App's Folder/vpn-slice"), versions: [:], certificateBundle: nil)
        let environment = runtime.environment(from: ["PATH": "/opt/homebrew/bin", "DYLD_LIBRARY_PATH": "/opt/homebrew/lib", "PYTHONPATH": "/tmp/custom", "TERM": "xterm"])
        #expect(environment["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin")
        #expect(environment["DYLD_LIBRARY_PATH"] == nil)
        #expect(environment["PYTHONPATH"] == nil)
        #expect(environment["TERM"] == "xterm")
        #expect(runtime.splitTunnelScript.hasPrefix("'/My App'\\''s Folder/vpn-slice' "))
    }

    private struct Fixture {
        let root: URL
        var bundle: URL { root.appendingPathComponent("BundledRuntime") }
        var system: URL { root.appendingPathComponent("system-prefix") }
        var resolver: VPNRuntimeResolver { VPNRuntimeResolver(bundledDirectory: bundle, systemPrefixes: [system]) }

        init() throws {
            root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("vpn-runtime-tests-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        }

        func remove() { try? FileManager.default.removeItem(at: root) }

        func writeExecutable(_ url: URL) throws {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data("#!/bin/sh\nexit 0\n".utf8).write(to: url)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        }

        func makeSystemPair() throws {
            try writeExecutable(system.appendingPathComponent("bin/openconnect"))
            try writeExecutable(system.appendingPathComponent("bin/vpn-slice"))
        }

        func makeBundle(architecture: String = VPNRuntimeResolver.architecture, extraFiles: [String: String] = [:]) throws {
            if FileManager.default.fileExists(atPath: bundle.path) { try FileManager.default.removeItem(at: bundle) }
            var files = extraFiles
            for relative in ["bin/openconnect", "bin/vpn-slice/vpn-slice", "share/ca-certificates.pem"] {
                let url = bundle.appendingPathComponent(relative)
                try writeExecutable(url)
                files[relative] = SHA256.hash(data: try Data(contentsOf: url)).map { String(format: "%02x", $0) }.joined()
            }
            let manifest: [String: Any] = ["format": "vpnhelper-runtime", "schemaVersion": 1, "architecture": architecture, "versions": ["openconnect": "test", "vpn-slice": "test"], "files": files, "symlinks": [:]]
            try JSONSerialization.data(withJSONObject: manifest).write(to: bundle.appendingPathComponent("manifest.json"))
        }
    }
}
