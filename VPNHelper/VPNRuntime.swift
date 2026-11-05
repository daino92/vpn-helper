import CryptoKit
import Foundation

nonisolated struct VPNRuntime {
    enum Source: String {
        case bundled
        case system
    }

    let source: Source
    let openconnect: URL
    let vpnSlice: URL
    let versions: [String: String]
    let certificateBundle: URL?

    var logDescription: String {
        switch source {
        case .bundled:
            return "Using bundled VPN runtime: OpenConnect \(versions["openconnect"] ?? "unknown"), vpn-slice \(versions["vpn-slice"] ?? "unknown")."
        case .system:
            return "Using system VPN runtime: \(openconnect.path), \(vpnSlice.path)."
        }
    }

    var certificateArguments: [String] {
        guard let certificateBundle else { return [] }
        return ["--no-system-trust", "--cafile", certificateBundle.path]
    }

    func environment(from inherited: [String: String]) -> [String: String] {
        guard source == .bundled else { return inherited }
        var result = inherited
        result["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin"
        for key in result.keys.filter({ $0.hasPrefix("DYLD_") || $0 == "PYTHONPATH" || $0 == "PYTHONHOME" }) {
            result.removeValue(forKey: key)
        }
        return result
    }

    var splitTunnelScript: String {
        let quoted = "'" + vpnSlice.path.replacingOccurrences(of: "'", with: "'\\''") + "'"
        return "\(quoted) --domains-vpn-dns=ote.gr,cosmote.gr,azure.com 10.0.0.0/8"
    }
}

nonisolated struct VPNRuntimeResolver {
    let bundledDirectory: URL
    let systemPrefixes: [URL]
    private let fileManager = FileManager.default

    init(
        bundledDirectory: URL = Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/VPNRuntime"),
        systemPrefixes: [URL] = [URL(fileURLWithPath: "/opt/homebrew"), URL(fileURLWithPath: "/usr/local")]
    ) {
        self.bundledDirectory = bundledDirectory
        self.systemPrefixes = systemPrefixes
    }

    func resolve() throws -> VPNRuntime {
        let rootLink = try? fileManager.destinationOfSymbolicLink(atPath: bundledDirectory.path)
        if rootLink != nil {
            throw RuntimeError("The bundled VPN runtime directory must not be a symbolic link.")
        }
        if fileManager.fileExists(atPath: bundledDirectory.path) {
            // A damaged bundled runtime is an error, not permission to silently
            // execute a different system version with administrator privileges.
            return try resolveBundled()
        }
        for prefix in systemPrefixes {
            let openconnect = prefix.appendingPathComponent("bin/openconnect")
            let vpnSlice = prefix.appendingPathComponent("bin/vpn-slice")
            if fileManager.isExecutableFile(atPath: openconnect.path),
               fileManager.isExecutableFile(atPath: vpnSlice.path) {
                return VPNRuntime(source: .system, openconnect: openconnect, vpnSlice: vpnSlice, versions: [:], certificateBundle: nil)
            }
        }
        throw RuntimeError("No complete VPN runtime was found. Use a build with the bundled tools, or install both openconnect and vpn-slice in the same Homebrew prefix.")
    }

    private func resolveBundled() throws -> VPNRuntime {
        do {
            let manifestURL = try containedURL("manifest.json")
            let manifest = try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: manifestURL))
            guard manifest.format == "vpnhelper-runtime", manifest.schemaVersion == 1,
                  manifest.architecture == Self.architecture else {
                throw RuntimeError("The bundled VPN runtime is incompatible with this app's architecture.")
            }
            let executables = ["bin/openconnect", "bin/vpn-slice/vpn-slice"]
            guard (executables + ["share/ca-certificates.pem"]).allSatisfy({ manifest.files[$0] != nil }) else {
                throw RuntimeError("The bundled VPN runtime is incomplete.")
            }
            for (relativePath, expectedHash) in manifest.files {
                let url = try containedURL(relativePath)
                let data = try Data(contentsOf: url, options: .mappedIfSafe)
                let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
                guard hash == expectedHash else {
                    throw RuntimeError("The bundled VPN runtime failed its integrity check: \(relativePath).")
                }
            }
            for (relativePath, target) in manifest.symlinks ?? [:] {
                let url = try containedURL(relativePath)
                guard try fileManager.destinationOfSymbolicLink(atPath: url.path) == target else {
                    throw RuntimeError("The bundled VPN runtime contains a modified symbolic link.")
                }
            }
            let openconnect = try containedURL(executables[0])
            let vpnSlice = try containedURL(executables[1])
            guard fileManager.isExecutableFile(atPath: openconnect.path),
                  fileManager.isExecutableFile(atPath: vpnSlice.path) else {
                throw RuntimeError("The bundled VPN tools are not executable.")
            }
            return VPNRuntime(source: .bundled, openconnect: openconnect, vpnSlice: vpnSlice, versions: manifest.versions, certificateBundle: try containedURL("share/ca-certificates.pem"))
        } catch let error as RuntimeError {
            throw error
        } catch {
            throw RuntimeError("The bundled VPN runtime could not be loaded. Rebuild or reinstall the app. \(error.localizedDescription)")
        }
    }

    private func containedURL(_ relativePath: String) throws -> URL {
        guard !relativePath.hasPrefix("/"),
              !relativePath.split(separator: "/").contains(".."),
              !relativePath.contains("\0") else {
            throw RuntimeError("The bundled VPN runtime contains an invalid path.")
        }
        let root = bundledDirectory.resolvingSymlinksInPath().standardizedFileURL
        let url = root.appendingPathComponent(relativePath).standardizedFileURL
        let resolved = url.resolvingSymlinksInPath()
        guard resolved.path.hasPrefix(root.path + "/") else {
            throw RuntimeError("The bundled VPN runtime contains a path outside its bundle.")
        }
        return url
    }

    static var architecture: String {
        #if arch(arm64)
        "arm64"
        #elseif arch(x86_64)
        "x86_64"
        #else
        "unsupported"
        #endif
    }

    private struct Manifest: Decodable {
        let format: String
        let schemaVersion: Int
        let architecture: String
        let versions: [String: String]
        let files: [String: String]
        let symlinks: [String: String]?
    }

    struct RuntimeError: LocalizedError {
        let message: String
        init(_ message: String) { self.message = message }
        var errorDescription: String? { message }
    }
}
