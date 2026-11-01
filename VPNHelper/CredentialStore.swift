import Foundation
import Security

protocol CredentialStore {
    func load() throws -> SavedCredentials?
    func save(_ credentials: SavedCredentials) throws
    func delete() throws
}

struct SavedCredentials: Codable {
    let emailPrefix: String
    let password: String
}

struct KeychainCredentialStore: CredentialStore {
    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "com.dainocorp.VPNHelper.credentials",
         kSecAttrAccount as String: "vpn-login"]
    }

    func load() throws -> SavedCredentials? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try check(status)
        guard let data = result as? Data else { return nil }
        return try JSONDecoder().decode(SavedCredentials.self, from: data)
    }

    func save(_ credentials: SavedCredentials) throws {
        let data = try JSONEncoder().encode(credentials)
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            try check(SecItemAdd(item as CFDictionary, nil))
        } else {
            try check(status)
        }
    }

    func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecItemNotFound { try check(status) }
    }

    private func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status), userInfo: [
                NSLocalizedDescriptionKey: SecCopyErrorMessageString(status, nil) as String? ?? "Keychain operation failed."
            ])
        }
    }
}
