import SwiftUI

/// Centralized appearance tokens. TeleNeo can replace the system family here
/// once licensed desktop font files are available for embedding.
enum AppTheme {
    static let magenta = Color("AccentColor")
    static let title = Font.system(size: 24, weight: .bold)
    static let headline = Font.system(size: 13, weight: .semibold)
    static let body = Font.system(size: 13)
    static let callout = Font.system(size: 12)
    static let caption = Font.system(size: 11)
}
