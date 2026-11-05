import SwiftUI

/// One native editor preserves paste, selection, keyboard navigation and autofill.
/// The six boxes are a visual representation of the same bound code.
struct OTPCodeField: View {
    @Binding var code: String
    var onSubmit: () -> Void
    @FocusState private var isFocused: Bool

    var body: some View {
        TextField("", text: $code)
            .textFieldStyle(.plain)
            .textContentType(.oneTimeCode)
            .foregroundStyle(.clear)
            .tint(.clear)
            .focused($isFocused)
            .frame(height: 44)
            .overlay {
                HStack(spacing: 8) {
                    ForEach(0..<6) { index in
                        let active = isFocused && index == min(code.count, 5)
                        Text(digit(at: index))
                            .font(.system(size: 18, weight: .medium, design: .monospaced))
                            .foregroundStyle(.primary)
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                            .background(.background, in: RoundedRectangle(cornerRadius: 8))
                            .overlay {
                                RoundedRectangle(cornerRadius: 8)
                                    .strokeBorder(active ? AppTheme.magenta : Color.secondary.opacity(0.3), lineWidth: active ? 2 : 1)
                            }
                    }
                }
                .allowsHitTesting(false)
                .accessibilityHidden(true)
            }
            .accessibilityLabel("6-digit one-time code")
            .accessibilityHint("Type or paste the code sent to your phone.")
            .onChange(of: code) { _, value in
                let sanitized = OTPInput.sanitize(value)
                if value != sanitized { code = sanitized }
            }
            .onSubmit(onSubmit)
            .onAppear { isFocused = true }
    }

    private func digit(at index: Int) -> String {
        let digits = Array(code)
        return index < digits.count ? String(digits[index]) : ""
    }

}

nonisolated enum OTPInput {
    static func sanitize(_ value: String) -> String {
        String(value.filter { $0.isASCII && $0.isNumber }.prefix(6))
    }
}
