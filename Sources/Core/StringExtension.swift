//
//  StringExtension.swift
//  CatCrypto
//
//  Created by Kcat on 2017/12/25.
//  Copyright © 2017年 imkcat. All rights reserved.
//
// https://github.com/ImKcat/CatCrypto
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//

import Foundation

public enum StringEncodeMode {
    case hex
    case base64
}

extension String {

    /// Process a hex string.
    ///
    /// - Returns: Desired hex string.
    func hex() -> String {
        let source = self.cString(using: .utf8) ?? []
        var hexString = String()
        for index in 0 ..< source.count {
            hexString = hexString.appendingFormat("%02x", source[index])
        }
        return hexString
    }

    func raw(encodeMode: StringEncodeMode = .hex) -> String {
        switch encodeMode {
        case .hex: return self.rawFromHex()
        default: return ""
        }
    }

    func rawFromHex() -> String {
        let scalars = self.unicodeScalars
        var bytes = [UInt8](repeating: 0, count: (scalars.count + 1) >> 1)
        for (index, scalar) in scalars.enumerated() {
            var nibble = scalar.hexNibble
            if index & 1 == 0 {
                nibble <<= 4
            }
            bytes[index >> 1] |= nibble
        }
        return String(cString: bytes)
    }

    /// Generate an appoint length string fill by zero.
    ///
    /// - Parameter length: Zero count.
    /// - Returns: Desired zero string.
    static func zeroString(length: Int) -> String {
        var zeroString = String()
        for _ in 0 ..< length {
            zeroString += "0"
        }
        return zeroString
    }

}
