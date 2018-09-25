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
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//

import Foundation

/// Encode modes.
public enum StringEncodeMode {

    /// Hexadecimal.
    case hex

    // TODO: Base64 encode
    /// Base64.
    case base64

}

extension String {

    /// Encode to hexadecimal string.
    ///
    /// - Returns: Encoded string.
    func hexEncode() -> String {
        let source = self.cString(using: .utf8) ?? []
        var hexString = String()
        for index in 0 ..< source.count {
            hexString = hexString.appendingFormat("%02x", source[index])
        }
        return hexString
    }

    /// Decode string with desire encode mode.
    ///
    /// - Parameter encodeMode: Mode for encode.
    /// - Returns: Bytes array.
    func decode(encodeMode: StringEncodeMode = .hex) -> [UInt8] {
        switch encodeMode {
        case .hex: return self.hexDecode()
        default: return []
        }
    }

    /// Decode to bytes array.
    ///
    /// - Returns: Decoded bytes array.
    func hexDecode() -> [UInt8] {
        var start = startIndex
        return (0...count/2).compactMap {  _ in
            let end = index(start, offsetBy: 2, limitedBy: endIndex) ?? endIndex
            defer { start = end }
            return UInt8(String(self[start..<end]), radix: 16)
        }
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
