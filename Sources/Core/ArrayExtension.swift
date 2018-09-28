//
//  ArrayExtension.swift
//  CatCrypto
//
//  Created by Kcat on 2018/1/18.
//  Copyright © 2018年 imkcat. All rights reserved.
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
public enum EncodeMode {

    /// Hexadecimal.
    case hex

    /// Base64.
    case base64

}

extension Array {

    /// Encode bytes with desire mode.
    ///
    /// - Parameter encodeMode: Mode for encode.
    /// - Returns: Encoded string.
    func encode(encodeMode: EncodeMode = .hex) -> String {
        if self is [UInt8] {
            switch encodeMode {
            case .hex: return self.hexEncode()
            case .base64: return self.base64Encode()
            }
        }
        return ""
    }

    /// Encode to hexadecimal string.
    ///
    /// - Returns: Encoded string.
    func hexEncode() -> String {
        var hexString = String()
        for element in self {
            hexString = hexString.appendingFormat("%02x", (element as? UInt8)!)
        }
        return hexString
    }

    /// Encode to base64 string.
    ///
    /// - Returns: Encoded string.
    func base64Encode() -> String {
        let base64Data = Data(bytes: self, count: self.count)
        return base64Data.base64EncodedString()
    }

}
