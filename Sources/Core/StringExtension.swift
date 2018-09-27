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

extension String {

    /// Decode string with desire mode.
    ///
    /// - Parameter encodeMode: Mode for Decode.
    /// - Returns: Bytes.
    func decode(encodeMode: EncodeMode = .hex) -> [UInt8] {
        switch encodeMode {
        case .hex: return self.hexDecode()
        case .base64: return self.base64Decode()
        }
    }

    /// Decode hexadecimal string to bytes.
    ///
    /// - Returns: Decoded bytes.
    func hexDecode() -> [UInt8] {
        var start = startIndex
        return (0...count/2).compactMap {  _ in
            let end = index(start, offsetBy: 2, limitedBy: endIndex) ?? endIndex
            defer { start = end }
            return UInt8(String(self[start..<end]), radix: 16)
        }
    }

    /// Decode base64 string to bytes.
    ///
    /// - Returns: Decoded bytes.
    func base64Decode() -> [UInt8] {
        let base64Data = Data(base64Encoded: self)
        let decodeString = String(data: base64Data ?? Data(), encoding: String.Encoding.utf8) ?? ""
        return [UInt8](decodeString.utf8)
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
