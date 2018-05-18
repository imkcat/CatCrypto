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

    /// Process a hex string from an unsigned char array point.
    ///
    /// - Parameters:
    ///   - source: Unsigned char array point to process.
    ///   - length: Array length.
    /// - Returns: Desired hex string.
    static func hexString(source: UnsafeMutablePointer<CUnsignedChar>, length: Int) -> String {
        var hexString = String()
        for index in 0 ..< length {
            hexString = hexString.appendingFormat("%02x", source[index])
        }
        return hexString
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
