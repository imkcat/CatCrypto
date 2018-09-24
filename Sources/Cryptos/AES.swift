//
//  AES.swift
//  CatCrypto
//
//  Created by Kcat on 2018/1/9.
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
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//

import Foundation
import CommonCryptoFramework

public struct CatAESContext {

    public init() {}

}

public class CatAESCrypto: Contextual, Encryption, Decryption {

    // MARK: - Contextual
    public typealias Context = CatAESContext

    public var context: CatAESContext

    public required init(context: CatAESContext = CatAESContext()) {
        self.context = context
    }

    // MARK: - Encryption
    public func encrypt(password: String) -> CatCryptoResult {
        return CatCryptoResult()
    }

    // MARK: - Decryption
    public func decrypt(encryptedPassword: String, encodeMode: StringEncodeMode) -> CatCryptoResult {
        return CatCryptoResult()
    }

}
