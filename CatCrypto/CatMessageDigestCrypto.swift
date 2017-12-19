//
//  CatMessageDigestCrypto.swift
//  CatCrypto
//
//  Created by Kcat on 2017/12/17.
//  Copyright © 2017年 imkcat. All rights reserved.
//
// https://github.com/ImKcat/CatCrypto
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

import Foundation
import CommonCrypto

/// CatMessageDigestContextMode has three mode to use: MD2, MD4, and MD5. MD5 is recommend
///
/// - MD2: The MD2 Message-Digest algorithm
/// - MD4: The MD4 Message-Digest algorithm
/// - MD5: The MD5 Message-Digest algorithm
public enum CatMessageDigestContextMode: Int {
    case MD2 = 0
    case MD4 = 1
    case MD5 = 2
}

/// CatMessageDigestContext is the context and it descript what you want to hash with Message-Digest function
public class CatMessageDigestContext {
    /// The mode of Message-Digest function
    public var mode: CatMessageDigestContextMode = .MD5
    
    public init(mode: CatMessageDigestContextMode = .MD5) {
        self.mode = mode
    }
}

/// CatMessageDigestCrypto is the crypto for Message-Digest function
public class CatMessageDigestCrypto: CatAsymmetricCrypto {
    /// Context for the crypto
    public var context: CatMessageDigestContext = CatMessageDigestContext()
    
    public init(context: CatMessageDigestContext = CatMessageDigestContext()) {
        self.context = context
    }
    
    override public func hash(password: String, completeHandler: ((CatCryptoHashResult) -> Void)?) {
        let passwordCString = password.cString(using: .utf8)
        let passwordLength = password.lengthOfBytes(using: .utf8)
        var digestLength: Int
        var md: UnsafeMutablePointer<CUnsignedChar>
        defer {
            md.deallocate(capacity: digestLength)
        }
        var hashString = String()
        switch context.mode {
        case .MD2:
            digestLength = Int(CC_MD2_DIGEST_LENGTH)
            md = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLength)
            CC_MD2(passwordCString, CUnsignedInt(passwordLength), md)
            for index in 0 ..< digestLength {
                hashString = hashString.appendingFormat("%02x", md[index])
            }
        case .MD4:
            digestLength = Int(CC_MD4_DIGEST_LENGTH)
            md = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLength)
            CC_MD4(passwordCString, CUnsignedInt(passwordLength), md)
            for index in 0 ..< digestLength {
                hashString = hashString.appendingFormat("%02x", md[index])
            }
        case .MD5:
            digestLength = Int(CC_MD5_DIGEST_LENGTH)
            md = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLength)
            CC_MD5(passwordCString, CUnsignedInt(passwordLength), md)
            for index in 0 ..< digestLength {
                hashString = hashString.appendingFormat("%02x", md[index])
            }
        }
        if completeHandler != nil {
            let hashResult = CatCryptoHashResult()
            hashResult.value = hashString
            completeHandler!(hashResult)
        }
    }
    
    public override func verify(hash: String, password: String, completeHandler: ((CatCryptoVerifyResult) -> Void)?) {
        let passwordCString = password.cString(using: .utf8)
        let passwordLength = password.lengthOfBytes(using: .utf8)
        var digestLength: Int
        var md: UnsafeMutablePointer<CUnsignedChar>
        defer {
            md.deallocate(capacity: digestLength)
        }
        var hashString = String()
        switch context.mode {
        case .MD2:
            digestLength = Int(CC_MD2_DIGEST_LENGTH)
            md = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLength)
            CC_MD2(passwordCString, CUnsignedInt(passwordLength), md)
            for index in 0 ..< digestLength {
                hashString = hashString.appendingFormat("%02x", md[index])
            }
        case .MD4:
            digestLength = Int(CC_MD4_DIGEST_LENGTH)
            md = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLength)
            CC_MD4(passwordCString, CUnsignedInt(passwordLength), md)
            for index in 0 ..< digestLength {
                hashString = hashString.appendingFormat("%02x", md[index])
            }
        case .MD5:
            digestLength = Int(CC_MD5_DIGEST_LENGTH)
            md = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLength)
            CC_MD5(passwordCString, CUnsignedInt(passwordLength), md)
            for index in 0 ..< digestLength {
                hashString = hashString.appendingFormat("%02x", md[index])
            }
        }
        if completeHandler != nil {
            let verifyResult = CatCryptoVerifyResult()
            verifyResult.value = hashString == hash ? true : false
            completeHandler!(verifyResult)
        }
    }
}
