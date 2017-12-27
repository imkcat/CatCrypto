//
//  MessageDigest.swift
//  CatCrypto
//
//  Created by Kcat on 2017/12/22.
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
import MD6

/// Message-Digest function mode from CommonCrypto.
private enum CCMessageDigestMode {
    
    /// MD2 function.
    case ccMD2
    
    /// MD4 function.
    case ccMD4
    
    /// MD5 function.
    case ccMD5
}

/// `CatCCMessageDigestCrypto` just for code convenient and coupling, and it just
/// as father class for `CatMD2Crypto`, `CatMD4Crypto` and `CatMD5Crypto`
/// classes.
public class CatCCMessageDigestCrypto {
    
    public init() {}
    
    /// Hash password string with desire Message-Digest function.
    ///
    /// - Parameters:
    ///   - mode: Function mode.
    ///   - password: Password data to hasing.
    ///   - passwordLength: Password size in bytes.
    ///   - digestLength: Digest length in bytes.
    /// - Returns: Return a hash result when hashing task finish.
    fileprivate func messageDigestHash(mode: CCMessageDigestMode,
                                       password: [CChar],
                                       passwordLength: CC_LONG,
                                       digestLength: Int) -> CatCryptoHashResult {
        var result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLength)
        defer {
            result.deallocate(capacity: digestLength)
        }
        switch mode {
        case .ccMD2:
            CC_MD2(password, passwordLength, result)
        case .ccMD4:
            CC_MD4(password, passwordLength, result)
        case .ccMD5:
            CC_MD5(password, passwordLength, result)
        }
        let hashResult = CatCryptoHashResult()
        hashResult.value = String.hexString(source: result, length: digestLength)
        return hashResult
    }
    
}

/// CatMD2Crypto is the crypto for [MD2](https://tools.ietf.org/html/rfc1319)
/// function.
public class CatMD2Crypto: CatCCMessageDigestCrypto, Hashing {
    
    public func hash(password: String) -> CatCryptoHashResult {
        return messageDigestHash(mode: .ccMD2,
                                 password: password.cString(using: .utf8)!,
                                 passwordLength: CC_LONG(password.lengthOfBytes(using: .utf8)),
                                 digestLength: Int(CC_MD2_DIGEST_LENGTH))
    }
    
}

/// CatMD4Crypto is the crypto for [MD4](https://tools.ietf.org/html/rfc1320)
/// function.
public class CatMD4Crypto: CatCCMessageDigestCrypto, Hashing {
    
    public func hash(password: String) -> CatCryptoHashResult {
        return messageDigestHash(mode: .ccMD4,
                                 password: password.cString(using: .utf8)!,
                                 passwordLength: CC_LONG(password.lengthOfBytes(using: .utf8)),
                                 digestLength: Int(CC_MD4_DIGEST_LENGTH))
    }
    
}

/// CatMD5Crypto is the crypto for [MD5](https://tools.ietf.org/html/rfc1321)
/// function.
public class CatMD5Crypto: CatCCMessageDigestCrypto, Hashing {
    
    public func hash(password: String) -> CatCryptoHashResult {
        return messageDigestHash(mode: .ccMD5,
                                 password: password.cString(using: .utf8)!,
                                 passwordLength: CC_LONG(password.lengthOfBytes(using: .utf8)),
                                 digestLength: Int(CC_MD5_DIGEST_LENGTH))
    }
    
}

/// Desired bit-length of the hash function output.
public enum CatMD6HashLength: CInt {
    
    /// 224 bits.
    case bit224 = 224
    
    /// 256 bits.
    case bit256 = 256
    
    /// 384 bits.
    case bit384 = 384
    
    /// 512 bits.
    case bit512 = 512
}

public class CatMD6Context: CatCryptoContext {
    
    /// Desired bit-length of the hash function output.
    public var hashLength: CatMD6HashLength = .bit512

    public init(hashLength: CatMD6HashLength = .bit512) {
        self.hashLength = hashLength
    }
    
}

/// CatMD6Crypto is the crypto for [MD6](http://groups.csail.mit.edu/cis/md6/)
/// function.
public class CatMD6Crypto: Hashing {
    
    /// Context for the crypto.
    public var context: CatMD6Context = CatMD6Context()
    
    public init(context: CatMD6Context = CatMD6Context()) {
        self.context = context
    }
    
    public func hash(password: String) -> CatCryptoHashResult {
        let passwordLength = password.lengthOfBytes(using: .utf8)
        var result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: Int(self.context.hashLength.rawValue))
        defer {
            result.deallocate(capacity: Int(self.context.hashLength.rawValue))
        }
        let data = UnsafeMutablePointer<CChar>(mutating: password.cString(using: .utf8))?.withMemoryRebound(to: CUnsignedChar.self, capacity: passwordLength, { point in
            return point
        })
        md6_hash(self.context.hashLength.rawValue, data, CUnsignedLongLong(passwordLength), result)
        let hashResult = CatCryptoHashResult()
        hashResult.value = String.hexString(source: result, length: Int(self.context.hashLength.rawValue / 8))
        return hashResult
    }
    
}
