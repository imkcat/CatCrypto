//
//  Crypto.swift
//  CatCrypto
//
//  Created by Kcat on 2017/12/28.
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

/// Function mode from CommonCrypto.
enum CatCCHashMode {
    
    /// MD2 function.
    case ccMD2
    
    /// MD4 function.
    case ccMD4
    
    /// MD5 function.
    case ccMD5
    
    /// SHA1 function.
    case ccSHA1
    
    /// SHA2 with 224 bit hash length.
    case ccSHA224
    
    /// SHA2 with 256 bit hash length.
    case ccSHA256
    
    /// SHA2 with 384 bit hash length.
    case ccSHA384
    
    /// SHA2 with 512 bit hash length.
    case ccSHA512
}

/// `CatCCHashCrypto` just for code convenient and coupling, and it just as
/// father class for hash function crypto class depend on `CommonCrypto`.
public class CatCCHashCrypto: Hashing {
    
    /// Mode to switch function from CommonCrypto.
    var mode: CatCCHashMode = .ccMD5 {
        didSet {
            switch mode {
            case .ccMD2:
                digestLength = Int(CC_MD2_DIGEST_LENGTH)
            case .ccMD4:
                digestLength = Int(CC_MD4_DIGEST_LENGTH)
            case .ccMD5:
                digestLength = Int(CC_MD5_DIGEST_LENGTH)
            case .ccSHA1:
                digestLength = Int(CC_SHA1_DIGEST_LENGTH)
            case .ccSHA224:
                digestLength = Int(CC_SHA224_DIGEST_LENGTH)
            case .ccSHA256:
                digestLength = Int(CC_SHA256_DIGEST_LENGTH)
            case .ccSHA384:
                digestLength = Int(CC_SHA384_DIGEST_LENGTH)
            case .ccSHA512:
                digestLength = Int(CC_SHA512_DIGEST_LENGTH)
            }
        }
    }
    
    /// Digest length in bytes to hash function.
    private(set) var digestLength: Int = Int(CC_MD5_DIGEST_LENGTH)
    
    /// Initialize the crypto.
    init() {}
    
    public func hash(password: String) -> CatCryptoHashResult {
        return commonCryptoHash(mode: mode,
                                password: password.cString(using: .utf8)!,
                                passwordLength: CC_LONG(password.lengthOfBytes(using: .utf8)),
                                digestLength: digestLength)
    }
    
    /// Hash password string with desire hash function from `CommonCrypto`.
    ///
    /// - Parameters:
    ///   - mode: Function mode.
    ///   - password: Password data to hasing.
    ///   - passwordLength: Password size in bytes.
    ///   - digestLength: Digest length in bytes.
    /// - Returns: Return a hash result when hashing task finish.
    func commonCryptoHash(mode: CatCCHashMode,
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
        case .ccSHA1:
            CC_SHA1(password, passwordLength, result)
        case .ccSHA224:
            CC_SHA224(password, passwordLength, result)
        case .ccSHA256:
            CC_SHA256(password, passwordLength, result)
        case .ccSHA384:
            CC_SHA384(password, passwordLength, result)
        case .ccSHA512:
            CC_SHA512(password, passwordLength, result)
        }
        let hashResult = CatCryptoHashResult()
        hashResult.value = String.hexString(source: result, length: digestLength)
        return hashResult
    }
    
}
