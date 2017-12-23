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

/// CatMD2Crypto is the crypto for [MD2](https://tools.ietf.org/html/rfc1319)
/// function.
public class CatMD2Crypto: Hashing {
    public init() {}
    
    public func hash(password: String) -> CatCryptoHashResult {
        let passwordCString = password.cString(using: .utf8)
        let passwordLength = password.lengthOfBytes(using: .utf8)
        var digestLength = Int(CC_MD2_DIGEST_LENGTH)
        var result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLength)
        defer {
            result.deallocate(capacity: digestLength)
        }
        var hashString = String()
        CC_MD2(passwordCString, CUnsignedInt(passwordLength), result)
        for index in 0 ..< digestLength {
            hashString = hashString.appendingFormat("%02x", result[index])
        }
        let hashResult = CatCryptoHashResult()
        hashResult.value = hashString
        return hashResult
    }
}

/// CatMD4Crypto is the crypto for [MD4](https://tools.ietf.org/html/rfc1320)
/// function.
public class CatMD4Crypto: Hashing {
    public init() {}
    
    public func hash(password: String) -> CatCryptoHashResult {
        let passwordCString = password.cString(using: .utf8)
        let passwordLength = password.lengthOfBytes(using: .utf8)
        var digestLength = Int(CC_MD4_DIGEST_LENGTH)
        var result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLength)
        defer {
            result.deallocate(capacity: digestLength)
        }
        var hashString = String()
        CC_MD4(passwordCString, CUnsignedInt(passwordLength), result)
        for index in 0 ..< digestLength {
            hashString = hashString.appendingFormat("%02x", result[index])
        }
        let hashResult = CatCryptoHashResult()
        hashResult.value = hashString
        return hashResult
    }
}

/// CatMD5Crypto is the crypto for [MD5](https://tools.ietf.org/html/rfc1321)
/// function.
public class CatMD5Crypto: Hashing {
    public init() {}
    
    public func hash(password: String) -> CatCryptoHashResult {
        let passwordCString = password.cString(using: .utf8)
        let passwordLength = password.lengthOfBytes(using: .utf8)
        var digestLength = Int(CC_MD5_DIGEST_LENGTH)
        var result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLength)
        defer {
            result.deallocate(capacity: digestLength)
        }
        var hashString = String()
        CC_MD5(passwordCString, CUnsignedInt(passwordLength), result)
        for index in 0 ..< digestLength {
            hashString = hashString.appendingFormat("%02x", result[index])
        }
        let hashResult = CatCryptoHashResult()
        hashResult.value = hashString
        return hashResult
    }
}

/// Message digest length for MD6 function output.
let MD6_DIGEST_LENGTH = CInt(512)

/// CatMD6Crypto is the crypto for [MD6](http://groups.csail.mit.edu/cis/md6/)
/// function.
public class CatMD6Crypto: Hashing {
    public init() {}
    
    public func hash(password: String) -> CatCryptoHashResult {
        let passwordCString = password.cString(using: .utf8)
        let passwordLength = password.lengthOfBytes(using: .utf8)
        var digestLength = Int(MD6_DIGEST_LENGTH)
        var result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLength)
        defer {
            result.deallocate(capacity: digestLength)
        }
        var hashString = String()
        let data = UnsafeMutablePointer<CChar>(mutating: passwordCString)?.withMemoryRebound(to: CUnsignedChar.self, capacity: passwordLength, { point in
            return point
        })
        md6_hash(MD6_DIGEST_LENGTH, data, CUnsignedLongLong(passwordLength), result)
        for index in 0 ..< digestLength/8 {
            hashString = hashString.appendingFormat("%02x", result[index])
        }
        let hashResult = CatCryptoHashResult()
        hashResult.value = hashString
        return hashResult
    }
}
