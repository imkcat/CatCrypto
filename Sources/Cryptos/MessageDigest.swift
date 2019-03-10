//
//  MessageDigest.swift
//  CatCrypto
//
//  Created by Kcat on 2017/12/22.
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
import CommonCrypto
import MD6

enum MD6ErrorCode: Int32, EnumDescription {

    case success = 0
    case fail = 1
    case badHashLength = 2
    case nullState = 3
    case badKeyLength = 4
    case stateNotInitialize = 5
    case stackUnderFlow = 6
    case stackOverFlow = 7
    case nullData = 8
    case nullN = 9
    case nullB = 10
    case badEll = 11
    case badP = 12
    case nullK = 13
    case nullQ = 14
    case nullC = 15
    case badL = 16
    case badR = 17
    case outOfMemory = 18

    var description: String? {

        switch self {
        case .success: return nil
        case .fail: return "Fail"
        case .badHashLength: return "Hashbitlen<1 or >512 bits"
        case .nullState: return "Null state passed to MD6"
        case .badKeyLength: return "Key length is <0 or >512 bits"
        case .stateNotInitialize: return "State was never initialized"
        case .stackUnderFlow: return "MD6 stack underflows (shouldn't happen)"
        case .stackOverFlow: return "MD6 stack overflow (message too long)"
        case .nullData: return "Null data pointer"
        case .nullN: return "Compress: N is null"
        case .nullB: return "Standard compress: null B pointer"
        case .badEll: return "Standard compress: ell not in {0,255}"
        case .badP: return "Standard compress: p<0 or p>b*w"
        case .nullK: return "Standard compress: K is null"
        case .nullQ: return "Standard compress: Q is null"
        case .nullC: return "Standard compress: C is null"
        case .badL: return "Standard compress: L <0 or > 255"
        case .badR: return "Compress: r<0 or r>255"
        case .outOfMemory: return "Compress: storage allocation failed"
        }

    }

}

/// `CatMD2Crypto` is the crypto for [MD2](https://tools.ietf.org/html/rfc1319) function.
public class CatMD2Crypto: CatCCHashingCrypto {

    public override init() {
        super.init()
        algorithm = .md2
    }

}

/// `CatMD4Crypto` is the crypto for [MD4](https://tools.ietf.org/html/rfc1320) function.
public class CatMD4Crypto: CatCCHashingCrypto {

    public override init() {
        super.init()
        algorithm = .md4
    }

}

/// `CatMD5Crypto` is the crypto for [MD5](https://tools.ietf.org/html/rfc1321) function.
public class CatMD5Crypto: CatCCHashingCrypto {

    public override init() {
        super.init()
        algorithm = .md5
    }

}

/// Desired bit-length of the hash function output.
public enum CatMD6HashLength: Int {

    /// 224 bits.
    case bit224 = 28

    /// 256 bits.
    case bit256 = 32

    /// 384 bits.
    case bit384 = 48

    /// 512 bits.
    case bit512 = 64

}

/// Context for MD6 crypto.
public class CatMD6Context {

    /// Desired bit-length of the hash function output.
    public var hashLength: CatMD6HashLength = .bit512

    /// Initialize the context.
    public init() {}

}

/// `CatMD6Crypto` is the crypto for [MD6](http://groups.csail.mit.edu/cis/md6/) function.
public class CatMD6Crypto: Contextual, Hashing {

    // MARK: - Contextual
    public typealias Context = CatMD6Context

    public var context: CatMD6Context

    public required init(context: Context = CatMD6Context()) {
        self.context = context
    }

    // MARK: - Core
    /// Hash with MD6 function.
    ///
    /// - Parameter password: Password string.
    /// - Returns: Return a tuple that include error code and raw output.
    func md6Hash(password: String) -> (errorCode: MD6ErrorCode, output: [UInt8]) {
        let passwordLength = password.lengthOfBytes(using: .utf8)
        var result: [UInt8] = Array(repeating: 0, count: self.context.hashLength.rawValue)
        var data: [UInt8] = [UInt8](password.utf8)
        let rawErrorCode = md6_hash(Int32(self.context.hashLength.rawValue * 8), &data,
                                    UInt64(passwordLength), &result)
        let errorCode = MD6ErrorCode(rawValue: rawErrorCode) ?? MD6ErrorCode.fail
        return (errorCode, result)
    }

    // MARK: - Hashing
    public func hash(password: String) -> CatCryptoResult {
        let result = md6Hash(password: password)
        switch result.errorCode {
        case .success:
            return CatCryptoResult(raw: result.output)
        default:
            return CatCryptoResult(error: CatCryptoError(errorCode: Int(result.errorCode.rawValue), errorDescription: result.errorCode.description))
        }
    }

}
