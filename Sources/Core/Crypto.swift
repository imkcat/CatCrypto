//
//  Crypto.swift
//  CatCrypto
//
//  Created by Kcat on 2017/12/28.
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

enum CatCCCryptoErrorCode: Int, EnumDescription {

    case success
    case fail
    case paramError
    case bufferTooSmall
    case memoryFailure
    case alignmentError
    case decodeError
    case unimplemented
    case overflow
    case rngFailure
    case unspecifiedError
    case callSequenceError
    case keySizeError

    var description: String? {
        switch self {
        case .success: return nil
        case .fail: return "Fail"
        case .paramError: return "Illegal parameter value"
        case .bufferTooSmall: return "Insufficent buffer provided for specified operation"
        case .memoryFailure: return "Memory allocation failure"
        case .alignmentError: return "Input size was not aligned properly"
        case .decodeError: return "Input data did not decode or decrypt properly"
        case .unimplemented: return "Function not implemented for the current algorithm"
        case .overflow: return "Overflow"
        case .rngFailure: return "RNG failure"
        case .unspecifiedError: return "Unspecified error"
        case .callSequenceError: return "Call sequence error"
        case .keySizeError: return "Key size error"
        }
    }

    init(errorCode value: Int) {
        switch value {
        case kCCSuccess: self = .success
        case kCCParamError: self = .paramError
        case kCCBufferTooSmall: self = .bufferTooSmall
        case kCCMemoryFailure: self = .memoryFailure
        case kCCAlignmentError: self = .alignmentError
        case kCCDecodeError: self = .decodeError
        case kCCUnimplemented: self = .unimplemented
        case kCCOverflow: self = .overflow
        case kCCRNGFailure: self = .rngFailure
        case kCCUnspecifiedError: self = .unspecifiedError
        case kCCCallSequenceError: self = .callSequenceError
        case kCCKeySizeError: self = .keySizeError
        default: self = .fail
        }
    }

}

/// Operation for CommonCrypto.
enum CatCCOperation {

    case encrypt
    case decrypt

    var ccValue: CCOperation {
        switch self {
        case .encrypt: return CCOperation(kCCEncrypt)
        case .decrypt: return CCOperation(kCCDecrypt)
        }
    }

}

/// Hashing function algorithm from CommonCrypto.
enum CatCCHashingAlgorithm {

    /// MD2 function.
    case md2

    /// MD4 function.
    case md4

    /// MD5 function.
    case md5

    /// SHA1 function.
    case sha1

    /// SHA2 with 224 bit hash length.
    case sha224

    /// SHA2 with 256 bit hash length.
    case sha256

    /// SHA2 with 384 bit hash length.
    case sha384

    /// SHA2 with 512 bit hash length.
    case sha512

}

/// `CatCCHashingCrypto` just for code convenient and coupling, and it just as super class for hash function crypto class depend on `CommonCrypto`.
public class CatCCHashingCrypto: Hashing {

    /// Algorithm to switch function for CommonCrypto.
    var algorithm: CatCCHashingAlgorithm = .md5 {
        didSet {
            switch algorithm {
            case .md2: digestLength = Int(CC_MD2_DIGEST_LENGTH)
            case .md4: digestLength = Int(CC_MD4_DIGEST_LENGTH)
            case .md5: digestLength = Int(CC_MD5_DIGEST_LENGTH)
            case .sha1: digestLength = Int(CC_SHA1_DIGEST_LENGTH)
            case .sha224: digestLength = Int(CC_SHA224_DIGEST_LENGTH)
            case .sha256: digestLength = Int(CC_SHA256_DIGEST_LENGTH)
            case .sha384: digestLength = Int(CC_SHA384_DIGEST_LENGTH)
            case .sha512: digestLength = Int(CC_SHA512_DIGEST_LENGTH)
            }
        }
    }

    /// Digest length in bytes to hash function.
    private(set) var digestLength: Int = Int(CC_MD5_DIGEST_LENGTH)

    /// Initialize the crypto.
    init() {}

    /// Hash password string with desire hash function from `CommonCrypto`.
    ///
    /// - Parameter password: Password string to hasing.
    /// - Returns: Return a tuple that include error code and raw output.
    func commonCryptoHash(password: String) -> (errorCode: CatCCCryptoErrorCode, output: [UInt8]) {
        let passwordCString = password.cString(using: .utf8)
        let passwordLength = UInt32(password.lengthOfBytes(using: .utf8))
        var result: [UInt8] = Array(repeating: 0, count: digestLength)
        switch algorithm {
        case .md2: CC_MD2(passwordCString, passwordLength, &result)
        case .md4: CC_MD4(passwordCString, passwordLength, &result)
        case .md5: CC_MD5(passwordCString, passwordLength, &result)
        case .sha1: CC_SHA1(passwordCString, passwordLength, &result)
        case .sha224: CC_SHA224(passwordCString, passwordLength, &result)
        case .sha256: CC_SHA256(passwordCString, passwordLength, &result)
        case .sha384: CC_SHA384(passwordCString, passwordLength, &result)
        case .sha512: CC_SHA512(passwordCString, passwordLength, &result)
        }
        return (.success, result)
    }

    // MARK: - Hashing
    public func hash(password: String) -> CatCryptoResult {
        let result = commonCryptoHash(password: password)
        return CatCryptoResult(raw: result.output)
    }

}
