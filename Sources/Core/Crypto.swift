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
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//

import Foundation
import CommonCryptoFramework

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

/// `CatCCHashingCrypto` just for code convenient and coupling, and it just as
/// father class for hash function crypto class depend on `CommonCrypto`.
public class CatCCHashingCrypto: Hashing {

    /// Algorithm to switch function from CommonCrypto.
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
    func commonCryptoHash(password: String) -> (errorCode: CatCCCryptoErrorCode, output: [CUnsignedChar]) {
        let passwordCString = password.cString(using: .utf8)
        let passwordLength = CC_LONG(password.lengthOfBytes(using: .utf8))
        var result: [CUnsignedChar] = Array(repeating: 0, count: digestLength)
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
        let cryptoResult = CatCryptoResult()
        cryptoResult.raw = result.output
        return cryptoResult
    }

}

/// Encryption algorithm mode from CommonCrypto.
enum CatCCEncryptionAlgorithm: Int {

    /// AES function.
    case aes

    /// DES function.
    case des

    /// 3DES function.
    case tdes

    /// RC2 function.
    case rc2

    /// RC4 function.
    case rc4

    /// CAST function.
    case cast

    /// Blowfish function.
    case blowfish

    var ccValue: CCAlgorithm {
        switch self {
        case .aes: return CCAlgorithm(kCCAlgorithmAES128)
        case .des: return CCAlgorithm(kCCAlgorithmDES)
        case .tdes: return CCAlgorithm(kCCAlgorithm3DES)
        case .rc2: return CCAlgorithm(kCCAlgorithmRC2)
        case .rc4: return CCAlgorithm(kCCAlgorithmRC4)
        case .cast: return CCAlgorithm(kCCAlgorithmCAST)
        case .blowfish: return CCAlgorithm(kCCAlgorithmBlowfish)
        }
    }

}

enum CatCCEncryptionMode {

    case ecb
    case cbc
    case cfb
    case cfb8
    case ctr
    case ofb
    case xts

    var ccValue: CCMode {
        switch self {
        case .ecb: return CCMode(kCCModeECB)
        case .cbc: return CCMode(kCCModeCBC)
        case .cfb: return CCMode(kCCModeCFB)
        case .cfb8: return CCMode(kCCModeCFB8)
        case .ctr: return CCMode(kCCModeCTR)
        case .ofb: return CCMode(kCCModeOFB)
        case .xts: return CCMode(kCCModeXTS)
        }
    }

}

enum CatCCEncryptionPadding {

    case noPadding
    case pkcs7Padding

    var ccValue: CCPadding {
        switch self {
        case .noPadding: return CCPadding(ccNoPadding)
        case .pkcs7Padding: return CCPadding(ccPKCS7Padding)
        }
    }

}

/// `CatCCEncryptionCrypto` just for code convenient and coupling, and it just as
/// father class for hash function crypto class depend on `CommonCrypto`.
public class CatCCEncryptionCrypto: Encryption, Decryption {

    /// Algorithm to switch function from CommonCrypto.
    var algorithm: CatCCEncryptionAlgorithm = .aes {
        didSet {
            switch algorithm {
            case .aes: blockSize = kCCBlockSizeAES128
            case .des: blockSize = kCCBlockSizeDES
            case .tdes: blockSize = kCCBlockSize3DES
            case .rc2: blockSize = kCCBlockSizeRC2
            case .rc4: blockSize = 0
            case .cast: blockSize = kCCBlockSizeCAST
            case .blowfish: blockSize = kCCBlockSizeBlowfish
            }
        }
    }

    var mode: CatCCEncryptionMode = .ecb

    var padding: CatCCEncryptionPadding = .pkcs7Padding

    var initializationVector: String = String.zeroString(length: 32)

    private var blockSize: Int = kCCBlockSizeAES128

    var key: String = String.zeroString(length: 32)

    var tweak: String = "tweak"

    var numberOfRounds: Int = 0

    /// Digest length in bytes to hash function.
    private(set) var digestLength: Int = Int(CC_MD5_DIGEST_LENGTH)

    /// Initialize the crypto.
    init() {}

    /// Encrypt or decrypt password string with desire encrypt function from
    /// `CommonCrypto`.
    ///
    /// - Parameters:
    ///   - operation: Operation for `CommonCrypto` to process.
    ///   - password: Password for encrypt or decrypt.
    /// - Returns: Return a crypto result.
    func commonCryptoOperation(operation: CatCCOperation, raw: [CChar]) -> CatCryptoResult {
        let rawLength = raw.count
        let ivCString = initializationVector.cString(using: .utf8)
        let keyCString = key.cString(using: .utf8)
        let keyLength = key.lengthOfBytes(using: .utf8)
        let tweakCString = tweak.cString(using: .utf8)
        let tweakLength = tweak.lengthOfBytes(using: .utf8)
        var cryptorRef: CCCryptorRef?
        let cryptorCreateState = CCCryptorCreateWithMode(operation.ccValue, mode.ccValue, algorithm.ccValue,
                                                         padding.ccValue, ivCString, keyCString, keyLength,
                                                         tweakCString, tweakLength, Int32(numberOfRounds),
                                                         CCModeOptions(kCCModeOptionCTR_BE), &cryptorRef)
        let resultLength = CCCryptorGetOutputLength(cryptorRef, rawLength, true)
        var result: [CUnsignedChar] = Array(repeating: 0, count: resultLength)
        var dataOutMoved: Int = 0
        let cryptorUpdateState = CCCryptorUpdate(cryptorRef, raw, rawLength,
                                                 &result, resultLength, &dataOutMoved)
        let cryptorFinalState = CCCryptorFinal(cryptorRef, &result, resultLength, &dataOutMoved)
        let cryptoResult = CatCryptoResult()
        let createErrorCode = CatCCCryptoErrorCode(errorCode: Int(cryptorCreateState))
        let updateErrorCode = CatCCCryptoErrorCode(errorCode: Int(cryptorUpdateState))
        let finalErrorCode = CatCCCryptoErrorCode(errorCode: Int(cryptorFinalState))
        guard createErrorCode == .success else {
            let error = CatCryptoError()
            error.errorCode = createErrorCode.rawValue
            error.errorDescription = createErrorCode.description
            cryptoResult.error = error
            return cryptoResult
        }
        guard updateErrorCode == .success else {
            let error = CatCryptoError()
            error.errorCode = updateErrorCode.rawValue
            error.errorDescription = updateErrorCode.description
            cryptoResult.error = error
            return cryptoResult
        }
        guard finalErrorCode == .success else {
            let error = CatCryptoError()
            error.errorCode = finalErrorCode.rawValue
            error.errorDescription = finalErrorCode.description
            cryptoResult.error = error
            return cryptoResult
        }
        cryptoResult.raw = Array(result[0 ..< resultLength])
        return cryptoResult
    }

    // MARK: - Encryption
    public func encrypt(password: String) -> CatCryptoResult {
        return commonCryptoOperation(operation: .encrypt, raw: password.cString(using: .utf8) ?? [])
    }

    // MARK: - Decryption
    public func decrypt(encryptedPassword: String, encodeMode: StringEncodeMode) -> CatCryptoResult {
        switch encodeMode {
        case .hex: return commonCryptoOperation(operation: .decrypt, raw: encryptedPassword.raw(encodeMode: .hex).cString(using: .utf8) ?? [])
        case .base64: return commonCryptoOperation(operation: .decrypt, raw: encryptedPassword.raw(encodeMode: .hex).cString(using: .utf8) ?? [])
        }
    }

}
