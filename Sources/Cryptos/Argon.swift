//
//  Argon.swift
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
import Argon2

/// `CatArgon2Mode` has three mode to use: `Argon2i`, `Argon2d`, and `Argon2id`. `Argon2i` is recommend.
public enum CatArgon2Mode: Int {

    /// Argon2d is faster and uses data-depending memory access, which makes it highly resistant against GPU cracking attacks and suitable for
    /// applications with no threats from side-channel timing attacks.
    case argon2d = 0

    /// Argon2i instead uses data-independent memory access, which is preferred for password hashing and password-based key derivation, but it is
    /// slower as it makes more passes over the memory to protect from tradeoff attacks.
    case argon2i = 1

    /// Argon2id is a hybrid of Argon2i and Argon2d, using a combination of data-depending and data-independent memory accesses, which gives some of
    /// Argon2i's resistance to side-channel cache timing attacks and much of Argon2d's resistance to GPU cracking attacks.
    case argon2id = 2
}

let argon2DefaultIterations = 3
let argon2MinIterations = 1
let argon2MaxIterations = 2 << 32 - 1

let argon2DefaultMemory = 1 << 12
let argon2MinMemory = 8
let argon2MaxMemory = 2 << 32 - 1

let argon2DefaultParallelism = 1
let argon2MinParallelism = 1
let argon2MaxParallelism = 2 << 32 - 1

let argon2DefaultHashLength = 32
let argon2MinHashLength = 4
let argon2MaxHashLength = Int(CUnsignedInt.max)

/// Context for Argon2 crypto.
public struct CatArgon2Context {

    /// Number of iterations.
    public var iterations: Int = argon2DefaultIterations {
        didSet {
            if !(argon2MinIterations...argon2MaxIterations).contains(iterations) {
                iterations = argon2DefaultIterations
            }
        }
    }

    /// Memory usage.
    public var memory: Int = argon2DefaultMemory {
        didSet {
            if !(argon2MinMemory...argon2MaxMemory).contains(memory) {
                memory = argon2DefaultMemory
            }
        }
    }

    /// Number of threads and compute lanes.
    public var parallelism: Int = argon2DefaultParallelism {
        didSet {
            if !(argon2MinParallelism...argon2MaxIterations).contains(parallelism) {
                parallelism = argon2DefaultParallelism
            }
        }
    }

    /// The mode of Argon2.
    public var mode: CatArgon2Mode = .argon2i

    /// String to salt.
    public var salt: String = "somesalt"

    /// Desired length of the hash.
    public var hashLength: Int = argon2DefaultHashLength {
        didSet {
            if !(argon2MinHashLength...argon2MaxHashLength).contains(hashLength) {
                hashLength = argon2DefaultHashLength
            }
        }
    }

    /// Initialize the context.
    public init() {}
}

/// `CatArgon2Crypto` is the crypto for Argon2 function.
///
/// [Argon2](https://github.com/P-H-C/phc-winner-argon2) is the password-hashing function that won the
/// [Password Hashing Competition (PHC)](https://password-hashing.net/).
public class CatArgon2Crypto: Contextual, Hashing, Verification {

    // MARK: - Contextual
    public typealias Context = CatArgon2Context

    /// Context for the crypto.
    public var context: CatArgon2Context = CatArgon2Context()

    public required init(context: Context = CatArgon2Context()) {
        self.context = context
    }

    // MARK: - Core
    /// Returns the encoded hash length.
    ///
    /// - Returns: The encoded hash length in bytes.
    func argon2EncodedLength() -> Int {
        let saltLength = context.salt.lengthOfBytes(using: .utf8)
        return argon2_encodedlen(CUnsignedInt(context.iterations),
                                 CUnsignedInt(context.memory),
                                 CUnsignedInt(context.parallelism),
                                 CUnsignedInt(saltLength),
                                 CUnsignedInt(context.hashLength),
                                 argon2_type(rawValue: CUnsignedInt(context.mode.rawValue)))
    }

    /// Hash with Argon2 function.
    ///
    /// - Parameter password: Password string.
    /// - Returns: Return a tuple that include error code and hashed string.
    func argon2Hash(password: String) -> (errorCode: CInt, hash: String) {
        let passwordCString = password.cString(using: .utf8)
        let passwordLength = password.lengthOfBytes(using: .utf8)
        let saltCString = context.salt.cString(using: .utf8)
        let saltLength = context.salt.lengthOfBytes(using: .utf8)
        let encodedLength = argon2EncodedLength()
        let result = UnsafeMutablePointer<CChar>.allocate(capacity: encodedLength)
        defer {
            result.deallocate()
        }
        var errorCode: CInt
        switch context.mode {
        case .argon2d:
            errorCode = argon2d_hash_encoded(CUnsignedInt(context.iterations), CUnsignedInt(context.memory), CUnsignedInt(context.parallelism),
                                             passwordCString, passwordLength, saltCString, saltLength, context.hashLength, result, encodedLength)
        case .argon2i:
            errorCode = argon2i_hash_encoded(CUnsignedInt(context.iterations), CUnsignedInt(context.memory), CUnsignedInt(context.parallelism),
                                             passwordCString, passwordLength, saltCString, saltLength, context.hashLength, result, encodedLength)
        case .argon2id:
            errorCode = argon2id_hash_encoded(CUnsignedInt(context.iterations), CUnsignedInt(context.memory), CUnsignedInt(context.parallelism),
                                              passwordCString, passwordLength, saltCString, saltLength, context.hashLength, result, encodedLength)
        }
        return (errorCode, String(cString: result))
    }

    /// Verify with Argon2 function.
    ///
    /// - Parameters:
    ///   - hash: Hash string.
    ///   - password: Password string.
    /// - Returns: Return an error code.
    func argon2Verify(hash: String,
                      password: String) -> CInt {
        let passwordLength = password.lengthOfBytes(using: .utf8)
        switch context.mode {
        case .argon2d: return argon2d_verify(hash.cString(using: .utf8), password.cString(using: .utf8), passwordLength)
        case .argon2i: return argon2i_verify(hash.cString(using: .utf8), password.cString(using: .utf8), passwordLength)
        case .argon2id: return argon2id_verify(hash.cString(using: .utf8), password.cString(using: .utf8), passwordLength)
        }
    }

    // MARK: - Hashing
    public func hash(password: String) -> CatCryptoHashResult {
        let result = argon2Hash(password: password)
        let hashResult = CatCryptoHashResult()
        if result.errorCode == 0 {
            hashResult.value = result.hash
        } else {
            let error = CatCryptoError()
            error.errorCode = Int(result.errorCode)
            error.errorDescription = String(cString: argon2_error_message(result.errorCode))
            hashResult.error = error
        }
        return hashResult
    }

    // MARK: - Verification
    public func verify(hash: String, password: String) -> CatCryptoVerifyResult {
        let errorCode = argon2Verify(hash: hash, password: password)
        let verifyResult = CatCryptoVerifyResult()
        if errorCode == 0 {
            verifyResult.value = true
        } else {
            let error = CatCryptoError()
            error.errorCode = Int(errorCode)
            error.errorDescription = String(cString: argon2_error_message(errorCode))
            verifyResult.error = error
        }
        return verifyResult
    }

}
