//
//  Argon.swift
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
import Argon2

/// `CatArgon2Mode` has three mode to use: `Argon2i`, `Argon2d`, and `Argon2id`.
/// `Argon2i` is recommend.
public enum CatArgon2Mode: Int {
    
    /// Argon2d is faster and uses data-depending memory access, which makes it
    /// highly resistant against GPU cracking attacks and suitable for
    /// applications with no threats from side-channel timing attacks.
    case argon2d = 0
    
    /// Argon2i instead uses data-independent memory access, which is preferred
    /// for password hashing and password-based key derivation, but it is slower
    /// as it makes more passes over the memory to protect from tradeoff attacks.
    case argon2i = 1
    
    /// Argon2id is a hybrid of Argon2i and Argon2d, using a combination of
    /// data-depending and data-independent memory accesses, which gives some of
    /// Argon2i's resistance to side-channel cache timing attacks and much of
    /// Argon2d's resistance to GPU cracking attacks.
    case argon2id = 2
}

public class CatArgon2Context: CatCryptoContext {
    
    /// Number of iterations.
    public var iterations: Int = 3
    
    /// Memory usage.
    public var memory: Int = 1 << 12
    
    /// Number of threads and compute lanes.
    public var parallelism: Int = 1
    
    /// The mode of Argon2.
    public var mode: CatArgon2Mode = .argon2i
    
    /// String to salt.
    public var salt: String = UUID().uuidString
    
    /// Desired length of the hash.
    public var hashLength: Int = 32
    
    public override init() {
        super.init()
    }
    
}

/// CatArgon2Crypto is the crypto for Argon2 function.
///
/// [Argon2](https://github.com/P-H-C/phc-winner-argon2) is the password-hashing
/// function that won the
/// [Password Hashing Competition (PHC)](https://password-hashing.net/).
public class CatArgon2Crypto: Contextual, Hashing, Verification {
    
    public typealias Context = CatArgon2Context
    
    public required init(context: Context = CatArgon2Context()) {
        self.context = context
    }
    
    /// Context for the crypto.
    public var context: CatArgon2Context = CatArgon2Context()
    
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
    
    // MARK: - Hashing
    
    /// Hash with design argon2 function.
    ///
    /// - Parameters:
    ///   - mode: Mode of argon2.
    ///   - iterations: Number of iterations.
    ///   - memory: Sets memory usage to m_cost kibibytes.
    ///   - parallelism: Number of threads and compute lanes.
    ///   - password: Password data to hasing.
    ///   - passwordLength: Password size in bytes.
    ///   - salt: String to salt.
    ///   - saltLength: Salt size in bytes.
    ///   - hashLength: Desired length of the hash in bytes.
    ///   - encoded: Encoded output.
    ///   - encodedLength: Encoded output length.
    /// - Returns: Result code for hasing.
    func argon2Hash(mode: CatArgon2Mode,
                    iterations: CUnsignedInt,
                    memory: CUnsignedInt,
                    parallelism: CUnsignedInt,
                    password: [CChar],
                    passwordLength: Int,
                    salt: [CChar],
                    saltLength: Int,
                    hashLength: Int,
                    encoded: UnsafeMutablePointer<CChar>,
                    encodedLength: Int) -> CInt {
        switch mode {
        case .argon2d:
            return argon2d_hash_encoded(iterations,
                                        memory,
                                        parallelism,
                                        password,
                                        passwordLength,
                                        salt,
                                        saltLength,
                                        hashLength,
                                        encoded,
                                        encodedLength)
        case .argon2i:
            return argon2i_hash_encoded(iterations,
                                        memory,
                                        parallelism,
                                        password,
                                        passwordLength,
                                        salt,
                                        saltLength,
                                        hashLength,
                                        encoded,
                                        encodedLength)
        case .argon2id:
            return argon2id_hash_encoded(iterations,
                                         memory,
                                         parallelism,
                                         password,
                                         passwordLength,
                                         salt,
                                         saltLength,
                                         hashLength,
                                         encoded,
                                         encodedLength)
        }
    }
    
    public func hash(password: String) -> CatCryptoHashResult {
        let encodedLength = argon2EncodedLength()
        let encoded = UnsafeMutablePointer<CChar>.allocate(capacity: encodedLength)
        defer {
            encoded.deallocate(capacity: encodedLength)
        }
        let resultCode = argon2Hash(mode: context.mode,
                                    iterations: CUnsignedInt(context.iterations),
                                    memory: CUnsignedInt(context.memory),
                                    parallelism: CUnsignedInt(context.parallelism),
                                    password: password.cString(using: .utf8)!,
                                    passwordLength: password.lengthOfBytes(using: .utf8),
                                    salt: context.salt.cString(using: .utf8)!,
                                    saltLength: context.salt.lengthOfBytes(using: .utf8),
                                    hashLength: context.hashLength,
                                    encoded: encoded,
                                    encodedLength: encodedLength)
        let hashResult = CatCryptoHashResult()
        if resultCode == 0 {
            hashResult.value = String(cString: encoded)
        } else {
            hashResult.error = CatCryptoError()
            hashResult.error?.errorCode = Int(resultCode)
            hashResult.error?.errorDescription = String(cString: argon2_error_message(resultCode))
        }
        return hashResult
    }
    
    // MARK: - Verification
    
    /// Verify with design argon2 function.
    ///
    /// - Parameters:
    ///   - mode: Mode of argon2
    ///   - encoded: Encoded string.
    ///   - password: Password string.
    ///   - passwordLength: Length of the password.
    /// - Returns: Result code for verification.
    func argon2Verify(mode: CatArgon2Mode,
                      encoded: [CChar],
                      password: [CChar],
                      passwordLength: Int) -> CInt {
        switch mode {
        case .argon2d:
            return argon2d_verify(encoded, password, passwordLength)
        case .argon2i:
            return argon2i_verify(encoded, password, passwordLength)
        case .argon2id:
            return argon2id_verify(encoded, password, passwordLength)
        }
    }
    
    public func verify(hash: String, password: String) -> CatCryptoVerifyResult {
        let resultCode = argon2Verify(mode: context.mode,
                                      encoded: hash.cString(using: .utf8)!,
                                      password: password.cString(using: .utf8)!,
                                      passwordLength: password.lengthOfBytes(using: .utf8))
        let verifyResult = CatCryptoVerifyResult()
        if resultCode == 0 {
            verifyResult.value = true
        } else {
            verifyResult.error = CatCryptoError()
            verifyResult.error?.errorCode = Int(resultCode)
            verifyResult.error?.errorDescription = String(cString: argon2_error_message(resultCode))
        }
        return verifyResult
    }
    
}
