//
//  CatArgon2Crypto.swift
//  CatCrypto
//
//  Created by Kcat on 2017/12/10.
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

/// CatArgon2ContextMode has three mode to use: Argon2i, Argon2d, and Argon2id. Argon2i is recommend
///
/// - Argon2d: Argon2d is faster and uses data-depending memory access, which makes it highly resistant against GPU cracking attacks and suitable for applications with no threats from side-channel timing attacks
/// - Argon2i: Argon2i instead uses data-independent memory access, which is preferred for password hashing and password-based key derivation, but it is slower as it makes more passes over the memory to protect from tradeoff attacks
/// - Argon2id: Argon2id is a hybrid of Argon2i and Argon2d, using a combination of data-depending and data-independent memory accesses, which gives some of Argon2i's resistance to side-channel cache timing attacks and much of Argon2d's resistance to GPU cracking attacks
public enum CatArgon2ContextMode: Int {
    case Argon2d = 0
    case Argon2i = 1
    case Argon2id = 2
}

/// CatArgon2Context is the context and it descript what you want to hash with Argon2 function
public class CatArgon2Context {
    
    /// The running time independently of the memory size
    public var iterations: Int = 3
    
    /// The memory usage
    public var memory: Int = 1 << 12
    
    /// Parallelism threads
    public var parallelism: Int = 1
    
    /// The mode of Argon2
    public var mode: CatArgon2ContextMode = CatArgon2ContextMode.Argon2i
    
    /// The salt to use, at least 8 characters
    public var salt: String = UUID().uuidString
    
    /// Hash output length
    public var hashlen: Int = 32
    
    public init(iterations: Int = 3,
                memory: Int = 1 << 12,
                parallelism: Int = 1,
                mode: CatArgon2ContextMode = .Argon2i,
                salt: String = UUID().uuidString,
                hashlen: Int = 32) {
        self.iterations = iterations
        self.memory = memory
        self.parallelism = parallelism
        self.mode = mode
        self.salt = salt
        self.hashlen = hashlen
    }
}

/// CatArgon2Crypto is the crypto for Argon2 function
///
/// [Argon2](https://github.com/P-H-C/phc-winner-argon2) is the password-hashing function that won the [Password Hashing Competition (PHC)](https://password-hashing.net/).
///
public class CatArgon2Crypto: CatAsymmetricCrypto {
    
    /// Context for the crypto
    public var context: CatArgon2Context = CatArgon2Context()
    
    public init(context: CatArgon2Context = CatArgon2Context()) {
        self.context = context
    }
    
    override public func hash(password: String, completeHandler: ((CatCryptoHashResult) -> Void)?) {
        let passwordCString = password.cString(using: .utf8)
        let passwordLength = password.lengthOfBytes(using: .utf8)
        let saltCString = context.salt.cString(using: .utf8)
        let saltLength = context.salt.lengthOfBytes(using: .utf8)
        let encodedlen = argon2_encodedlen(CUnsignedInt(context.iterations),
                                           CUnsignedInt(context.memory),
                                           CUnsignedInt(context.parallelism),
                                           CUnsignedInt(saltLength),
                                           CUnsignedInt(context.hashlen),
                                           argon2_type(rawValue: CUnsignedInt(context.mode.rawValue)))
        
        var resultCode: CInt
        let encoded = UnsafeMutablePointer<CChar>.allocate(capacity: encodedlen)
        defer {
            encoded.deallocate(capacity: encodedlen)
        }
        
        switch context.mode {
        case .Argon2d:
            resultCode = argon2d_hash_encoded(CUnsignedInt(context.iterations),
                                              CUnsignedInt(context.memory),
                                              CUnsignedInt(context.parallelism),
                                              passwordCString,
                                              passwordLength,
                                              saltCString,
                                              saltLength,
                                              context.hashlen,
                                              encoded,
                                              encodedlen)
        case .Argon2i:
            resultCode = argon2i_hash_encoded(CUnsignedInt(context.iterations),
                                              CUnsignedInt(context.memory),
                                              CUnsignedInt(context.parallelism),
                                              passwordCString,
                                              passwordLength,
                                              saltCString,
                                              saltLength,
                                              context.hashlen,
                                              encoded,
                                              encodedlen)
        case .Argon2id:
            resultCode = argon2id_hash_encoded(CUnsignedInt(context.iterations),
                                               CUnsignedInt(context.memory),
                                               CUnsignedInt(context.parallelism),
                                               passwordCString,
                                               passwordLength,
                                               saltCString,
                                               saltLength,
                                               context.hashlen,
                                               encoded,
                                               encodedlen)
        }
        
        if completeHandler != nil {
            let cryptoResult = CatCryptoHashResult()
            if resultCode == 0 {
                cryptoResult.value = String(cString: encoded)
                completeHandler!(cryptoResult)
            } else {
                cryptoResult.error = CatCryptoError()
                cryptoResult.error?.errorCode = Int(resultCode)
                cryptoResult.error?.errorDescription = String(cString: argon2_error_message(resultCode))
                completeHandler!(cryptoResult)
            }
        }
    }
    
    override public func verify(hash: String, password: String, completeHandler: ((CatCryptoVerifyResult) -> Void)?) {
        let encodedCString = hash.cString(using: .utf8)
        let passwordCString = password.cString(using: .utf8)
        let passwordLength = password.lengthOfBytes(using: .utf8)
        var resultCode: CInt
        
        switch context.mode {
        case .Argon2d:
            resultCode = argon2d_verify(encodedCString, passwordCString, passwordLength)
        case .Argon2i:
            resultCode = argon2i_verify(encodedCString, passwordCString, passwordLength)
        case .Argon2id:
            resultCode = argon2id_verify(encodedCString, passwordCString, passwordLength)
        }
        
        if completeHandler != nil {
            let cryptoResult = CatCryptoVerifyResult()
            if resultCode == 0 {
                cryptoResult.value = true
                completeHandler!(cryptoResult)
            } else {
                cryptoResult.error = CatCryptoError()
                cryptoResult.error?.errorCode = Int(resultCode)
                cryptoResult.error?.errorDescription = String(cString: argon2_error_message(resultCode))
                completeHandler!(cryptoResult)
            }
        }
    }
}
