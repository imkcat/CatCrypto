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

/// CatArgon2Crypto is the crypto for Argon2
///
/// [Argon2](https://github.com/P-H-C/phc-winner-argon2) is the password-hashing function that won the [Password Hashing Competition (PHC)](https://password-hashing.net/).
///
public class CatArgon2Crypto: CatUnsymmetricCrypto {
    
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
