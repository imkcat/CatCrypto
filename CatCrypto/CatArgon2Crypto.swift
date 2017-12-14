//
//  CatArgon2Crypto.swift
//  Example
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import Foundation
import argon2

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
        let pwdutf8 = strdup(NSString(string: password).utf8String)
        let pwd = UnsafeRawPointer(pwdutf8)
        let pwdlen = strlen(NSString(string: password).utf8String)
        let saltutf8 = strdup(NSString(string: context.salt).utf8String)
        let salt = UnsafeRawPointer(saltutf8)
        let saltlen = strlen(NSString(string: context.salt).utf8String)
        let encodedlen = argon2_encodedlen(UInt32(context.iterations),
                                           UInt32(context.memory),
                                           UInt32(context.parallelism),
                                           UInt32(saltlen),
                                           UInt32(context.hashlen),
                                           argon2_type(rawValue: UInt32(context.mode.rawValue)))
        
        var resultCode: Int32
        let encoded = UnsafeMutablePointer<Int8>.allocate(capacity: encodedlen)
        
        switch context.mode {
        case .Argon2d:
            resultCode = argon2d_hash_encoded(UInt32(context.iterations),
                                              UInt32(context.memory),
                                              UInt32(context.parallelism),
                                              pwd,
                                              pwdlen,
                                              salt,
                                              saltlen,
                                              context.hashlen,
                                              encoded,
                                              encodedlen)
        case .Argon2i:
            resultCode = argon2i_hash_encoded(UInt32(context.iterations),
                                              UInt32(context.memory),
                                              UInt32(context.parallelism),
                                              pwd,
                                              pwdlen,
                                              salt,
                                              saltlen,
                                              context.hashlen,
                                              encoded,
                                              encodedlen)
        case .Argon2id:
            resultCode = argon2id_hash_encoded(UInt32(context.iterations),
                                               UInt32(context.memory),
                                               UInt32(context.parallelism),
                                               pwd,
                                               pwdlen,
                                               salt,
                                               saltlen,
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
        
        free(pwdutf8)
        free(saltutf8)
        encoded.deallocate(capacity: encodedlen)
    }
    
    override public func verify(hash: String, password: String, completeHandler: ((CatCryptoVerifyResult) -> Void)?) {
        let pwdutf8 = strdup(NSString(string: password).utf8String)
        let pwd = UnsafeRawPointer(pwdutf8)
        let pwdlen = strlen(NSString(string: password).utf8String)
        let encoded = strdup(NSString(string: hash).utf8String)
        var resultCode: Int32
        
        switch context.mode {
        case .Argon2d:
            resultCode = argon2d_verify(encoded, pwd, pwdlen)
        case .Argon2i:
            resultCode = argon2i_verify(encoded, pwd, pwdlen)
        case .Argon2id:
            resultCode = argon2id_verify(encoded, pwd, pwdlen)
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
        
        free(pwdutf8)
        free(encoded)
    }
}
