//
//  CatArgon2Crypto.swift
//  Example
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import Foundation
import argon2

public enum CatArgon2Error: Int {
    case ARGON2_OK = 0
    case ARGON2_OUTPUT_PTR_NULL = -1
    case ARGON2_OUTPUT_TOO_SHORT = -2
    case ARGON2_OUTPUT_TOO_LONG = -3
    case ARGON2_PWD_TOO_SHORT = -4
    case ARGON2_PWD_TOO_LONG = -5
    case ARGON2_SALT_TOO_SHORT = -6
    case ARGON2_SALT_TOO_LONG = -7
    case ARGON2_AD_TOO_SHORT = -8
    case ARGON2_AD_TOO_LONG = -9
    case ARGON2_SECRET_TOO_SHORT = -10
    case ARGON2_SECRET_TOO_LONG = -11
    case ARGON2_TIME_TOO_SMALL = -12
    case ARGON2_TIME_TOO_LARGE = -13
    case ARGON2_MEMORY_TOO_LITTLE = -14
    case ARGON2_MEMORY_TOO_MUCH = -15
    case ARGON2_LANES_TOO_FEW = -16
    case ARGON2_LANES_TOO_MANY = -17
    case ARGON2_PWD_PTR_MISMATCH = -18    /* NULL ptr with non-zero length */
    case ARGON2_SALT_PTR_MISMATCH = -19   /* NULL ptr with non-zero length */
    case ARGON2_SECRET_PTR_MISMATCH = -20 /* NULL ptr with non-zero length */
    case ARGON2_AD_PTR_MISMATCH = -21     /* NULL ptr with non-zero length */
    case ARGON2_MEMORY_ALLOCATION_ERROR = -22
    case ARGON2_FREE_MEMORY_CBK_NULL = -23
    case ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24
    case ARGON2_INCORRECT_PARAMETER = -25
    case ARGON2_INCORRECT_TYPE = -26
    case ARGON2_OUT_PTR_MISMATCH = -27
    case ARGON2_THREADS_TOO_FEW = -28
    case ARGON2_THREADS_TOO_MANY = -29
    case ARGON2_MISSING_ARGS = -30
    case ARGON2_ENCODING_FAIL = -31
    case ARGON2_DECODING_FAIL = -32
    case ARGON2_THREAD_FAIL = -33
    case ARGON2_DECODING_LENGTH_FAIL = -34
    case ARGON2_VERIFY_MISMATCH = -35
}

public class CatArgon2Crypto: CatUnsymmetricCrypto {
    public var context: CatArgon2Context = CatArgon2Context()
    
    override public func hash(password: String, completeHandler: ((CatCryptoHashResult) -> Void)?) {
        let pwd = UnsafeRawPointer(strdup(NSString(string: password).utf8String))
        let pwdlen = strlen(NSString(string: password).utf8String)
        let salt = UnsafeRawPointer(strdup(NSString(string: context.salt).utf8String))
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
                cryptoResult.error?.errorDescription = String(describing: CatArgon2Error(rawValue: Int(resultCode))!)
                completeHandler!(cryptoResult)
            }
        }
    }
    
    override public func verify(hash: String, password: String, completeHandler: ((CatCryptoVerifyResult) -> Void)?) {
        let pwd = UnsafeRawPointer(strdup(NSString(string: password).utf8String))
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
                cryptoResult.error?.errorDescription = String(describing: CatArgon2Error(rawValue: Int(resultCode))!)
                completeHandler!(cryptoResult)
            }
        }
    }
}
