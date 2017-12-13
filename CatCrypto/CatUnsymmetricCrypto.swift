//
//  CatUnsymmetricCrypto.swift
//  Example
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import Foundation

public class CatUnsymmetricCrypto {
    
    /// Hash password string with unsymmetric password-hashing function
    ///
    /// - Parameters:
    ///   - password: Password string for hash
    ///   - completeHandler: Return a hash result when hashing task finish
    public func hash(password: String, completeHandler: ((CatCryptoHashResult) -> Void)?) {}
    
    /// Verify hashed string and original password string
    ///
    /// - Parameters:
    ///   - hash: Hashed string
    ///   - password: Original password string
    ///   - completeHandler: Return a verify result when verifying task finish
    public func verify(hash: String, password: String, completeHandler: ((CatCryptoVerifyResult) -> Void)?) {}
}
