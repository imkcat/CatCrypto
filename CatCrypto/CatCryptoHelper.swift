//
//  CatCryptoHelper.swift
//  Example
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import Foundation

/// Base result class for encrypt, decrypt, hash or verify
public class CatCryptoResult {
    
    /// Error for result
    public var error: CatCryptoError? = nil
}

/// Hash result class, include a string value
public class CatCryptoHashResult: CatCryptoResult {
    
    /// Hashed string commonly
    public var value: String? = nil
}

/// Verify result class, include a boolean value
public class CatCryptoVerifyResult: CatCryptoResult {
    
    /// Verification result
    public var value: Bool = false
}

/// Error for descript result
public class CatCryptoError: LocalizedError {
    
    /// Code number for error condition
    public var errorCode: Int = 0
    
    /// The description string for error
    public var errorDescription: String?
}
