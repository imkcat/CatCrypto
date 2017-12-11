//
//  CatCryptoHelper.swift
//  Example
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import Foundation

public class CatCryptoResult {
    public var error: CatCryptoError? = nil
}

public class CatCryptoHashResult: CatCryptoResult {
    public var value: String? = nil
}

public class CatCryptoVerifyResult: CatCryptoResult {
    public var value: Bool = false
}

public class CatCryptoError: LocalizedError {
    public var errorCode: Int = 0
    public var errorDescription: String?
}
