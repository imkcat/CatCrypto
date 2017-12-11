//
//  CatCryptoHelper.swift
//  Example
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import Foundation

class CatCryptoResult {
    var error: CatCryptoError? = nil
}

class CatCryptoHashResult: CatCryptoResult {
    var value: String? = nil
}

class CatCryptoVerifyResult: CatCryptoResult {
    var value: Bool = false
}

class CatCryptoError: LocalizedError {
    var errorCode: Int = 0
    var errorDescription: String?
}
