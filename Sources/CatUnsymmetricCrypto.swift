//
//  CatUnsymmetricCrypto.swift
//  Example
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import Foundation

class CatUnsymmetricCrypto {
    func hash(password: String, completeHandler: ((CatCryptoHashResult) -> Void)?) {}
    
    func verify(hash: String, password: String, completeHandler: ((CatCryptoVerifyResult) -> Void)?) {}
}
