//
//  CatUnsymmetricCrypto.swift
//  Example
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import Foundation

public class CatUnsymmetricCrypto {
    public func hash(password: String, completeHandler: ((CatCryptoHashResult) -> Void)?) {}
    
    public func verify(hash: String, password: String, completeHandler: ((CatCryptoVerifyResult) -> Void)?) {}
}
