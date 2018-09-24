//
//  AES.swift
//  CatCrypto-iOSTests
//
//  Created by Kcat on 2018/1/12.
//  Copyright © 2018年 imkcat. All rights reserved.
//

import XCTest
@testable import CatCrypto
import CommonCrypto

class AES: XCTestCase {

    var aesCrypto: CatCCEncryptionCrypto!

    override func setUp() {
        super.setUp()
        aesCrypto = CatCCEncryptionCrypto()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testNormalEncrypt() {
        aesCrypto.algorithm = .aes
        aesCrypto.mode = .ecb
        let encryptedResult = aesCrypto.encrypt(password: "CatCrypto")
        let hexString = encryptedResult.hexStringValue()
        print(hexString)
        print(aesCrypto.decrypt(encryptedPassword: hexString ?? "", encodeMode: .hex).stringValue())
//        print(encryptedResult.hexStringValue())
//        print(aesCrypto.decrypt(encryptedPassword: encryptedResult.stringValue()!).stringValue())
//        let decryptedString = aesCrypto.decrypt(encryptedPassword: encryptedString!).stringValue()
//        print(decryptedString!)
    }

}
