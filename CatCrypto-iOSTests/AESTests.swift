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
        print([UInt8]("CatCrypt".utf8))
        let encryptedResult = aesCrypto.encrypt(password: "CatCry")
        let encryptedRaw = encryptedResult.raw as? [UInt8] ?? []
        let decryptedResult = aesCrypto.commonCryptoOperation(operation: .decrypt, raw: encryptedRaw)
        print(decryptedResult.raw)
        print(decryptedResult.stringValue())
//        print(encryptedResult.hexStringValue())
//        print(aesCrypto.decrypt(encryptedPassword: encryptedResult.stringValue()!).stringValue())
//        let decryptedString = aesCrypto.decrypt(encryptedPassword: encryptedString!).stringValue()
//        print(decryptedString!)
    }

}
