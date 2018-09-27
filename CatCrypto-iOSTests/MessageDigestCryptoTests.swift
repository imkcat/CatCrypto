//
//  MessageDigestCryptoTests.swift
//  CatCrypto-iOSTests
//
//  Created by Kcat on 2017/12/28.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import XCTest
@testable import CatCrypto

class MessageDigestCryptoTests: XCTestCase {

    var md2Crypto: CatMD2Crypto!

    var md4Crypto: CatMD4Crypto!

    var md5Crypto: CatMD5Crypto!

    var md6Crypto: CatMD6Crypto!

    override func setUp() {
        super.setUp()
        md2Crypto = CatMD2Crypto()
        md4Crypto = CatMD4Crypto()
        md5Crypto = CatMD5Crypto()
        md6Crypto = CatMD6Crypto()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testNormalHashing() {
        let password = "Hi CatCrypto!"
        let md2Hash = "6ea4345a17562bf4703152aec8672d6d"
        let md4Hash = "c2bb6aee7fafc5ee23b05baaafba8b9d"
        let md5Hash = "3677650e5a4c1a8497e87331dd67c112"
        let md6Hash = "377f5f2f9372341b15e9a2e54c4034b7f8161d4a9907c3c8bdb37208369cc2446ef7382928e432a9bd58177a54ef7bd53f27f35d80006167b17248c5fa3d" +
        "f1b3"
        XCTAssertEqual(md2Crypto.hash(password: password).hexStringValue(), md2Hash)
        XCTAssertEqual(md4Crypto.hash(password: password).hexStringValue(), md4Hash)
        XCTAssertEqual(md5Crypto.hash(password: password).hexStringValue(), md5Hash)
        XCTAssertEqual(md6Crypto.hash(password: password).hexStringValue(), md6Hash)
    }

    func testEmptyHashing() {
        let password = ""
        let md2Hash = "8350e5a3e24c153df2275c9f80692773"
        let md4Hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
        let md5Hash = "d41d8cd98f00b204e9800998ecf8427e"
        let md6Hash = "6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ece49ccb469f8beeee7c831206bd577f9f2630d9177979203a9489e47e04df4e6deaa0f8" +
        "e0c0"
        XCTAssertEqual(md2Crypto.hash(password: password).hexStringValue(), md2Hash)
        XCTAssertEqual(md4Crypto.hash(password: password).hexStringValue(), md4Hash)
        XCTAssertEqual(md5Crypto.hash(password: password).hexStringValue(), md5Hash)
        XCTAssertEqual(md6Crypto.hash(password: password).hexStringValue(), md6Hash)
    }

    func testMD6HashLength() {
        let password = "Hi CatCrypto!"
        let bit224Hash = "1e9fff946e2d35d551bd3927a71233cecc769e263435085dfdad79bc"
        let bit256Hash = "5402a99f803be2f12d7e7675affcea14ac26af0a84c565ae631de93add884d43"
        let bit384Hash = "8c0202be3d8190dc1ad232dd340ded9b76446365c4834e68ab81e710f751631e67becb848e264b55bd244014d3ed5b04"
        let bit512Hash = "377f5f2f9372341b15e9a2e54c4034b7f8161d4a9907c3c8bdb37208369cc2446ef7382928e432a9bd58177a54ef7bd53f27f35d80006167b17248c5f" +
        "a3df1b3"
        md6Crypto.context.hashLength = .bit224
        XCTAssertEqual(md6Crypto.hash(password: password).hexStringValue(), bit224Hash)
        md6Crypto.context.hashLength = .bit256
        XCTAssertEqual(md6Crypto.hash(password: password).hexStringValue(), bit256Hash)
        md6Crypto.context.hashLength = .bit384
        XCTAssertEqual(md6Crypto.hash(password: password).hexStringValue(), bit384Hash)
        md6Crypto.context.hashLength = .bit512
        XCTAssertEqual(md6Crypto.hash(password: password).hexStringValue(), bit512Hash)
    }

}
