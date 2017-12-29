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
        let md6Hash = "377f5f2f9372341b15e9a2e54c4034b7f8161d4a9907c3c8bdb372" +
        "08369cc2446ef7382928e432a9bd58177a54ef7bd53f27f35d80006167b17248c5fa" +
        "3df1b3"
        XCTAssertEqual(md2Crypto.hash(password: password).value, md2Hash)
        XCTAssertEqual(md4Crypto.hash(password: password).value, md4Hash)
        XCTAssertEqual(md5Crypto.hash(password: password).value, md5Hash)
        XCTAssertEqual(md6Crypto.hash(password: password).value, md6Hash)
    }
    
    func testEmptyHashing() {
        let password = ""
        let md2Hash = "8350e5a3e24c153df2275c9f80692773"
        let md4Hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
        let md5Hash = "d41d8cd98f00b204e9800998ecf8427e"
        let md6Hash = "6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ec" +
        "e49ccb469f8beeee7c831206bd577f9f2630d9177979203a9489e47e04df4e6deaa0" +
        "f8e0c0"
        XCTAssertEqual(md2Crypto.hash(password: password).value, md2Hash)
        XCTAssertEqual(md4Crypto.hash(password: password).value, md4Hash)
        XCTAssertEqual(md5Crypto.hash(password: password).value, md5Hash)
        XCTAssertEqual(md6Crypto.hash(password: password).value, md6Hash)
    }
    
}
