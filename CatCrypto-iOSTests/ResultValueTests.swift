//
//  ResultValueTests.swift
//  CatCrypto-iOSTests
//
//  Created by vlang on 2018/9/27.
//  Copyright © 2018 imkcat. All rights reserved.
//

import XCTest
@testable import CatCrypto

class ResultValueTests: XCTestCase {

    var argon2Crypto: CatArgon2Crypto!
    var md6Crypto: CatMD6Crypto!
    let password = "CatCrypto"

    override func setUp() {
        argon2Crypto = CatArgon2Crypto()
        md6Crypto = CatMD6Crypto()
    }

    override func tearDown() {
    }

    func testStringValue() {
        XCTAssertFalse(argon2Crypto.hash(password: password).stringValue() == "")
    }

    func testHexValue() {
        XCTAssertFalse(md6Crypto.hash(password: password).hexStringValue() == "")
    }

    func testBase64Value() {
        XCTAssertFalse(md6Crypto.hash(password: password).base64StringValue() == "")
    }

}
