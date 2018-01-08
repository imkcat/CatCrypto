//
//  SHATests.swift
//  CatCrypto-iOSTests
//
//  Created by Kcat on 2017/12/29.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import XCTest
@testable import CatCrypto

class SHATests: XCTestCase {

    var sha1Crypto: CatSHA1Crypto!

    var sha2Crypto: CatSHA2Crypto!

    var sha3Crypto: CatSHA3Crypto!

    override func setUp() {
        super.setUp()
        sha1Crypto = CatSHA1Crypto()
        sha2Crypto = CatSHA2Crypto()
        sha3Crypto = CatSHA3Crypto()
    }

    override func tearDown() {
        super.tearDown()
    }

    func testNormalHashing() {
        let password = "Hi CatCrypto!"
        let sha1Hash = "78fc7f3a35cec79fc7bb7ace4e90316c90a91eae"
        let sha2Hash = "c9fd74f142910d835c22dff40cc943de3e3a8c364c752a488e0e6" +
        "6e0e17f7fea9f5c0e4b8f5f1e64d8e8ec96e97ef4a011704fec3c742d105299ce4ec" +
        "1c30976"
        XCTAssertEqual(sha1Crypto.hash(password: password).value, sha1Hash)
        XCTAssertEqual(sha2Crypto.hash(password: password).value, sha2Hash)
    }

    func testEmptyHashing() {
        let password = ""
        let sha1Hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        let sha2Hash = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a" +
        "921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af" +
        "927da3e"
        XCTAssertEqual(sha1Crypto.hash(password: password).value, sha1Hash)
        XCTAssertEqual(sha2Crypto.hash(password: password).value, sha2Hash)
    }

    func testSHA2HashLength() {
        let password = "Hi CatCrypto!"
        let bit224Hash = "2cbea89f84eaeb8411db4b5ea0cb06162e6286071959377171a" +
        "86d88"
        let bit256Hash = "7221d760b4be1adb057705650a8bc8d5858dfbf1d4740fc511a" +
        "7f216d02c60df"
        let bit384Hash = "faab5de04ebe052cdb76e2485d7bee7866ce48adc9dc0091828" +
        "bb0c25e5491296f9c37839fdd82cd37f062c996b74c80"
        let bit512Hash = "c9fd74f142910d835c22dff40cc943de3e3a8c364c752a488e0" +
        "e66e0e17f7fea9f5c0e4b8f5f1e64d8e8ec96e97ef4a011704fec3c742d105299ce4" +
        "ec1c30976"
        sha2Crypto.context.hashLength = .bit224
        XCTAssertEqual(sha2Crypto.hash(password: password).value, bit224Hash)
        sha2Crypto.context.hashLength = .bit256
        XCTAssertEqual(sha2Crypto.hash(password: password).value, bit256Hash)
        sha2Crypto.context.hashLength = .bit384
        XCTAssertEqual(sha2Crypto.hash(password: password).value, bit384Hash)
        sha2Crypto.context.hashLength = .bit512
        XCTAssertEqual(sha2Crypto.hash(password: password).value, bit512Hash)
    }

    func testSHA3HashLength() {
        let password = "Hi CatCrypto!"
        let bit224Hash = "13ef53d3f57e6b69244cfd6faf67d0dfad70927725504870a56" +
        "d92a5"
        let bit256Hash = "a4c90d63d19c6c4cb661480c29fed4b5ef900e53358b0190c8a" +
        "ff54ccda733ba"
        let bit384Hash = "9ad86c44624d577511728bcb5ee3df644856d8c1f7374de93a9" +
        "5f2c232def165f5dfaf56217e774e426179b4a30a0cd8"
        let bit512Hash = "a6a3a62c6e3572473bcd91dc366828acdf51d29b19aa1eef92c" +
        "b12a41f195000eff6a127ca66f19aa78754abea079157397d4a85e0e1c3c60f3f894" +
        "80b0159c6"
        sha3Crypto.context.hashLength = .bit224
        XCTAssertEqual(sha3Crypto.hash(password: password).value, bit224Hash)
        sha3Crypto.context.hashLength = .bit256
        XCTAssertEqual(sha3Crypto.hash(password: password).value, bit256Hash)
        sha3Crypto.context.hashLength = .bit384
        XCTAssertEqual(sha3Crypto.hash(password: password).value, bit384Hash)
        sha3Crypto.context.hashLength = .bit512
        XCTAssertEqual(sha3Crypto.hash(password: password).value, bit512Hash)
    }

}
