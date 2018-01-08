//
//  ArgonTests.swift
//  CatCrypto-iOSTests
//
//  Created by Kcat on 2017/12/30.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import XCTest
@testable import CatCrypto

class ArgonTests: XCTestCase {

    var argon2Crypto: CatArgon2Crypto!

    override func setUp() {
        super.setUp()
        argon2Crypto = CatArgon2Crypto()
    }

    func testNormalHashing() {
        let password = "Hi CatCrypto!"
        argon2Crypto.context = CatArgon2Context()
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
    }

    func testEmptyHashing() {
        let password = ""
        argon2Crypto.context = CatArgon2Context()
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
    }

    func testNormalVerification() {
        let hash = "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$fBDUF2J/v69XKO" +
        "d9wyDQp1l5Vb97caIrGIvJ7HR2Kk8"
        let password = "Hi CatCrypto!"
        let wrongPassword = "CatCrypto"
        argon2Crypto.context = CatArgon2Context()
        XCTAssertTrue(argon2Crypto.verify(hash: hash, password: password).value)
        XCTAssertFalse(argon2Crypto.verify(hash: hash, password: wrongPassword).value)
    }

    func testIterations() {
        let password = "Hi CatCrypto!"
        argon2Crypto.context = CatArgon2Context()
        argon2Crypto.context.iterations = 0
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
        argon2Crypto.context.iterations = 2 << 33
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
    }

    func testMemery() {
        let password = "Hi CatCrypto!"
        argon2Crypto.context = CatArgon2Context()
        argon2Crypto.context.memory = 0
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
        argon2Crypto.context.memory = 2 << 33
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
    }

    func testParallelism() {
        let password = "Hi CatCrypto!"
        argon2Crypto.context = CatArgon2Context()
        argon2Crypto.context.parallelism = 0
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
        argon2Crypto.context.parallelism = 2 << 32
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
    }

    func testMode() {
        let argon2dHash = "$argon2d$v=19$m=4096,t=3,p=1$MzA0RkU2NkUtMDQ3Mi00N" +
        "kU0LTkwQzMtQUU0NzYyOURDMjVB$olTMaUSUINprvqhNoOPCR9ScpnAb4tlGYRYs2r8Z" +
        "k2E"
        let argon2iHash = "$argon2i$v=19$m=4096,t=3,p=1$MzA0RkU2NkUtMDQ3Mi00N" +
        "kU0LTkwQzMtQUU0NzYyOURDMjVB$xTosSgQwcRnXH2F8JtH/55gS2bM9aOFlc3LGZyzp" +
        "0lk"
        let argon2idHash = "$argon2id$v=19$m=4096,t=3,p=1$MzA0RkU2NkUtMDQ3Mi0" +
        "0NkU0LTkwQzMtQUU0NzYyOURDMjVB$ZcJqwaBXemTn3+Uxenc0fda9ISSArJANUJhpzK" +
        "iOxdY"
        let password = "Hi CatCrypto!"
        argon2Crypto.context = CatArgon2Context()
        argon2Crypto.context.salt = UUID().uuidString
        argon2Crypto.context.mode = .argon2d
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
        XCTAssertTrue(argon2Crypto.verify(hash: argon2dHash, password: password).value)
        argon2Crypto.context.mode = .argon2i
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
        XCTAssertTrue(argon2Crypto.verify(hash: argon2iHash, password: password).value)
        argon2Crypto.context.mode = .argon2id
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
        XCTAssertTrue(argon2Crypto.verify(hash: argon2idHash, password: password).value)
    }

    func testSalt() {
        let password = "Hi CatCrypto!"
        argon2Crypto.context = CatArgon2Context()
        argon2Crypto.context.salt = ""
        XCTAssertNil(argon2Crypto.hash(password: password).value)
        argon2Crypto.context.salt = UUID().uuidString
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
    }

    func testHashLength() {
        let password = "Hi CatCrypto!"
        argon2Crypto.context = CatArgon2Context()
        argon2Crypto.context.hashLength = 0
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
        argon2Crypto.context.hashLength = -1
        argon2Crypto.context.hashLength = Int(CUnsignedInt.max) + 1
        XCTAssertNotNil(argon2Crypto.hash(password: password).value)
    }

}
