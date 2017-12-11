//
//  CatArgon2CryptoTests.swift
//  CatCryptoTests
//
//  Created by Kcat on 2017/12/11.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import XCTest
@testable import CatCrypto

class CatArgon2CryptoTests: XCTestCase {
    
    let argon2Crypto = CatArgon2Crypto()
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testArgon2() {
        let password = UUID().uuidString
        let hashExpectation = self.expectation(description: "Hashing")
        let verifyExpectation = self.expectation(description: "Verifing")
        argon2Crypto.hash(password: password, completeHandler: { (hashResult) in
            if hashResult.error == nil {
                self.argon2Crypto.verify(hash: hashResult.value!, password: password, completeHandler: { (verifyResult) in
                    if verifyResult.error == nil {
                        XCTAssert(true, "Verify success")
                    } else {
                        XCTFail("Verify failure, " + verifyResult.error!.errorDescription!)
                    }
                    verifyExpectation.fulfill()
                })
            }
            hashExpectation.fulfill()
        })
        self.waitForExpectations(timeout: 20, handler: nil)
    }

    func testArgon2HashPerformance() {
        self.measure {
            for _ in 1...50 {
                argon2Crypto.hash(password: UUID().uuidString, completeHandler: { (hashResult) in
                    XCTAssert(hashResult.error == nil)
                })
            }
        }
    }
    
}
