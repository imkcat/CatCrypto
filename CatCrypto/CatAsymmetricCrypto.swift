//
//  CatAsymmetricCrypto.swift
//  CatCrypto
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//
// https://github.com/ImKcat/CatCrypto
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

import Foundation

public class CatAsymmetricCrypto {
    
    /// Hash password string with unsymmetric password-hashing function
    ///
    /// - Parameters:
    ///   - password: Password string for hash
    ///   - completeHandler: Return a hash result when hashing task finish
    public func hash(password: String, completeHandler: ((CatCryptoHashResult) -> Void)?) {}
    
    /// Verify hashed string and original password string
    ///
    /// - Parameters:
    ///   - hash: Hashed string
    ///   - password: Original password string
    ///   - completeHandler: Return a verify result when verifying task finish
    public func verify(hash: String, password: String, completeHandler: ((CatCryptoVerifyResult) -> Void)?) {}
}
