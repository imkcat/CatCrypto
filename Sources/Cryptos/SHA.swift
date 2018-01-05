//
//  SHA.swift
//  CatCrypto
//
//  Created by Kcat on 2017/12/28.
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
import CommonCrypto
import SHA3

///  `CatSHA1Crypto` is the crypto for
/// [SHA-1](https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf)
/// function.
public class CatSHA1Crypto: CatCCHashCrypto {
    public override init() {
        super.init()
        mode = .ccSHA1
    }
}

/// Desired bit-length of the hash function output.
public enum CatSHA2HashLength {
    
    /// 224 bits.
    case bit224
    
    /// 256 bits.
    case bit256
    
    /// 384 bits.
    case bit384
    
    /// 512 bits.
    case bit512
}

/// Context for SHA-2 crypto.
public struct CatSHA2Context {
    
    /// Desired bit-length of the hash function output.
    public var hashLength: CatSHA2HashLength = .bit512
    
    /// Initialize the context.
    public init() {}
    
}

///  `CatSHA2Crypto` is the crypto for
/// [SHA-2](https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf)
/// function.
public class CatSHA2Crypto: CatCCHashCrypto, Contextual {
    
    public typealias Context = CatSHA2Context
    
    public var context: CatSHA2Context {
        didSet {
            switch context.hashLength {
            case .bit224:
                mode = .ccSHA224
            case .bit256:
                mode = .ccSHA256
            case .bit384:
                mode = .ccSHA384
            case .bit512:
                mode = .ccSHA512
            }
        }
    }
    
    public required init(context: Context = CatSHA2Context()) {
        self.context = context
        super.init()
        mode = .ccSHA512
    }
    
}

/// Desired bit-length of the hash function output.
public enum CatSHA3HashLength: Int {
    
    /// 224 bits.
    case bit224 = 28
    
    /// 256 bits.
    case bit256 = 32
    
    /// 384 bits.
    case bit384 = 48
    
    /// 512 bits.
    case bit512 = 64
}

/// Context for SHA-3 crypto.
public struct CatSHA3Context {
    
    /// Desired bit-length of the hash function output.
    public var hashLength: CatSHA3HashLength = .bit512
    
    /// Initialize the context.
    public init() {}
    
}

///  `CatSHA2Crypto` is the crypto for
/// [SHA-3](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) function.
public class CatSHA3Crypto: Contextual, Hashing {
    
    public typealias Context = CatSHA3Context
    
    public var context: CatSHA3Context
    
    public required init(context: CatSHA3Context = CatSHA3Context()) {
        self.context = context
    }
    
    /// Hash with SHA-3 function.
    ///
    /// - Parameters:
    ///   - output: Pointer to the output buffer.
    ///   - input: Pointer to the input message.
    ///   - inputByteLen: The length of the input message in bytes.
    /// - Returns: Result code of hashing function, 0 if successful, 1 otherwise.
    func sha3Hash(output: UnsafeMutablePointer<CUnsignedChar>,
                  input: UnsafePointer<CUnsignedChar>,
                  inputByteLen: Int) -> CInt {
        switch context.hashLength {
        case .bit224:
            return SHA3_224(output, input, inputByteLen)
        case .bit256:
            return SHA3_256(output, input, inputByteLen)
        case .bit384:
            return SHA3_384(output, input, inputByteLen)
        case .bit512:
            return SHA3_512(output, input, inputByteLen)
        }
    }
    
    public func hash(password: String) -> CatCryptoHashResult {
        let passwordLength = password.lengthOfBytes(using: .utf8)
        let passwordCString = UnsafeMutablePointer<CChar>(mutating: password.cString(using: .utf8))?.withMemoryRebound(to: CUnsignedChar.self, capacity: passwordLength, { point in
            return point
        })
        var result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: context.hashLength.rawValue)
        defer {
            result.deallocate(capacity: context.hashLength.rawValue)
        }
        let resultCode = sha3Hash(output: result, input: passwordCString!, inputByteLen: passwordLength)
        let hashResult = CatCryptoHashResult()
        if resultCode == 0 {
            hashResult.value = String.hexString(source: result, length: context.hashLength.rawValue)
        } else {
            hashResult.error?.errorCode = Int(resultCode)
        }
        return hashResult
    }
    
}
