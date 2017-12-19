![CatCrypto Logo](https://github.com/ImKcat/CatCrypto/raw/master/CatCrypto-Logo.png)

[![License](https://img.shields.io/cocoapods/l/CatCrypto.svg?style=flat)](http://cocoapods.org/pods/CatCrypto)
[![Support Platform](https://img.shields.io/cocoapods/p/CatCrypto.svg?style=flat&colorB=7c3636)](http://cocoapods.org/pods/CatCrypto)
[![Language](https://img.shields.io/badge/Language-swift4-EF5138.svg?style=flat)](https://github.com/Carthage/Carthage)
[![CocoaPods Version](https://img.shields.io/cocoapods/v/CatCrypto.svg?style=flat)](http://cocoapods.org/pods/CatCrypto)
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![Travis CI Status](http://img.shields.io/travis/ImKcat/CatCrypto.svg?style=flat)](https://travis-ci.org/ImKcat/CatCrypto)

## Requirements

- Swift 4+
- iOS 8.0+
- macOS 10.10+
- tvOS 9.0+
- watchOS 2.0+

## Usage

CatCrypto include a series of hashing functions and more functions in progress!

## Asymmetric hashing function

Because the nature of asymmetric hashing function, asymmetric hashing function always has two functions 'hash' and 'verify'.

### Message-Digest

CatCrypto support `MD2`, `MD4` and `MD5` Message-Digest functions.

Simply use Message-Digest function with `CatMessageDigestCrypto`:

``` swift
let messageDigestCrypto = CatMessageDigestCrypto()

messageDigestCrypto.context.mode = .MD2
messageDigestCrypto.context.mode = .MD4
messageDigestCrypto.context.mode = .MD5

// 13b86760bd1e322de76fc9035b848029
```

### Argon2

[Argon2](https://github.com/P-H-C/phc-winner-argon2) is the password-hashing function that won the [Password Hashing Competition (PHC)](https://password-hashing.net/).

CatCrypto support `Argon2i`, `Argon2d`, and `Argon2id` three different modes, `Argon2i` is default mode and it is recommend.

Simply use Argon2 function with `CatArgon2Crypto`:

``` swift
let argon2Crypto = CatArgon2Crypto()

argon2Crypto.context.mode = .Argon2i
argon2Crypto.context.mode = .Argon2d
argon2Crypto.context.mode = .Argon2id

// $argon2i$v=19$m=4096,t=3,p=1$Q2F0Q3J5cHRv$Ad6gXMVLvZ3uQOeTi6nCmU4Ns2/nPDfPD5B3yyebv8k
```

## Installation

CatCrypto is available through [CocoaPods](http://cocoapods.org) and [Carthage](https://github.com/Carthage/Carthage).

### CocoaPods

Add the following line to your Podfile:

```ruby
use_frameworks!

pod 'CatCrypto'
```

### Carthage

Add the following line to your Cartfile:

```ruby
github "ImKcat/CatCrypto"
```

## License

CatCrypto is available under the MIT license. See the LICENSE file for more info.
