<p align="center">
	<img src="CatCrypto-Logo.png" alt="Logo">
</p>

<p align="center">
	<img src="https://img.shields.io/badge/Language-swift4-EF5138.svg?style=flat" alt="Language">
	<a href="http://cocoapods.org/pods/CatCrypto"><img src="https://img.shields.io/cocoapods/p/CatCrypto.svg?style=flat" alt="Support Platform"></a>
	<a href="http://cocoapods.org/pods/CatCrypto"><img src="https://img.shields.io/cocoapods/l/CatCrypto.svg?style=flat" alt="License"></a>
</p>

<p align="center">
	<a href="https://github.com/Carthage/Carthage"><img src="https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat" alt="Carthage compatible"></a>
	<a href="http://cocoapods.org/pods/CatCrypto"><img src="https://img.shields.io/cocoapods/v/CatCrypto.svg?style=flat" alt="CocoaPods Version"></a>
</p>

<p align="center">
	<a href="https://travis-ci.org/ImKcat/CatCrypto"><img src="http://img.shields.io/travis/ImKcat/CatCrypto.svg?style=flat" alt="Travis CI Status"></a>
	<a href="https://codebeat.co/projects/github-com-imkcat-catcrypto-master"><img src="https://codebeat.co/badges/003d39ba-cbd6-4166-ab28-57630fc60f9f" alt="Codebeat"></a>
	<a href="https://imkcat.github.io/CatCrypto/"><img src="./docs/badge.svg" alt="Document"></a>
</p>

## Requirements

- Swift 4+
- iOS 8.0+
- macOS 10.10+
- tvOS 9.0+
- watchOS 2.0+

## Usage

CatCrypto include a series of hashing and encryption functions and more functions in progress!

## Support functions

- Hashing
	- Message-Digest
  		- [MD2](https://tools.ietf.org/html/rfc1319)
  		- [MD4](https://tools.ietf.org/html/rfc1320)
  		- [MD5](https://tools.ietf.org/html/rfc1321)
  		- [MD6](http://groups.csail.mit.edu/cis/md6/)
	- [Argon2](https://github.com/P-H-C/phc-winner-argon2)

## Installation

CatCrypto is available through [CocoaPods](http://cocoapods.org) and [Carthage](https://github.com/Carthage/Carthage).

## Usage

### Hash

[Hash function](https://en.wikipedia.org/wiki/Hash_function) used to map data of arbitrary size to data of fixed size.

Simply hash string with `MD5` function:

``` swift
let md6Crypto = CatMD6Crypto()
md6Crypto.context.hashLength = .bit512
print(md6Crypto.hash(password: "CatCrypto").value!)

// 3ad3003383633c40281bb5185424ee56a5a1c6dfa3a0e7c3a9e381c58d253323e146feb3f04cb9ebcde47186e042ce63109b8d19f3ca760ea00c90654eb2b272
```

### Verify

Some hash function support to verify their hashed value.

Verify with `Argon2` function:

``` swift
let hash = "$argon2i$v=19$m=4096,t=3,p=1$Q2F0Q3J5cHRv$Ad6gXMVLvZ3uQOeTi6nCmU4Ns2/nPDfPD5B3yyebv8k"
let argon2Crypto = CatArgon2Crypto()
argon2Crypto.context.mode = .argon2i
argon2Crypto.context.salt = "CatCrypto"
print(argon2Crypto.verify(hash: hash, password: "CatCrypto").value)

// true
```

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

## Documentation

[API Reference](https://imkcat.github.io/CatCrypto/)

## License

CatCrypto is available under the MIT license. See the LICENSE file for more info.
