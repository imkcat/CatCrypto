<p align="center">
  <img src="https://github.com/ImKcat/CatCrypto/raw/master/CatCrypto-Logo.png" alt="Logo">
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
      <a href="https://codecov.io/gh/ImKcat/CatCrypto"><img src="https://codecov.io/gh/ImKcat/CatCrypto/branch/master/graph/badge.svg" alt="Codecov"></a>
  <a href="https://beerpay.io/ImKcat/CatCrypto"><img src="https://beerpay.io/ImKcat/CatCrypto/badge.svg?style=flat" alt="Beerpay"></a>
</p>

CatCrypto include a series of hashing and encryption functions and more functions in progress!

CatCrypto also contains Swift bindings of [Argon2](https://github.com/P-H-C/phc-winner-argon2), the password-hashing function that won the Password Hashing Competition (PHC).

## Content

- [Content](#content)
- [Requirements](#requirements)
- [Support Functions](#support-functions)
- [Upcoming Functions](#upcoming-functions)
- [Usage](#usage)
  - [Context](#context)
  - [Hashing](#hashing)
  - [Verification](#verification)
- [Installation](#installation)
  - [CocoaPods](#cocoapods)
  - [Carthage](#carthage)
- [Documentation](#documentation)
- [Interacting](#interacting)
  - [Need Help](#need-help)
  - [Contribute](#contribute)
- [License](#license)

## Requirements

- Swift 4+
- iOS 8.0+
- macOS 10.10+
- tvOS 9.0+
- watchOS 2.0+

## Support Functions

- Hashing
  - Message-Digest
    - [MD2](https://tools.ietf.org/html/rfc1319)
    - [MD4](https://tools.ietf.org/html/rfc1320)
    - [MD5](https://tools.ietf.org/html/rfc1321)
    - [MD6](http://groups.csail.mit.edu/cis/md6/)
  - Secure Hash Algorithm
    - [SHA-1](https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf)
    - [SHA-2](https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf)
    - [SHA-3](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
  - [Argon2](https://github.com/P-H-C/phc-winner-argon2)

## Upcoming Functions

- Advanced Encryption Standard (AES)
- Data Encryption Standard (DES)
- Triple DES (3DES)

## Usage

### Context

Context contains inputs and configures for function crypto.

Change hash length with `SHA-2` function crypto:

```swift
let sha2Crypto = CatSHA2Crypto()
sha2Crypto.context.hashLength = .bit384
```

### Hashing

[Hash function](https://en.wikipedia.org/wiki/Hash_function) used to map data of arbitrary size to data of fixed size.

Simply hashing string with `MD6` function crypto:

```swift
let md6Crypto = CatMD6Crypto()
md6Crypto.context.hashLength = .bit512
print(md6Crypto.hash(password: "CatCrypto").hexStringValue())

// 3ad3003383633c40281bb5185424ee56a5a1c6dfa3a0e7c3a9e381c58d253323e146feb3f04cb9ebcde47186e042ce63109b8d19f3ca760ea00c90654eb2b272
```

### Verification

Some hash function support to verify their hashed value.

Verifing with `Argon2` function crypto:

```swift
let hash = "$argon2i$v=19$m=4096,t=3,p=1$Q2F0Q3J5cHRv$Ad6gXMVLvZ3uQOeTi6nCmU4Ns2/nPDfPD5B3yyebv8k"
let argon2Crypto = CatArgon2Crypto()
argon2Crypto.context.mode = .argon2i
argon2Crypto.context.salt = "CatCrypto"
print(argon2Crypto.verify(hash: hash, password: "CatCrypto").boolValue())

// true
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

## Documentation

- [API Reference](https://imkcat.github.io/CatCrypto/)

## Interacting

CatCrypto is always trying to support more functions and keep itself easy to use, please reading down below to interacting with CatCrypto.

### Need Help

- Reading [usage](https://github.com/ImKcat/CatCrypto#usage) section and [API Reference](https://imkcat.github.io/CatCrypto/)
- Searched in [issues](https://github.com/ImKcat/CatCrypto/issues) to find duplicated or related issues
- Ask question? [Open a question type issue](https://github.com/ImKcat/CatCrypto/issues/new)
- Report bug? [Open a bug type issue](https://github.com/ImKcat/CatCrypto/issues/new)
- Need new feature? [Open a feature type issue](https://github.com/ImKcat/CatCrypto/issues/new)

### Contribute

If you want to contribute with CatCrypto, please reading [Contribute Guidelines](https://github.com/ImKcat/CatCrypto/blob/master/CONTRIBUTING.md) at first.

## License

CatCrypto is available under the MIT license. See the LICENSE file for more info.
