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
</p>

## Requirements

- Swift 4+
- iOS 8.0+
- macOS 10.10+
- tvOS 9.0+
- watchOS 2.0+

## Usage

CatCrypto include a series of hashing and encryption functions and more functions in progress!

### Message-Digest `Hash`

CatCrypto support [MD2](https://tools.ietf.org/html/rfc1319), [MD4](https://tools.ietf.org/html/rfc1320), [MD5](https://tools.ietf.org/html/rfc1321) and [MD6](http://groups.csail.mit.edu/cis/md6/) Message-Digest functions.

Simply use `MD5` function with `CatMD5Crypto`:

``` swift
let md5Crypto = CatMD5Crypto()

print(md5Crypto.hash(password: "CatCrypto").value!)

// 13b86760bd1e322de76fc9035b848029
```

### Argon2 `Hash` `Verify`

[Argon2](https://github.com/P-H-C/phc-winner-argon2) is the password-hashing function that won the [Password Hashing Competition (PHC)](https://password-hashing.net/).

CatCrypto support `Argon2i`, `Argon2d`, and `Argon2id` three different modes, `Argon2i` is default mode and it is recommend.

Simply use Argon2 function with `CatArgon2Crypto`:

``` swift
let argon2Crypto = CatArgon2Crypto()

argon2Crypto.context.salt = "CatCrypto"
argon2Crypto.context.mode = .argon2i

print(argon2Crypto.hash(password: "CatCrypto").value!)

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
