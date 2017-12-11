# CatCrypto

[![CI Status](http://img.shields.io/travis/ImKcat/CatCrypto.svg?style=flat)](https://travis-ci.org/ImKcat/CatCrypto)
[![Version](https://img.shields.io/cocoapods/v/CatCrypto.svg?style=flat)](http://cocoapods.org/pods/CatCrypto)
[![License](https://img.shields.io/cocoapods/l/CatCrypto.svg?style=flat)](http://cocoapods.org/pods/CatCrypto)
[![Platform](https://img.shields.io/cocoapods/p/CatCrypto.svg?style=flat&colorB=7c3636)](http://cocoapods.org/pods/CatCrypto)

## Requirements
- Xcode 9+
- Swift 4

## Usage

CatCrypto support only Argon2 password-hashing function currently, more functions in progress!

### Argon2
[Argon2](https://github.com/P-H-C/phc-winner-argon2) is the password-hashing function that won the [Password Hashing Competition (PHC)](https://password-hashing.net/).

``` swift
let argon2Crypto = CatArgon2Crypto()
argon2Crypto.hash(password: "password", completeHandler: { (hashResult) in
                if hashResult.error == nil {
                    print(hashResult.value!)
                }
            })

// $argon2i$v=19$m=4096,t=3,p=1$OTY3Njk1RDAtMzAxMy00MDQxLUE1MkEtNDMwRThGN0QzQTgz$JIYBIOhvjT955Vxx2uTN6FrXUyPuzjhF1l3pFeEVpfQ

let hash = "$argon2i$v=19$m=4096,t=3,p=1$OTY3Njk1RDAtMzAxMy00MDQxLUE1MkEtNDMwRThGN0QzQTgz$JIYBIOhvjT955Vxx2uTN6FrXUyPuzjhF1l3pFeEVpfQ"

argon2Crypto.verify(hash: hash, password: "password", completeHandler: { (verifyResult) in
                    if verifyResult.error == nil {
                        print("Verify success")
                    } else {
                    	print("Verify failure")
                    }
                })

// Verify success
```

CatCrypto support Argon2i, Argon2d, and Argon2id three different mode, Argon2i is default mode and it is recommend.

you can switch mode with `CatArgon2Context`:

``` swift
argon2Crypto.context.mode = .Argon2i
argon2Crypto.context.mode = .Argon2d
argon2Crypto.context.mode = .Argon2id
```

## Installation

CatCrypto is available through [CocoaPods](http://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod 'CatCrypto'
```

## License

CatCrypto is available under the MIT license. See the LICENSE file for more info.
