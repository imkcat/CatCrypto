//
//  CatArgon2Context.swift
//  Example
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import Foundation

enum CatArgon2ContextMode: Int {
    case Argon2d = 0
    case Argon2i = 1
    case Argon2id = 2
}

class CatArgon2Context {
    var iterations: Int = 3
    var memory: Int = 1 << 12
    var parallelism: Int = 1
    var mode: CatArgon2ContextMode = CatArgon2ContextMode.Argon2i
    var salt: String = UUID().uuidString
    var hashlen: Int = 32
}
