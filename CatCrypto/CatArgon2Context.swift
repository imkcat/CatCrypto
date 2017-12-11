//
//  CatArgon2Context.swift
//  Example
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import Foundation

public enum CatArgon2ContextMode: Int {
    case Argon2d = 0
    case Argon2i = 1
    case Argon2id = 2
}

public class CatArgon2Context {
    public var iterations: Int = 3
    public var memory: Int = 1 << 12
    public var parallelism: Int = 1
    public var mode: CatArgon2ContextMode = CatArgon2ContextMode.Argon2i
    public var salt: String = UUID().uuidString
    public var hashlen: Int = 32
    
    public init(iterations: Int = 3,
                memory: Int = 1 << 12,
                parallelism: Int = 1,
                mode: CatArgon2ContextMode = .Argon2i,
                salt: String = UUID().uuidString,
                hashlen: Int = 32) {
        self.iterations = iterations
        self.memory = memory
        self.parallelism = parallelism
        self.mode = mode
        self.salt = salt
        self.hashlen = hashlen
    }
}
