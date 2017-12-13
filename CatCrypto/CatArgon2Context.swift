//
//  CatArgon2Context.swift
//  Example
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import Foundation

/// CatArgon2ContextMode has three mode to use: Argon2i, Argon2d, and Argon2id. Argon2i is recommend
///
/// - Argon2d: Argon2d is faster and uses data-depending memory access, which makes it highly resistant against GPU cracking attacks and suitable for applications with no threats from side-channel timing attacks
/// - Argon2i: Argon2i instead uses data-independent memory access, which is preferred for password hashing and password-based key derivation, but it is slower as it makes more passes over the memory to protect from tradeoff attacks
/// - Argon2id: Argon2id is a hybrid of Argon2i and Argon2d, using a combination of data-depending and data-independent memory accesses, which gives some of Argon2i's resistance to side-channel cache timing attacks and much of Argon2d's resistance to GPU cracking attacks
public enum CatArgon2ContextMode: Int {
    case Argon2d = 0
    case Argon2i = 1
    case Argon2id = 2
}

/// CatArgon2Context is the context and it descript what you want to hash with Argon2
public class CatArgon2Context {
    
    /// The running time independently of the memory size
    public var iterations: Int = 3
    
    /// The memory usage
    public var memory: Int = 1 << 12
    
    /// Parallelism threads
    public var parallelism: Int = 1
    
    /// The mode of Argon2
    public var mode: CatArgon2ContextMode = CatArgon2ContextMode.Argon2i
    
    /// The salt to use, at least 8 characters
    public var salt: String = UUID().uuidString
    
    /// Hash output length
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
