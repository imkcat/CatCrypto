//
//  ViewController.swift
//  CatCrypto
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        let argon2Crypto = CatArgon2Crypto()
        argon2Crypto.context.mode = .Argon2i
        
        var timeCount = 0.00
        let timer = DispatchSource.makeTimerSource()
        timer.schedule(deadline: DispatchTime.now(), repeating: 0.01)
        timer.setEventHandler {
            timeCount += 0.01
        }
        timer.resume()
        
        print("Let's hash 50 UUID string with argon2 in 2i mode")
        
        for _ in 1...50 {
            argon2Crypto.context.salt = UUID().uuidString
            argon2Crypto.hash(password: UUID().uuidString, completeHandler: { (hashResult) in
                if hashResult.error == nil {
                    print(hashResult.value!)
                } else {
                    print(hashResult.error!.errorDescription!)
                }
            })
        }
        timer.cancel()
        
        print("Hash job is done!")
        print(String(format: "Time: %0.2fs", timeCount))
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

