//
//  RootViewController.swift
//  Example-iOS
//
//  Created by Kcat on 2017/12/25.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import UIKit
import CatCrypto

class RootViewController: UIViewController {

    let hashAndEncryptQueue = DispatchQueue(label: "com.CatCrypto.HashAndEncryptQueue")

    let sourceString: String = "CatCrypto"

    let hashCryptos: [Hashing] = [CatMD2Crypto(), CatMD4Crypto(), CatMD5Crypto(), CatMD6Crypto(), CatSHA1Crypto(), CatSHA2Crypto(), CatSHA3Crypto(),
                                  CatArgon2Crypto()]

    override func viewDidLoad() {
        super.viewDidLoad()
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
    }

    // MARK: - Actions
    /// Printing CatCrypto infomations.
    func showInfo() {
        let infoDict =  Bundle(identifier: "com.imkcat.CatCrypto-iOS")?.infoDictionary
        let version = infoDict!["CFBundleShortVersionString"] as? String
        print("CatCrypto, Version: " + version! + "\n")
    }

    @IBAction func hashAndEncrypt(_ sender: Any) {
        showInfo()
        for hashCrypto in hashCryptos {
            let hashTimer = DispatchSource.makeTimerSource(queue: DispatchQueue.global())
            hashTimer.schedule(deadline: DispatchTime.now(), repeating: .milliseconds(1))
            var timeCost = 0.000
            hashTimer.setEventHandler(handler: {
                timeCost += 0.001
            })
            let hashWorkItem = DispatchWorkItem(block: {
                hashTimer.resume()
                print("Crypto name: " + String(describing: hashCrypto.self))
                let hashResult = hashCrypto.hash(password: self.sourceString)
                print("Result: " + (hashResult.error == nil ? hashResult.hexStringValue() : hashResult.error!.errorDescription!))
                hashTimer.cancel()
                print("Cost: " + String(format: "%0.3f", timeCost) + "s\n")
            })
            hashAndEncryptQueue.async(execute: hashWorkItem)
        }
    }

}
