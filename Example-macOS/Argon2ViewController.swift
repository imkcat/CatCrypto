//
//  Argon2ViewController.swift
//  Example-macOS
//
//  Created by Kcat on 2017/12/15.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import Cocoa
import CatCrypto

class Argon2ViewController: NSViewController {

    @IBOutlet weak var passwordTextField: NSTextField!
    @IBOutlet weak var modeComboBox: NSComboBox!
    @IBOutlet weak var saltTextField: NSTextField!
    @IBOutlet var hashTextView: NSTextView!
    
    let argon2Crypto = CatArgon2Crypto()
    var argon2Mode: CatArgon2ContextMode = .Argon2i {
        didSet {
            modeComboBox.selectItem(at: argon2Mode.rawValue)
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        argon2Mode = .Argon2i
    }
    
    @IBAction func hashAction(_ sender: Any) {
        argon2Crypto.context.salt = saltTextField.stringValue
        argon2Crypto.context.mode = argon2Mode
        argon2Crypto.hash(password: passwordTextField.stringValue, completeHandler: { (hashResult) in
            if hashResult.error == nil {
                self.hashTextView.string = hashResult.value!
            } else {
                self.hashTextView.string = hashResult.error!.errorDescription!
            }
        })
    }
    
    @IBAction func modeSwitch(_ sender: Any) {
        argon2Mode = CatArgon2ContextMode(rawValue: (sender as! NSComboBox).indexOfSelectedItem)!
    }
}
