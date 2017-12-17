//
//  Argon2ViewController.swift
//  Example-tvOS
//
//  Created by Kcat on 2017/12/16.
//  Copyright © 2017年 imkcat. All rights reserved.
//
// https://github.com/ImKcat/CatCrypto
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

import Foundation
import UIKit
import CatCrypto

class Argon2ViewController: UIViewController {
    @IBOutlet weak var modeSegmentedControl: UISegmentedControl!
    @IBOutlet weak var passwordTextField: UITextField!
    @IBOutlet weak var saltTextField: UITextField!
    @IBOutlet weak var hashTextView: UITextView!
    
    let argon2Crypto = CatArgon2Crypto()
    var argon2Mode: CatArgon2ContextMode = .Argon2i {
        didSet {
            modeSegmentedControl.selectedSegmentIndex = argon2Mode.rawValue
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        argon2Mode = .Argon2i
    }
    
    @IBAction func modeSwitch(_ sender: Any) {
        argon2Mode = CatArgon2ContextMode(rawValue: (sender as! UISegmentedControl).selectedSegmentIndex)!
    }
    
    @IBAction func hashAction(_ sender: Any) {
        argon2Crypto.context.salt = saltTextField.text ?? ""
        argon2Crypto.context.mode = argon2Mode
        argon2Crypto.hash(password: passwordTextField.text ?? "", completeHandler: { (hashResult) in
            if hashResult.error == nil {
                self.hashTextView.text = hashResult.value!
            } else {
                self.hashTextView.text = hashResult.error!.errorDescription!
            }
        })
    }
}
