//
//  ViewController.swift
//  CatCrypto
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import UIKit
import CatCrypto

class ViewController: UIViewController {

    @IBOutlet weak var passwordTextField: UITextField!
    @IBOutlet weak var hashTextView: UITextView!
    let argon2Crypto = CatArgon2Crypto()
    
    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    @IBAction func hashAction(_ sender: Any) {
        argon2Crypto.hash(password: passwordTextField.text ?? "", completeHandler: { (hashResult) in
            if hashResult.error == nil {
                self.hashTextView.text = hashResult.value!
            } else {
                self.hashTextView.text = hashResult.error!.errorDescription!
            }
        })
    }
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

