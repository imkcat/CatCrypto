//
//  Argon2ViewController.swift
//  CatCrypto
//
//  Created by Kcat on 2017/12/10.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import UIKit
import CatCrypto

class Argon2ViewController: UIViewController {
    @IBOutlet weak var saltTextField: UITextField!
    @IBOutlet weak var passwordTextField: UITextField!
    @IBOutlet weak var hashTextView: UITextView!
    
    let argon2Crypto = CatArgon2Crypto()
    var argon2Mode: CatArgon2ContextMode = .Argon2i {
        didSet {
            switch argon2Mode {
            case .Argon2d:
                title = "Argon2d"
            case .Argon2i:
                title = "Argon2i"
            case .Argon2id:
                title = "Argon2id"
            }
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        argon2Mode = .Argon2i
    }
    
    @IBAction func modeAction(_ sender: Any) {
        let alertController = UIAlertController(title: "Mode switch", message: nil, preferredStyle: .actionSheet)
        alertController.addAction(UIAlertAction(title: "Argon2d", style: .default, handler: { (alertAction) in
            self.argon2Mode = .Argon2d
        }))
        alertController.addAction(UIAlertAction(title: "Argon2i", style: .default, handler: { (alertAction) in
            self.argon2Mode = .Argon2i
        }))
        alertController.addAction(UIAlertAction(title: "Argon2id", style: .default, handler: { (alertAction) in
            self.argon2Mode = .Argon2id
        }))
        self.present(alertController, animated: true, completion: nil)
    }
    
    @IBAction func hashAction(_ sender: Any) {
        passwordTextField.resignFirstResponder()
        
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
    
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }


}

