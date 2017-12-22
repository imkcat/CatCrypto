//
//  MessageDigestViewController.swift
//  Example-iOS
//
//  Created by Kcat on 2017/12/17.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import UIKit
import CatCrypto

class MessageDigestViewController: UIViewController {

    @IBOutlet weak var passwordTextField: UITextField!
    let messageDigestCrypto = CatMessageDigestCrypto()
    var messageDigestMode: CatMessageDigestContextMode = .MD5 {
        didSet {
            switch messageDigestMode {
            case .MD2:
                title = "MD2"
            case .MD4:
                title = "MD4"
            case .MD5:
                title = "MD5"
            case .MD6:
                title = "MD6"
            }
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        messageDigestMode = .MD5
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    @IBAction func switchMode(_ sender: Any) {
        let alertController = UIAlertController(title: "Mode switch", message: nil, preferredStyle: .actionSheet)
        alertController.addAction(UIAlertAction(title: "MD2", style: .default, handler: { (alertAction) in
            self.messageDigestMode = .MD2
        }))
        alertController.addAction(UIAlertAction(title: "MD4", style: .default, handler: { (alertAction) in
            self.messageDigestMode = .MD4
        }))
        alertController.addAction(UIAlertAction(title: "MD5", style: .default, handler: { (alertAction) in
            self.messageDigestMode = .MD5
        }))
        alertController.addAction(UIAlertAction(title: "MD6", style: .default, handler: { (alertAction) in
            self.messageDigestMode = .MD6
        }))
        alertController.addAction(UIAlertAction(title: "Cancel", style: .cancel, handler: { (alertAction) in
            alertController.dismiss(animated: true, completion: nil)
        }))
        self.present(alertController, animated: true, completion: nil)
    }
    
    @IBAction func hashAction(_ sender: Any) {
        messageDigestCrypto.context.mode = messageDigestMode
        let hashResult = messageDigestCrypto.hash(password: passwordTextField.text ?? "")
        let resultViewController = UIStoryboard(name: "Main", bundle: nil).instantiateViewController(withIdentifier: "ResultViewController") as! ResultViewController
        resultViewController.result = hashResult.value
        self.navigationController?.pushViewController(resultViewController, animated: true)
    }

}
