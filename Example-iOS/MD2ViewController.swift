//
//  MD2ViewController.swift
//  Example-iOS
//
//  Created by Kcat on 2017/12/23.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import UIKit
import CatCrypto

class MD2ViewController: UIViewController {
    
    @IBOutlet weak var passwordTextField: UITextField!
    
    let md2Crypto = CatMD2Crypto()
    
    override func viewDidLoad() {
        super.viewDidLoad()

        // Do any additional setup after loading the view.
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    @IBAction func hashAction(_ sender: Any) {
        let hashResult = md2Crypto.hash(password: passwordTextField.text ?? "")
        let resultViewController = UIStoryboard(name: "Main", bundle: nil).instantiateViewController(withIdentifier: "ResultViewController") as! ResultViewController
        resultViewController.result = hashResult.value
        self.navigationController?.pushViewController(resultViewController, animated: true)
    }
    

    /*
    // MARK: - Navigation

    // In a storyboard-based application, you will often want to do a little preparation before navigation
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        // Get the new view controller using segue.destinationViewController.
        // Pass the selected object to the new view controller.
    }
    */

}
