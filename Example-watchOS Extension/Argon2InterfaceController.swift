//
//  Argon2InterfaceController.swift
//  Example-watchOS Extension
//
//  Created by Kcat on 2017/12/17.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import WatchKit
import Foundation
import CatCrypto

class Argon2InterfaceController: WKInterfaceController {

    @IBOutlet var argon2Table: WKInterfaceTable!
    let argon2Crypto = CatArgon2Crypto()
    
    override func awake(withContext context: Any?) {
        super.awake(withContext: context)
        layoutInit()
    }
    
    func layoutInit() {
        argon2Table.setNumberOfRows(3, withRowType: "RootRowType")
        
        (argon2Table.rowController(at: 0) as! BaseRowController).titleLabel.setText("Argon2d")
        (argon2Table.rowController(at: 1) as! BaseRowController).titleLabel.setText("Argon2i")
        (argon2Table.rowController(at: 2) as! BaseRowController).titleLabel.setText("Argon2id")
    }

    override func table(_ table: WKInterfaceTable, didSelectRowAt rowIndex: Int) {
        switch rowIndex {
        case 0:
            argon2Crypto.context.mode = .Argon2d
        case 1:
            argon2Crypto.context.mode = .Argon2i
        case 2:
            argon2Crypto.context.mode = .Argon2id
        default:
            break
        }
        argon2Crypto.hash(password: UUID().uuidString, completeHandler: { (hashResult) in
            if hashResult.error == nil {
                self.pushController(withName: "ResultInterfaceController", context: hashResult.value)
            } else {
                self.pushController(withName: "ResultInterfaceController", context: hashResult.error?.errorDescription)
            }
        })
    }
    
    override func willActivate() {
        // This method is called when watch view controller is about to be visible to user
        super.willActivate()
    }

    override func didDeactivate() {
        // This method is called when watch view controller is no longer visible
        super.didDeactivate()
    }

}
