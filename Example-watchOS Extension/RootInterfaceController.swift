//
//  RootInterfaceController.swift
//  Example-watchOS Extension
//
//  Created by Kcat on 2017/12/17.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import WatchKit
import Foundation


class RootInterfaceController: WKInterfaceController {
    
    @IBOutlet var cryptoTable: WKInterfaceTable!
    
    override func awake(withContext context: Any?) {
        super.awake(withContext: context)
        layoutInit()
    }
    
    func layoutInit() {
        cryptoTable.setNumberOfRows(1, withRowType: "RootRowType")
        
        (cryptoTable.rowController(at: 0) as! BaseRowController).titleLabel.setText("Argon2")
        
    }
    
    override func table(_ table: WKInterfaceTable, didSelectRowAt rowIndex: Int) {
        switch rowIndex {
        case 0:
            self.pushController(withName: "Argon2InterfaceController", context: nil)
        default:
            break
        }
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
