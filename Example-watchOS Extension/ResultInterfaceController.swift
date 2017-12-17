//
//  ResultInterfaceController.swift
//  Example-watchOS Extension
//
//  Created by Kcat on 2017/12/17.
//  Copyright © 2017年 imkcat. All rights reserved.
//

import WatchKit
import Foundation


class ResultInterfaceController: WKInterfaceController {
    @IBOutlet var resultLabel: WKInterfaceLabel!
    
    override func awake(withContext context: Any?) {
        super.awake(withContext: context)
        if context is String {
            resultLabel.setText(context as? String)
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
