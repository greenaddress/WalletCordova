//
//  CDVTouchId.swift
//  GreenAddress
//
//  Created by Jerzy K on 27/12/15.
//
//

import Foundation
import LocalAuthentication

@objc(CDVTouchId) class CDVTouchId : CDVPlugin {
    func isAvailable(_ command: CDVInvokedUrlCommand) {
        
        let ctx = LAContext()
        var touchIDError : NSError?
        
        let available = ctx.canEvaluatePolicy(
            LAPolicy.deviceOwnerAuthenticationWithBiometrics,
            error:&touchIDError
        )
        
        let pluginResult = CDVPluginResult(
            status: CDVCommandStatus_OK,
            messageAs: available
        )
        commandDelegate!.send(
            pluginResult, callbackId:command.callbackId
        )
    }
    
    func setSecret(_ command: CDVInvokedUrlCommand) {
        let keychain = Keychain()
        DispatchQueue.global(priority: DispatchQueue.GlobalQueuePriority.default).async {
            do {
                // Should be the secret invalidated when passcode is removed? If not then use `.WhenUnlocked`
                try keychain
                    .accessibility(.whenPasscodeSetThisDeviceOnly, authenticationPolicy: .userPresence)
                    .authenticationPrompt("Authenticate to update your access token")
                    .set(
                        command.argument(at: 0) as! NSString as String,
                        key: "pin"
                    )
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_OK
                )
                self.commandDelegate!.send(
                    pluginResult, callbackId: command.callbackId
                )
            } catch let error {
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_ERROR
                )
                self.commandDelegate!.send(
                    pluginResult, callbackId: command.callbackId
                )
            }
        }
    }
    
    func getSecret(_ command: CDVInvokedUrlCommand) {
        let keychain = Keychain()
        DispatchQueue.global(priority: DispatchQueue.GlobalQueuePriority.default).async {
            do {
                // Should be the secret invalidated when passcode is removed? If not then use `.WhenUnlocked`
                let password = try keychain
                    .accessibility(.whenPasscodeSetThisDeviceOnly, authenticationPolicy: .userPresence)
                    .authenticationPrompt("Authenticate to log in")
                    .get("pin")
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_OK,
                    messageAs: password
                )
                self.commandDelegate!.send(
                    pluginResult, callbackId: command.callbackId
                )
            } catch let error {
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_ERROR
                )
                self.commandDelegate!.send(
                    pluginResult, callbackId: command.callbackId
                )
            }
        }
    }
    
    func removeSecret(_ command: CDVInvokedUrlCommand) {
        let keychain = Keychain()
        DispatchQueue.global(priority: DispatchQueue.GlobalQueuePriority.default).async {
            do {
                // Should be the secret invalidated when passcode is removed? If not then use `.WhenUnlocked`
                try keychain.remove("pin");
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_OK
                )
                self.commandDelegate!.send(
                    pluginResult, callbackId: command.callbackId
                )
            } catch let error {
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_ERROR
                )
                self.commandDelegate!.send(
                    pluginResult, callbackId: command.callbackId
                )
            }
        }
    }

}
