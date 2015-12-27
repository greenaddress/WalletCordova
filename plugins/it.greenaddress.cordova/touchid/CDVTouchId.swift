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
    func isAvailable(command: CDVInvokedUrlCommand) {
        
        let ctx = LAContext()
        var touchIDError : NSError?
        
        let available = ctx.canEvaluatePolicy(
            LAPolicy.DeviceOwnerAuthenticationWithBiometrics,
            error:&touchIDError
        )
        
        let pluginResult = CDVPluginResult(
            status: CDVCommandStatus_OK,
            messageAsBool: available
        )
        commandDelegate!.sendPluginResult(
            pluginResult, callbackId:command.callbackId
        )
    }
    
    func setSecret(command: CDVInvokedUrlCommand) {
        let keychain = Keychain()
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)) {
            do {
                // Should be the secret invalidated when passcode is removed? If not then use `.WhenUnlocked`
                try keychain
                    .accessibility(.WhenPasscodeSetThisDeviceOnly, authenticationPolicy: .UserPresence)
                    .authenticationPrompt("Authenticate to update your access token")
                    .set(
                        command.argumentAtIndex(0) as! NSString as String,
                        key: "pin"
                    )
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_OK
                )
                self.commandDelegate!.sendPluginResult(
                    pluginResult, callbackId: command.callbackId
                )
            } catch let error {
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_ERROR
                )
                self.commandDelegate!.sendPluginResult(
                    pluginResult, callbackId: command.callbackId
                )
            }
        }
    }
    
    func getSecret(command: CDVInvokedUrlCommand) {
        let keychain = Keychain()
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)) {
            do {
                // Should be the secret invalidated when passcode is removed? If not then use `.WhenUnlocked`
                let password = try keychain
                    .accessibility(.WhenPasscodeSetThisDeviceOnly, authenticationPolicy: .UserPresence)
                    .authenticationPrompt("Authenticate to log in")
                    .get("pin")
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_OK,
                    messageAsString: password
                )
                self.commandDelegate!.sendPluginResult(
                    pluginResult, callbackId: command.callbackId
                )
            } catch let error {
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_ERROR
                )
                self.commandDelegate!.sendPluginResult(
                    pluginResult, callbackId: command.callbackId
                )
            }
        }
    }
    
    func removeSecret(command: CDVInvokedUrlCommand) {
        let keychain = Keychain()
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)) {
            do {
                // Should be the secret invalidated when passcode is removed? If not then use `.WhenUnlocked`
                try keychain.remove("pin");
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_OK
                )
                self.commandDelegate!.sendPluginResult(
                    pluginResult, callbackId: command.callbackId
                )
            } catch let error {
                let pluginResult = CDVPluginResult(
                    status: CDVCommandStatus_ERROR
                )
                self.commandDelegate!.sendPluginResult(
                    pluginResult, callbackId: command.callbackId
                )
            }
        }
    }

}