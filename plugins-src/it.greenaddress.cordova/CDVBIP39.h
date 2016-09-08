//
//  CDVBIP39.h
//  GreenAddress
//

#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>

@interface CDVBIP39 : CDVPlugin {}

- (void)calcSeed:(CDVInvokedUrlCommand*)command;

@end
