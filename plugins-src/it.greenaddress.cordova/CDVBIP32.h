//
//  CDVBIP32.h
//  GreenAddress
//

#import <Cordova/CDVPlugin.h>

@interface CDVBIP32 : CDVPlugin {}

- (void)seedToKey:(CDVInvokedUrlCommand*)command;
- (void)derive:(CDVInvokedUrlCommand*)command;

@end
