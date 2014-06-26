//
//  CDVBIP32.h
//  GreenAddress.It
//

#import <Cordova/CDVPlugin.h>

@interface CDVBIP32 : CDVPlugin {}

- (void)seedToKey:(CDVInvokedUrlCommand*)command;
- (void)derive:(CDVInvokedUrlCommand*)command;

@end
