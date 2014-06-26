//
//  CDVAES.h
//  GreenAddress.It
//

#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>

@interface CDVAES : CDVPlugin {}

- (void)encrypt:(CDVInvokedUrlCommand*)command;
- (void)decrypt:(CDVInvokedUrlCommand*)command;

@end
