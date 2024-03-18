//
//  AppDelegate.m
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/14.
//

#import "AppDelegate.h"
#import "ViewController.h"

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // Override point for customization after application launch.
    
    ViewController *mainVC = [[ViewController alloc] init];
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = mainVC;
    [self.window makeKeyAndVisible];
    
    return YES;
}



@end
