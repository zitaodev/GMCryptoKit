//
//  GMUtilities.h
//  GMCryptoKit
//
//  Created by Joe's Laptop on 2024/4/15.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GMUtilities : NSObject

+ (NSData *_Nullable)hexStringToData:(NSString *)hexString;

+ (NSString *_Nullable)dataToHexString:(NSData *)data;

+ (NSString *_Nullable)stringToHexString:(NSString *)string;

+ (NSString *_Nullable)hexStringToString:(NSString *)hexString;

+ (NSData *_Nullable)stringToData:(NSString *)string;

+ (NSString *_Nullable)dataToBase64String:(NSData *)data;

+ (NSData *_Nullable)base64StringToData:(NSString *)base64String;
@end

NS_ASSUME_NONNULL_END
