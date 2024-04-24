//
//  GMRandomGenerator.m
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/15.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import "GMRandomGenerator.h"

@implementation GMRandomGenerator

+ (NSData *_Nullable)secRandomDataWithLength:(NSUInteger)length {
    NSParameterAssert(length > 0);
    
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int status = SecRandomCopyBytes(kSecRandomDefault, length, [data mutableBytes]);
    return (status == errSecSuccess? data: nil);
}
@end
