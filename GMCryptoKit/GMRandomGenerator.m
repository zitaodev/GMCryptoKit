//
//  GMRandomGenerator.m
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/15.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import "GMRandomGenerator.h"

@implementation GMRandomGenerator

+ (NSData *)randomDataWithLength:(NSUInteger)length {
    if (length == 0) {
        return nil;
    }
    
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int status = SecRandomCopyBytes(kSecRandomDefault, length, [data mutableBytes]);
    return (status == errSecSuccess? data: nil);
}
@end
