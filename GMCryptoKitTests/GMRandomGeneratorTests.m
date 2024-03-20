//
//  GMRandomGeneratorTests.m
//  GMCryptoKitTests
//
//  Created by Joe's Laptop on 2024/3/20.
//  Copyright © 2024 zitaodev. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "GMCryptoKit.h"

@interface GMRandomGeneratorTests : XCTestCase

@end

@implementation GMRandomGeneratorTests

- (void)testRandomGenerator {
    NSInteger length = 16;
    NSData *randomData = [GMRandomGenerator gm_secRandomDataWithLength:length];
    XCTAssertNotNil(randomData, @"生成随机字节序列不能为空");
    XCTAssertEqual(randomData.length, length, @"生成随机字节序列字节长度与预期字节长度需一致");
}

- (void)testRandomGeneratorUnique {
    const NSInteger numberOfRandomDatas = 1000;
    const NSInteger length = 16;
    NSMutableSet<NSData *> *randomDataSet = [NSMutableSet set];

    for (NSInteger i = 0; i < numberOfRandomDatas; i++) {
        NSData *randomData = [GMRandomGenerator gm_secRandomDataWithLength:length];
        assert(randomData != nil);
        
        [randomDataSet addObject:randomData];
    }

    XCTAssertEqual(randomDataSet.count, numberOfRandomDatas, @"生成随机字节序列需唯一");
}

- (void)testRandomGeneratorThrows {
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wnonnull"
    XCTAssertThrows((void) [GMRandomGenerator gm_secRandomDataWithLength:0]);
    #pragma clang diagnostic pop
}

- (void)testPerformanceRandomGenerator {
    [self measureBlock:^{
        const NSInteger numberOfRandomDatas = 1000;
        const NSInteger length = 16;
        for (NSInteger i = 0; i < numberOfRandomDatas; i++) {
            NSData *randomData = [GMRandomGenerator gm_secRandomDataWithLength:length];
            XCTAssertNotNil(randomData, @"生成随机字节序列不能为空");
        }
    }];
}

@end
