//
//  GMCryptoKitTests.m
//  GMCryptoKitTests
//
//  Created by zitaodev's Laptop on 2024/3/16.
//

#import <XCTest/XCTest.h>
#import "GMCryptoKit.h"

@interface GMCryptoKitTests : XCTestCase

@property (nonatomic, copy) NSData *pubKey;  // 公钥
@property (nonatomic, copy) NSData *priKey;  // 私钥
@property (nonatomic, copy) NSData *plaintextData;  // 原文
@property (nonatomic, copy) NSData *ciphertextData;  // 密文

@end

@implementation GMCryptoKitTests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
    
    NSDictionary<NSString *, NSData *> *keyPair = [GMSm2Cryptor gm_createSm2KeyPair];
    self.pubKey = keyPair[@"publicKey"];
    self.priKey = keyPair[@"privateKey"];
    
    self.plaintextData = [GMRandomGenerator gm_secRandomDataWithLength:16];
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    self.pubKey = nil;
    self.priKey = nil;
    self.plaintextData = nil;
    self.ciphertextData = nil;
}

- (void)testExample {
    
    // 1、测试生成的随机数不为空
    for (int i = 0; i < 1000; i++) {
        NSData *randomData = [GMRandomGenerator gm_secRandomDataWithLength: i + 1];
        XCTAssertNotNil(randomData, @"生成的随机数不能为空");
    }
    
    // 2、测试生成的密钥对不为空
    for (int i = 0; i < 1000; i++) {
        // 生成公私钥
        NSDictionary<NSString *, NSData *> *keyPair = [GMSm2Cryptor gm_createSm2KeyPair];
        NSData *publicKey = keyPair[@"publicKey"];
        NSData *privateKey = keyPair[@"privateKey"];
        XCTAssertNotNil(publicKey, @"生成公钥不能为空");
        XCTAssertNotNil(privateKey, @"生成私钥不能为空");
    }
    
    // 3、测试SM2加解密
    for (int i = 0; i < 1000; i++) {
        // 加密
        NSData *ciphertextData = [GMSm2Cryptor gm_sm2EncryptData:self.plaintextData withPublicKey:self.pubKey];
        XCTAssertNotNil(ciphertextData, @"密文不能为空");
        // 解密
        NSData *decryptedData = [GMSm2Cryptor gm_sm2DecryptData:ciphertextData withPrivateKey:self.priKey];
        XCTAssertTrue([decryptedData isEqualToData:self.plaintextData], @"解密结果与原文需一致");
    }
    
    // 4、测试SM2签名和验签
    for (int i = 0; i < 1000; i++) {
        // 数字签名
        NSData *signatureData = [GMSm2Cryptor gm_sm2SignData:self.plaintextData withPrivateKey:self.priKey];
        XCTAssertNotNil(signatureData, @"数字签名不能为空");
        // 签名验签
        BOOL isSignatureValid = [GMSm2Cryptor gm_sm2VerifySignature:signatureData forData:self.plaintextData withPublicKey:self.pubKey];
        XCTAssertTrue(isSignatureValid, @"签名验签需成功");
    }
    
    // 5、测试SM3提取摘要
    for (int i = 0; i < 1000; i++) {
        // 提取摘要
        NSData *digestData = [GMSm3Digest gm_sm3DigestWithData:self.plaintextData];
        XCTAssertNotNil(digestData, @"摘要值不能为空");
    }
}

- (void)testPerformanceSm3Digest {
    NSData *plaintextData = [@"123456" dataUsingEncoding:NSUTF8StringEncoding];
    [self measureBlock:^{
        // 提取摘要
        NSData *digestData = [GMSm3Digest gm_sm3DigestWithData:plaintextData];
        XCTAssertTrue(digestData,  @"摘要值不能为空");
    }];
}

- (void)testPerformanceSm2Verify {
    NSData *plaintextData = [@"123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signatureData = [GMSm2Cryptor gm_sm2SignData:plaintextData withPrivateKey:self.priKey];
    [self measureBlock:^{
        // 签名验签
        BOOL isSignatureValid = [GMSm2Cryptor gm_sm2VerifySignature:signatureData forData:plaintextData withPublicKey:self.pubKey];
        XCTAssertTrue(isSignatureValid, @"签名验签需成功");
    }];
}

- (void)testPerformanceSm2Sign {
    NSData *plaintextData = [@"123456" dataUsingEncoding:NSUTF8StringEncoding];
    [self measureBlock:^{
        // 数字签名
        NSData *signatureData = [GMSm2Cryptor gm_sm2SignData:plaintextData withPrivateKey:self.priKey];
        XCTAssertNotNil(signatureData, @"数字签名不能为空");
    }];
}

- (void)testPerformanceSm2Decrypt {
    NSData *plaintextData = [@"123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ciphertextData = [GMSm2Cryptor gm_sm2EncryptData:plaintextData withPublicKey:self.pubKey];
    [self measureBlock:^{
        // 解密
        NSData *decryptedData = [GMSm2Cryptor gm_sm2DecryptData:ciphertextData withPrivateKey:self.priKey];
        XCTAssertTrue([decryptedData isEqualToData:plaintextData], @"解密结果与原文需一致");
    }];
}

- (void)testPerformanceSm2Encrypt {
    NSData *plaintextData = [@"123456" dataUsingEncoding:NSUTF8StringEncoding];
    [self measureBlock:^{
        // 加密
        NSData *ciphertextData = [GMSm2Cryptor gm_sm2EncryptData:plaintextData withPublicKey:self.pubKey];
        XCTAssertNotNil(ciphertextData, @"密文不能为空");
    }];
}

- (void)testPerformanceSm2KeyPairGenerate {
    [self measureBlock:^{
        // 生成公私钥
        NSDictionary<NSString *, NSData *> *keyPair = [GMSm2Cryptor gm_createSm2KeyPair];
        NSData *publicKey = keyPair[@"publicKey"];
        NSData *privateKey = keyPair[@"privateKey"];
        XCTAssertNotNil(publicKey, @"生成公钥不能为空");
        XCTAssertNotNil(privateKey, @"生成私钥不能为空");
    }];
}

- (void)testPerformanceRandomGenerator {
    [self measureBlock:^{
        // 生成随机数
        NSUInteger length = 1 + arc4random() % 100;
        NSData *randomData = [GMRandomGenerator gm_secRandomDataWithLength:length];
        XCTAssertNotNil(randomData, @"生成的随机数不能为空");
    }];
}

@end
