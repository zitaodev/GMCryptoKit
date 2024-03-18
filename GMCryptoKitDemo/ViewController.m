//
//  ViewController.m
//  GMCryptoKit
//
//  Created by zitaodev's Laptop on 2024/3/14.
//

#import "ViewController.h"
#import <GMCryptoKit/GMCryptoKit.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // 生成SM2密钥对
    NSDictionary *keyPair = [GMSm2Cryptor gm_createSm2KeyPair];
    NSData *publicKey = keyPair[@"publicKey"];
    NSData *privateKey = keyPair[@"privateKey"];
    
    
    // 加密和解密
    NSData *plaintextData = [GMRandomGenerator randomDataWithLength:12];// 待加密的原文Data数据
    NSData *ciphertextData = [GMSm2Cryptor gm_sm2EncryptData:plaintextData withPublicKey:publicKey];
    NSData *decryptedData = [GMSm2Cryptor gm_sm2DecryptData:ciphertextData withPrivateKey:privateKey];
    
    NSMutableString *encAndDecStr = [NSMutableString stringWithString:@""];
    [encAndDecStr appendString:@"\n-------SM2加密与解密-------"];
    [encAndDecStr appendFormat:@"\nSM2明文：%@", plaintextData];
    [encAndDecStr appendFormat:@"\nSM2公钥：%@", publicKey];
    [encAndDecStr appendFormat:@"\nSM2私钥：%@", privateKey];
    [encAndDecStr appendFormat:@"\nSM2加密密文：%@", ciphertextData];
    [encAndDecStr appendFormat:@"\nSM2解密结果：%@", decryptedData];
    NSLog(@"%@", encAndDecStr);
    
    // 数字签名和验证
    NSData *messageData = [GMRandomGenerator randomDataWithLength:36]; // 待签名的数据
    NSData *signatureData = [GMSm2Cryptor gm_sm2SignData:messageData withPrivateKey:privateKey];
    BOOL isSignatureValid = [GMSm2Cryptor gm_sm2VerifySignature:signatureData forData:messageData withPublicKey:publicKey];

    NSMutableString *sigAndVerStr = [NSMutableString stringWithString:@""];
    [sigAndVerStr appendString:@"\n-------SM2签名与验签-------"];
    [sigAndVerStr appendFormat:@"\nSM2签名消息：%@", messageData];
    [sigAndVerStr appendFormat:@"\nSM2公钥：%@", publicKey];
    [sigAndVerStr appendFormat:@"\nSM2私钥：%@", privateKey];
    [sigAndVerStr appendFormat:@"\nSM2数字签名：%@", signatureData];
    [sigAndVerStr appendFormat:@"\nSM2验签结果：%@", isSignatureValid ? @"验签成功" : @"验签失败"];
    NSLog(@"%@", encAndDecStr);
}

@end
