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
    self.view.backgroundColor = [UIColor whiteColor];
    
    NSMutableString *logStr = [NSMutableString stringWithString:@""];
    // 生成指定字节的加密安全随机数
    NSData *randomData = [GMRandomGenerator gm_secRandomDataWithLength:16];
    [logStr appendString:@"\n-------安全随机数-------"];
    [logStr appendFormat:@"\n随机数：%@", randomData];
    
    // 生成SM2密钥对
    NSDictionary *keyPair = [GMSm2Cryptor gm_createSm2KeyPair];
    NSData *publicKey = keyPair[@"publicKey"];
    NSData *privateKey = keyPair[@"privateKey"];
    
    
    // 加密和解密
    NSData *plaintextData = [GMRandomGenerator gm_secRandomDataWithLength:12];// 待加密的原文Data数据
    NSData *ciphertextData = [GMSm2Cryptor gm_sm2EncryptData:plaintextData withPublicKey:publicKey];
    NSData *decryptedData = [GMSm2Cryptor gm_sm2DecryptData:ciphertextData withPrivateKey:privateKey];
    
    [logStr appendString:@"\n-------SM2加密与解密-------"];
    [logStr appendFormat:@"\nSM2明文：%@", plaintextData];
    [logStr appendFormat:@"\nSM2公钥：%@", publicKey];
    [logStr appendFormat:@"\nSM2私钥：%@", privateKey];
    [logStr appendFormat:@"\nSM2加密密文：%@", ciphertextData];
    [logStr appendFormat:@"\nSM2解密结果：%@", decryptedData];
    
    // 数字签名和验证
    NSData *messageData = [GMRandomGenerator gm_secRandomDataWithLength:36]; // 待签名的数据
    NSData *signatureData = [GMSm2Cryptor gm_sm2SignData:messageData withPrivateKey:privateKey];
    BOOL isSignatureValid = [GMSm2Cryptor gm_sm2VerifySignature:signatureData forData:messageData withPublicKey:publicKey];

    [logStr appendString:@"\n-------SM2签名与验签-------"];
    [logStr appendFormat:@"\nSM2签名消息：%@", messageData];
    [logStr appendFormat:@"\nSM2公钥：%@", publicKey];
    [logStr appendFormat:@"\nSM2私钥：%@", privateKey];
    [logStr appendFormat:@"\nSM2数字签名：%@", signatureData];
    [logStr appendFormat:@"\nSM2验签结果：%@", isSignatureValid ? @"验签成功" : @"验签失败"];
    
    // SM3提取摘要
    NSData *mesData = [@"hello world!" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *digestData = [GMSm3Digest gm_sm3DigestWithData:mesData];
    [logStr appendString:@"\n-------SM3提取摘要-------"];
    [logStr appendFormat:@"\nSM3待提取消息：%@", mesData];
    [logStr appendFormat:@"\nSM3摘要值：%@", digestData];
    
    NSLog(@"%@", logStr);
}

@end
