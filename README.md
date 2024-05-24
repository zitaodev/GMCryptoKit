# GMCryptoKit
- [GMCryptoKit](#gmcryptokit)
  - [概述](#概述)
  - [项目状态](#项目状态)
    - [已完成功能](#已完成功能)
    - [待完成功能](#待完成功能)
  - [功能特性](#功能特性)
    - [1. 加密安全的随机数](#1-加密安全的随机数)
      - [1.1 使用示例](#11-使用示例)
      - [1.2 生成随机数方法原型](#12-生成随机数方法原型)
    - [2. SM2非对称加密算法](#2-sm2非对称加密算法)
      - [2.1 使用示例](#21-使用示例)
      - [2.2 生成密钥对方法原型](#22-生成密钥对方法原型)
      - [2.3 加密方法原型](#23-加密方法原型)
      - [2.4 解密方法原型](#24-解密方法原型)
      - [2.5 签名方法原型](#25-签名方法原型)
      - [2.6 验签方法原型](#26-验签方法原型)
    - [3. SM3 摘要算法](#3-sm3-摘要算法)
      - [3.1 使用示例](#31-使用示例)
      - [3.2 摘要算法原型](#32-摘要算法原型)
      - [3.3 基于SM3算法的HMAC计算方法原型](#33-基于sm3算法的hmac计算方法原型)
    - [4. SM4 对称加密算法](#4-sm4-对称加密算法)
      - [4.1 使用示例](#41-使用示例)
      - [4.2 生成密钥方法原型](#42-生成密钥方法原型)
      - [4.3 CBC模式（PKCS7Padding）加密方法原型](#43-cbc模式pkcs7padding加密方法原型)
      - [4.4 CBC模式（PKCS7Padding）解密方法原型](#44-cbc模式pkcs7padding解密方法原型)
  - [环境要求](#环境要求)
  - [使用](#使用)
  - [运行示例应用程序](#运行示例应用程序)
  - [运行单元测试](#运行单元测试)
  - [联系我](#联系我)
  - [许可证](#许可证)

## 概述

GMCryptoKit是一个基于[GmSSL](https://github.com/guanzhi/GmSSL)开源库封装的Objective-C国密算法组件，旨在为 iOS 开发者提供国密算法的实现。该密码组建支持生成加密安全的随机数和国密算法（SM2/SM3/SM4/SM9），为 iOS 应用提供了密码学安全的功能支持。

## 项目状态 

### 已完成功能

- **生成加密安全的随机数：** 生成加密安全的随机数。
- **SM2 非对称加密算法：** 非对称加解密、数字签名、验签。
- **SM3 摘要算法：**  提取摘要值、基于哈希的消息认证码（HMAC）。
- **SM4 对称加密算法：** CBC模式（PKCS7Padding）对称加解密。

### 待完成功能

- **SM4 对称加密算法：** CBC（NOPadding）、ECB、CBC、CFB、OFB，CTR、GCM、CCM等模式。
- **SM9 标识密码算法：**  密钥生成、加解密、签名验证。

## 功能特性

### 1. 加密安全的随机数

通过GMCryptoKit，你可以轻松生成指定字节长度的加密安全的随机数，可用于密钥生成、初始化向量IV等场景。

本方法使用的是苹果 Security 框架中提供的API **SecRandomCopyBytes**创建[加密安全随机字节数组](https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc)。

#### 1.1 使用示例

```objective-c
#import <GMCryptoKit/GMCryptoKit.h>

// 生成指定字节的加密安全随机数
NSData *randomData = [GMRandomGenerator gm_secRandomDataWithLength:16];
```

#### 1.2 生成随机数方法原型

```objective-c
/**
 生成指定字节长度的加密安全随机数
 
 @param length 指定的随机数长度
 @return 填充指定字节长度的NSData格式随机数
 */
+ (NSData *_Nullable)secRandomDataWithLength:(NSUInteger)length;
```

### 2. SM2非对称加密算法

GMCryptoKit提供了对SM2算法的支持，包括密钥对生成、加密、解密、数字签名和验证等功能。

#### 2.1 使用示例

```objective-c
#import <GMCryptoKit/GMCryptoKit.h>

// ---------------------- 生成SM2密钥对 ----------------------
// 二进制数据的密钥对
NSArray *keyPairData = [GMSm2Cryptor createSm2DataKeyPair];
NSData *publicKey = keyPairData[0];
NSData *privateKey = keyPairData[1];
// Hex编码字符串的密钥对
NSArray *keyPairHex = [GMSm2Cryptor createSm2HexKeyPair];
NSString *publicKeyHex = keyPairHex[0];
NSString *privateKeyHex = keyPairHex[1];

// ---------------------- SM2加密和解密 ----------------------
// UTF-8编码字符串的加密和解密
NSString *plaintext = @"hello world!";
NSString *base64Ciphertext = [GMSm2Cryptor sm2EncryptText:plaintext withPublicKey:publicKeyHex];
NSString *decryptedtext = [GMSm2Cryptor sm2DecryptText:base64Ciphertext withPrivateKey:privateKeyHex];
// Hex编码字符串的加密和解密
NSString *hexPlaintext = [GMUtilities stringToHexString:plaintext];
NSString *hexCiphertext = [GMSm2Cryptor sm2EncryptHexText:hexPlaintext withPublicKey:publicKeyHex];
NSString *decryptedHextext = [GMSm2Cryptor sm2DecryptHexText:hexCiphertext withPrivateKey:privateKeyHex];
// 二进制数据的加密和解密
NSData *plaintextData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
NSData *ciphertextData = [GMSm2Cryptor sm2EncryptData:plaintextData withPublicKey:publicKey];
NSData *decryptedData = [GMSm2Cryptor sm2DecryptData:ciphertextData withPrivateKey:privateKey];

// ---------------------- SM2数字签名和验证 ----------------------
// UTF-8编码字符串的签名和验签
NSString *message = @"hello world!";
NSString *base64Signature = [GMSm2Cryptor sm2SignText:message withPrivateKey:privateKeyHex];
BOOL isBase64SignatureValid = [GMSm2Cryptor sm2VerifyText:base64Signature forMessage:message withPublicKey:publicKeyHex];
// Hex编码字符串的签名和验签
NSString *hexMessage = [GMUtilities stringToHexString:message];
NSString *hexSignature = [GMSm2Cryptor sm2SignHexText:hexMessage withPrivateKey:privateKeyHex];
BOOL isHexSignatureValid = [GMSm2Cryptor sm2VerifyHexText:hexSignature forMessageHex:hexMessage withPublicKey:publicKeyHex];
// 二进制数据的签名和验签
NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
NSData *signatureData = [GMSm2Cryptor sm2SignData:messageData withPrivateKey:privateKey];
BOOL isSignatureValid = [GMSm2Cryptor sm2VerifyData:signatureData forMessageData:messageData withPublicKey:publicKey];
```

#### 2.2 生成密钥对方法原型

```objective-c
/**
 SM2 生成密钥对，私钥为256bit的大整数(64字节Hex编码字符串或32字节二进制数据)，公钥格式为 X | Y，其中X和Y为256bit大整数(128字节Hex编码字符串或64字节二进制数据)
 
 @return 字典实例密钥对: [0] 为SM2公钥, [1] 为SM2私钥,输出格式分别是Hex编码字符串、二进制数据，失败则返回nil
 */
+ (NSArray<NSString *> *_Nullable)createSm2HexKeyPair;
+ (NSArray<NSData *> *_Nullable)createSm2DataKeyPair;
```

#### 2.3 加密方法原型

```objective-c
/**
 SM2 非对称加密算法，加密
 
 @param plaintext 待加密的内容,输入格式分别是：plaintext UTF-8编码字符串、plaintextHex Hex编码字符串、 plainData 二进制数据
 @param publicKey 公钥,输入格式分别是128字节Hex编码字符串或64字节二进制数据
 @return 密文（04||C1||C3||C2）,输出格式分别是Base64编码字符串、Hex编码字符串、二进制数据;失败则返回nil
 */
+ (NSString *_Nullable)sm2EncryptText:(NSString *)plaintext withPublicKey:(NSString *)publicKey;
+ (NSString *_Nullable)sm2EncryptHexText:(NSString *)plaintextHex withPublicKey:(NSString *)publicKey;
+ (NSData *_Nullable)sm2EncryptData:(NSData *)plainData withPublicKey:(NSData *)publicKey;
```

#### 2.4 解密方法原型

```objective-c
/**
 SM2 非对称加密算法，解密
 
 @param ciphertextBase64 待解密密文（04||C1||C3||C2）,输入格式分别是：ciphertextBase64 Base64编码字符串、ciphertextHex Hex编码字符串、 cipherData 二进制数据
 @param privateKey 私钥,输入格式分别是64字节Hex编码字符串或32字节二进制数据
 @return 解密结果，输出格式分别是UTF-8编码字符串、Hex编码字符串、二进制数据;失败则返回nil
 */
+ (NSString *_Nullable)sm2DecryptText:(NSString *)ciphertextBase64 withPrivateKey:(NSString *)privateKey;
+ (NSString *_Nullable)sm2DecryptHexText:(NSString *)ciphertextHex withPrivateKey:(NSString *)privateKey;
+ (NSData *_Nullable)sm2DecryptData:(NSData *)cipherData withPrivateKey:(NSData *)privateKey;
```

#### 2.5 签名方法原型

```objective-c
/**
 SM2 签名验签算法，签名
 
 @param message 待签名消息,输入格式分别是：message UTF-8编码字符串、messageHex Hex编码字符串、 messageData 二进制数据
 @param privateKey 私钥,输入格式分别是64字节Hex编码字符串或32字节二进制数据
 @return 签名结果，输出格式分别是Base64编码字符串、Hex编码字符串、二进制数据;失败则返回nil
 */
+ (NSString *_Nullable)sm2SignText:(NSString *)message withPrivateKey:(NSString *)privateKey;
+ (NSString *_Nullable)sm2SignHexText:(NSString *)messageHex withPrivateKey:(NSString *)privateKey;
+ (NSData *_Nullable)sm2SignData:(NSData *)messageData withPrivateKey:(NSData *)privateKey;
```

#### 2.6 验签方法原型

```objective-c
/**
 SM2 签名验签算法，验签
 
 @param signatureBase64 签名结果，输入格式分别是：signatureBase64 Base64编码字符串、signatureHex Hex编码字符串、 signatureData 二进制数据
 @param message 待验签内容，输入格式分别是：message UTF-8编码字符串、messageHex Hex编码字符串、 messageData 二进制数据
 @param publicKey 公钥,输入格式分别是128字节Hex编码字符串或64字节二进制数据
 @return 验签结果,YES 表示验签成功,NO 表示验签失败
 */
+ (BOOL)sm2VerifyText:(NSString *)signatureBase64 forMessage:(NSString *)message withPublicKey:(NSString *)publicKey;
+ (BOOL)sm2VerifyHexText:(NSString *)signatureHex forMessageHex:(NSString *)messageHex withPublicKey:(NSString *)publicKey;
+ (BOOL)sm2VerifyData:(NSData *)signatureData forMessageData:(NSData *)messageData withPublicKey:(NSData *)publicKey;
```

### 3. SM3 摘要算法

GMCryptoKit提供了对SM3算法的支持，包括提取摘要、基于哈希的消息认证码（HMAC）等功能。

#### 3.1 使用示例

```objective-c
#import <GMCryptoKit/GMCryptoKit.h>

// ---------------------- SM3提取摘要 ----------------------
// UTF-8编码字符串的摘要提取
NSString *sm3message = @"hello world!";
NSString *sm3DigestBase64 = [GMSm3Digest sm3DigestWithText:sm3message];
// Hex编码字符串的摘要提取
NSString *sm3messageHex = [GMUtilities stringToHexString:sm3message];
NSString *sm3DigestHex = [GMSm3Digest sm3DigestWithHexText:sm3messageHex];
// 二进制数据的摘要提取
NSData *sm3messageData = [GMUtilities stringToData:sm3message];
NSData *sm3DigestData = [GMSm3Digest sm3DigestWithData:sm3messageData];

// ---------------------- 基于SM3计算HMAC ----------------------
// UTF-8编码字符串的HMAC计算
NSString *sm3HmacMessage = @"hello world!";
NSString *hmacKey = [GMUtilities dataToHexString:[GMRandomGenerator secRandomDataWithLength:32]];
NSString *sm3HmacBase64 = [GMSm3Digest hmacSm3DigestWithText:sm3HmacMessage key:hmacKey];
// Hex编码字符串的HMAC计算
NSString *sm3HmacMessageHex = [GMUtilities stringToHexString:sm3HmacMessage];
NSString *sm3HmacHex = [GMSm3Digest hmacSm3DigestWithHexText:sm3HmacMessageHex key:hmacKey];
// 二进制数据的HMAC计算
NSData *sm3HmacMessageData = [GMUtilities stringToData:sm3HmacMessage];
NSData *hmacKeyData = [GMRandomGenerator secRandomDataWithLength:32];
NSData *hmacData = [GMSm3Digest hmacSm3DigestWithData:sm3HmacMessageData key:hmacKeyData];
```

#### 3.2 摘要算法原型

```objective-c
/**
 SM3 摘要算法
 将任意长度的输入数据计算为固定32字节长度的哈希值。
 
 @param plaintext 待计算哈希的数据，输入格式分别是：plaintext UTF-8编码字符串、plaintextHex Hex编码字符串、 plainData 二进制数据
 @return 哈希值，输出格式分别是Base64编码字符串、Hex编码字符串、二进制数据，失败则返回nil
 */
+ (NSString *_Nullable)sm3DigestWithText:(NSString *)plaintext;
+ (NSString *_Nullable)sm3DigestWithHexText:(NSString *)plaintextHex;
+ (NSData *_Nullable)sm3DigestWithData:(NSData *)plainData;
```

#### 3.3 基于SM3算法的HMAC计算方法原型

```objective-c
/**
 基于SM3算法的HMAC计算
 密钥长度建议采用32字节（等同于SM3哈希值的长度），
 不应少于16字节，采用比32字节更长的密钥长度会增加计算开销而不会增加安全性。
 
 @param plaintext 待计算HMAC的数据,输入格式分别是：plaintext UTF-8编码字符串、plainHexText Hex编码字符串、 plainData 二进制数据
 @param key       密钥,输入格式分别是Hex编码字符串或者二进制数据
 @return HMAC值,输出格式分别是Base64编码字符串、Hex编码字符串、二进制数据，失败则返回nil
 */
+ (NSString *_Nullable)hmacSm3DigestWithText:(NSString *)plaintext key:(NSString *)key;
+ (NSString *_Nullable)hmacSm3DigestWithHexText:(NSString *)plaintextHex key:(NSString *)key;
+ (NSData *_Nullable)hmacSm3DigestWithData:(NSData *)plainData key:(NSData *)key;
```



### 4. SM4 对称加密算法

GMCryptoKit提供了对SM4算法的支持，包括生成密钥、CBC模式加解密等功能。

密钥、IV生成格式有两种：Hex编码字符串或者二进制数据，根据需要自行调用

CBC模式加解密使用PKCS#7填充标准，密文输出格式有三种，分别是Base64编码字符串、Hex编码字符串、二进制数据

#### 4.1 使用示例

```objective-c
#import <GMCryptoKit/GMCryptoKit.h>

// ---------------------- 生成密钥和初始化向量 ----------------------
// 二进制数据的密钥和初始化向量
NSData *sm4KeyData = [GMSm4Cryptor createSm4Key];
NSData *sm4IvData = [GMSm4Cryptor createSm4Key];
// Hex编码字符串的密钥和初始化向量
NSString *sm4Key = [GMSm4Cryptor createSm4HexKey];
NSString *sm4Iv = [GMSm4Cryptor createSm4HexKey];

// ---------------------- SM4加密和解密 ----------------------
// UTF-8编码字符串的CBC模式加密和解密
NSString *sm4Plaintext = @"hello, world!";
NSString *sm4CiphertextBase64 = [GMSm4Cryptor sm4CbcPaddingEncryptText:sm4Plaintext withKey:sm4Key withIv:sm4Iv];
NSString *sm4Decryptedtext = [GMSm4Cryptor sm4CbcPaddingDecryptText:sm4CiphertextBase64 withKey:sm4Key withIv:sm4Iv];
// Hex编码字符串的CBC模式加密和解密
NSString *sm4plaintextHex = [GMUtilities stringToHexString:sm4Plaintext];
NSString *sm4CiphertextHex = [GMSm4Cryptor sm4CbcPaddingEncryptHexText:sm4plaintextHex withKey:sm4Key withIv:sm4Iv];
NSString *sm4DecryptedHextext = [GMSm4Cryptor sm4CbcPaddingDecryptHexText:sm4CiphertextHex withKey:sm4Key withIv:sm4Iv];
// 二进制数据的CBC模式加密和解密
NSData *sm4PlaintextData = [GMUtilities stringToData:sm4Plaintext];
NSData *sm4CiphertextData = [GMSm4Cryptor sm4CbcPaddingEncryptData:sm4PlaintextData withKey:sm4KeyData withIv:sm4IvData];
NSData *sm4DecryptedData = [GMSm4Cryptor sm4CbcPaddingDecryptData:sm4CiphertextData withKey:sm4KeyData withIv:sm4IvData];
```

#### 4.2 生成密钥方法原型

```objective-c
/**
 SM4 生成密钥。也可以调用该方法生成SM4 CBC模式的初始化向量iv，iv长度和key长度一致

 @return 密钥，输出格式分别是32字节Hex编码字符串或者16字节的二进制数据
 */
+ (NSString *_Nullable)createSm4HexKey;
+ (NSData *_Nullable)createSm4Key;
```

#### 4.3 CBC模式（PKCS7Padding）加密方法原型

```objective-c
/**
 SM4 对称加解密。CBC模式加密，使用PKCS#7填充标准
 
 @param plaintext 待加密的明文,输入格式分别是：plaintext UTF-8编码字符串、plaintextHex Hex编码字符串、 plainData 二进制数据
 @param key 32字节Hex编码字符串的密钥
 @param iv 32字节Hex编码字符串的初始化向量
 @return 密文,输出格式分别是Base64编码字符串、Hex编码字符串、二进制数据
 */
+ (NSString *_Nullable)sm4CbcPaddingEncryptText:(NSString *)plaintext withKey:(NSString *)key withIv:(NSString *)iv;
+ (NSString *_Nullable)sm4CbcPaddingEncryptHexText:(NSString *)plaintextHex withKey:(NSString *)key withIv:(NSString *)iv;
+ (NSData *_Nullable)sm4CbcPaddingEncryptData:(NSData *)plainData withKey:(NSData *)key withIv:(NSData *)iv;
```

#### 4.4 CBC模式（PKCS7Padding）解密方法原型

```objective-c
/**
 SM4 对称加解密。CBC模式解密，使用PKCS#7填充标准
 
 @param ciphertextBase64 待加密的密文，输入格式分别是：ciphertextBase64 Base64编码字符串、ciphertextHex Hex编码字符串、 cipherData 二进制数据
 @param key 32字节Hex编码字符串的密钥
 @param iv  32字节Hex编码字符串的初始化向量
 @return 解密后的明文,输出格式分别是UTF-8编码字符串、Hex编码字符串、二进制数据
 */
+ (NSString *_Nullable)sm4CbcPaddingDecryptText:(NSString *)ciphertextBase64 withKey:(NSString *)key withIv:(NSString *)iv;
+ (NSString *_Nullable)sm4CbcPaddingDecryptHexText:(NSString *)ciphertextHex withKey:(NSString *)key withIv:(NSString *)iv;
+ (NSData *_Nullable)sm4CbcPaddingDecryptData:(NSData *)cipherData withKey:(NSData *)key withIv:(NSData *)iv;
```

## 环境要求

- GmSSL v3.1.0+
- Xcode 14.3+
- iOS 11.0+

## 使用

- 从 [GitHub](https://github.com/zitaodev/GMCryptoKit) 获取源代码

- 将源代码中 GMCryptoKit 目录导入 App 项目，并选中 ***Copy items if needed***

- 从[GmSSL](https://github.com/guanzhi/GmSSL) 编译获取GmSSL 静态库：libgmssl 和对应的头文件，并添加到 App项目中

- 导入头文件\#import <GMCryptoKit/GMCryptoKit.h>即可调用国密算法


  > 注意：[GmSSL 静态库编译步骤参考](https://github.com/guanzhi/GmSSL/blob/v3.1.0/INSTALL.md)
  >

## 运行示例应用程序

在示例应用中，你可以找到对应功能的用法和实例代码。请参考`GMCryptoKitDemo`目录下的示例应用。

## 运行单元测试

打开示例应用，选择单元测试对应的Scheme`GMCryptoKitTests`,然后按Command-u构建组件并运行单元测试。

## 联系我

如有任何问题或建议，欢迎联系我：

- 邮件：zitaodev@gmail.com
- GitHub：[https://github.com/zitaodev/GMCryptoKit](https://github.com/yourusername/GmSSLCryptoKit)

## 许可证

GmSSLCryptoKit基于MIT许可证开源，详见LICENSE文件。
