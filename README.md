# GMCryptoKit

## 概述

GMCryptoKit是一个基于[GmSSL](https://github.com/guanzhi/GmSSL)开源库封装的Objective-C国密算法组件，旨在为 iOS 开发者提供国密算法的实现。该密码组建支持生成加密安全的随机数和国密算法（SM2/SM3/SM4/SM9），为 iOS 应用提供了密码学安全的功能支持。

## 项目状态 

### 已完成功能：

- **生成加密安全的随机数：**生成加密安全的随机数。
- **SM2 非对称加解密、数字签名和验证：** 非对称加解密、数字签名、验签。
- **SM3 摘要算法：**  提取摘要值、基于哈希的消息认证码（HMAC）。
- **SM4 对称加密算法：** CBC模式（PKCS7Padding）对称加解密。

### 待完成功能：

- **SM4 对称加密算法：** CBC（NOPadding）、ECB、CBC、CFB、OFB，CTR、GCM、CCM等模式。
- **SM9 加密算法：**密钥生成、堆成加密解密、签名验证。

## 功能特性

### 1. 随机数生成

通过GMCryptoKit，你可以轻松生成指定字节长度的加密安全的随机数，可用于密钥生成、初始化向量等场景。

#### 使用示例：

```objective-c
#import <GMCryptoKit/GMCryptoKit.h>

// 生成指定字节的加密安全随机数
NSData *randomData = [GMRandomGenerator gm_secRandomDataWithLength:16];
```

### 2. 非对称国密算法SM2

GMCryptoKit提供了对SM2算法的支持，包括密钥对生成、加密、解密、数字签名和验证等功能。

#### 使用示例：

```objective-c
#import <GMCryptoKit/GMCryptoKit.h>

// 生成SM2密钥对
NSDictionary *keyPair = [GMSm2Cryptor gm_createSm2KeyPair];
NSData *publicKey = keyPair[@"publicKey"];
NSData *privateKey = keyPair[@"privateKey"];

// SM2加密和解密
NSData *plaintextData = [GMRandomGenerator gm_secRandomDataWithLength:16];
NSData *ciphertextData = [GMSm2Cryptor gm_sm2EncryptData:plaintextData withPublicKey:publicKey];
NSData *decryptedData = [GMSm2Cryptor gm_sm2DecryptData:ciphertextData withPrivateKey:privateKey];

// SM2数字签名和验证
NSData *messageData = [GMRandomGenerator gm_secRandomDataWithLength:36];
NSData *signatureData = [GMSm2Cryptor gm_sm2SignData:messageData withPrivateKey:privateKey];
BOOL isSignatureValid = [GMSm2Cryptor gm_sm2VerifySignature:signatureData forData:messageData withPublicKey:publicKey];
```

### 3. SM3提取摘要

GMCryptoKit提供了对SM3算法的支持，包括提取摘要、基于哈希的消息认证码（HMAC）等功能。

#### 使用示例：

```objective-c
#import <GMCryptoKit/GMCryptoKit.h>

// SM3 提取摘要值
NSString *inputString = @"hello world!";
NSData *inputData = [inputString dataUsingEncoding:NSUTF8StringEncoding];
NSData *hashValue = [GMSm3Digest gm_sm3DigestWithData:mesData];

// 基于SM3计算HMAC
NSString *key = @"mySecretKey";
NSString *inputString = @"hello world!";
NSData *inputData = [inputString dataUsingEncoding:NSUTF8StringEncoding];
NSData *hmacValue = [GMSm3Digest gm_hmacSm3DigestWithData:inputData keyData:key];
```

### 4. SM4 对称加解密

GMCryptoKit提供了对SM4算法的支持，包括生成密钥、CBC模式加解密等功能。

#### 使用示例：

```objective-c
#import <GMCryptoKit/GMCryptoKit.h>

// SM4 生成密钥
NSData *key = [GMSm4Cryptor gm_createSm4Key];
NSData *iv = [GMSm4Cryptor gm_createSm4Key]; 

// SM4 CBC模式加密
NSString *inputString = @"hello, world!";
NSData *inputData = [inputString dataUsingEncoding:NSUTF8StringEncoding];
NSData *encryptedData = [GMSm4Cryptor gm_sm4CbcPaddingEncryptData:inputData withKey:key withIv:iv];

// SM4 CBC模式解密
NSData *decryptedData =[GMSm4Cryptor gm_sm4CbcPaddingDecryptData:encryptedData withKey:key withIv:iv];
```



## 环境要求

- GmSSL v3.1.0+
- Xcode 14.3+
- iOS 8.0+

## 使用

- 从 [GitHub](https://github.com/zitaodev/GMCryptoKit) 获取源代码

- 将源代码中 GMCryptoKit 目录导入 App 项目，并选中 ***Copy items if needed***

- 从[GmSSL](https://github.com/guanzhi/GmSSL) 编译获取GmSSL 静态库：libgmssl 和对应的头文件，并添加到 App项目中

- 导入头文件\#import <GMCryptoKit/GMCryptoKit.h>即可调用国密算法


  > 注意：
  >
  > 1、[GmSSL](https://github.com/guanzhi/GmSSL) 版本需要编译v3.1.0或以上版本.
  >
  > 2、[GmSSL 静态库编译步骤参考](https://github.com/guanzhi/GmSSL/blob/v3.1.0/INSTALL.md)

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
