//
//  APEncryptRSA.swift
//  APSwiftEncrypt
//
//  Created by Juan Alvarez on 11/3/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

import Foundation
import Security

private let SecPublicKeyAttrs = kSecPublicKeyAttrs.takeRetainedValue() as String
private let SecPrivateKeyAttrs = kSecPrivateKeyAttrs.takeRetainedValue() as String

typealias DictionaryType = [String: AnyObject]

enum EncryptRSASize: Int {
    case Size512 = 512
    case Size768 = 768
    case Size1024 = 1024
    case Size2048 = 2048
}

enum EncryptRSAPadding {
    case None, PKCS1, OAEP
}

enum EncryptRSAHMACAlgorithm {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    func isSHADigestType() -> Bool {
        switch self {
        case .SHA1, .SHA224, .SHA256, .SHA384, .SHA512:
            return true
        default:
            return false
        }
    }
}

enum SecKeyType {
    case RSA // kSecAttrKeyTypeRSA
    case EC  // kSecAttrKeyTypeEC
    
    func getValue() -> String {
        switch self {
        case .RSA: return kSecAttrKeyTypeRSA
        case .EC: return kSecAttrKeyTypeEC
        }
    }
}

struct KeyPair {
    let identifier: String?
    let publicKey: SecKeyRef
    let privateKey: SecKeyRef
}

extension KeyPair {
    func getPublicKeyData() -> NSData? {
        return EncryptRSA.getKeyData(publicKey)
    }
    
    func getPrivateKeyData() -> NSData? {
        return EncryptRSA.getKeyData(privateKey)
    }
}

struct EncryptRSA {
    
    /**
    Generates RSA key pair with provided size
    
    :param: size          EncryptRSASize type
    :param: tagIdentifier Optional. If not nil, the key will be saved to the keychain. If pair with provided tag exists, will return nil. Use getKeyPair() to get pair with tag.
    
    :returns: a KeyPair struct with the public and private keys. If RSA pair exsits with provided tag, nil will be returned
    */
    
    static func generateRSAPair(size: EncryptRSASize, tagIdentifier: String?) -> KeyPair? {
        var attributes: [String: AnyObject] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: size.rawValue
        ]
        
        if let tag = tagIdentifier {
            if let pair = getKeyPairWith(tag) {
                return nil
            } else {
                var identifiers = keychainIdentifiers(tag)
                
                let pubAttr: [String: AnyObject] = [kSecAttrIsPermanent: true, kSecAttrApplicationTag: identifiers.pub]
                let privAttr: [String: AnyObject] = [kSecAttrIsPermanent: true, kSecAttrApplicationTag: identifiers.priv]
                
                attributes[SecPublicKeyAttrs] = pubAttr
                attributes[SecPrivateKeyAttrs] = privAttr
            }
        }
        
        var publicKeyRef: Unmanaged<SecKeyRef>?
        var privateKeyRef: Unmanaged<SecKeyRef>?
        
        let status: OSStatus = SecKeyGeneratePair(attributes, &publicKeyRef, &privateKeyRef)
        
        if status == errSecSuccess {
            // if status is successful then the keys should be valid
            var publicKey: SecKeyRef = Unmanaged<SecKeyRef>.fromOpaque(publicKeyRef!.toOpaque()).takeUnretainedValue()
            var privateKey: SecKeyRef = Unmanaged<SecKeyRef>.fromOpaque(privateKeyRef!.toOpaque()).takeUnretainedValue()
            
            if let tag = tagIdentifier {
                // if there is a tag then the keys should have been saved permenently in the keychain
                // so let's retrieve it that way
                return getKeyPairWith(tag)
            } else {
                return KeyPair(identifier: nil, publicKey: publicKey, privateKey: privateKey)
            }
        }
        
        return nil
    }
    
    /**
    Retrive the RSA Key Pair from the keychain
    
    :param: tag identifer used to save the key pair to the keychain
    
    :returns: RSA Key Pair matching the tag
    */
    
    static func getKeyPairWith(tag: String) -> KeyPair? {
        let identifiers = keychainIdentifiers(tag)
        
        let publicKey = getKeyRef(identifiers.pub)
        let privateKey = getKeyRef(identifiers.priv)
        
        switch (publicKey, privateKey) {
        case let (.Some(publicKey), .Some(privateKey)):
            return KeyPair(identifier: tag, publicKey: publicKey, privateKey: privateKey)
        default:
            return nil
        }
    }
    
    static func removeKeyPairWith(tag: String) -> Bool {
        let identifiers = keychainIdentifiers(tag)
        
        let queryPubKey = keyQueryDictionary(identifiers.pub)
        let queryPrivKey = keyQueryDictionary(identifiers.priv)
        
        let pubStatus = SecItemDelete(queryPubKey)
        let privStatus = SecItemDelete(queryPrivKey)
        
        if pubStatus == errSecSuccess && privStatus == errSecSuccess {
            return true
        }
        
        return false
    }
}

// MARK: Encryption Methods

extension NSData {
    
    func encrypt(keys: KeyPair, padding: EncryptRSAPadding = .PKCS1) -> String? {
        let plainTextBuffer = UnsafePointer<UInt8>(bytes)
        let plainTextLength = UInt(length)
        
        var maxLength = SecKeyGetBlockSize(keys.publicKey)
        
        // When PKCS1 padding is performed, the maximum length of data that can
        // be encrypted is the value returned by SecKeyGetBlockSize() - 11.
        if padding == .PKCS1 {
            maxLength -= 11
        }
        
        if (plainTextLength > maxLength) {
            println("String length is too long to sign with this key, max length is \(maxLength) and actual length is \(plainTextLength)")
            
            return nil
        }
        
        let blockSize = SecKeyGetBlockSize(keys.publicKey)
        
        let cipherData = NSMutableData(length: Int(blockSize))!
        let cipherBuffer = UnsafeMutablePointer<UInt8>(cipherData.mutableBytes)
        var cipherBufferLength = size_t(cipherData.length)
        
        let paddingSec = padding.toSecPadding()
        
        let status = SecKeyEncrypt(
            keys.publicKey,
            paddingSec,
            plainTextBuffer,
            plainTextLength,
            cipherBuffer,
            &cipherBufferLength
        )
        
        if status == errSecSuccess {
            let encryptedString = cipherData.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(0))
            
            return encryptedString
        }
        
        return nil
    }
}

extension String {
    
    func encrypt(keys: KeyPair, padding: EncryptRSAPadding = .PKCS1) -> String? {
        let plainTextData = dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!
        
        return plainTextData.encrypt(keys, padding: padding)
    }
}

// MARK: Decryption Methods

extension NSData {
    
    /**
    Decrypt a block of ciphertext. Must be base64Encoded.
    
    :param: keys    KeyPair object that contains the private key required for decryption
    :param: padding EncryptRSAPadding type
    
    :returns: returns a String decrypted from data
    */
    
    func decrypt(keys: KeyPair, padding: EncryptRSAPadding = .PKCS1) -> String? {
        let blockSize = SecKeyGetBlockSize(keys.privateKey)
        
        let cipherBuffer = UnsafePointer<UInt8>(bytes)
        let cipherSize = size_t(length)
        
        if cipherSize > blockSize {
            println("String length is too long to decrypt with this key, max length is \(blockSize) and actual length is \(cipherSize)")
            
            return nil
        }
        
        let plainTextData = NSMutableData(length: Int(blockSize))!
        let plainTextBuffer = UnsafeMutablePointer<UInt8>(plainTextData.mutableBytes)
        var plainTextBufferLength = size_t(blockSize)
        
        let paddingSec = padding.toSecPadding()
        
        let status = SecKeyDecrypt(
            keys.privateKey,
            paddingSec,
            cipherBuffer,
            cipherSize,
            plainTextBuffer,
            &plainTextBufferLength
        )
        
        if status == errSecSuccess {
            let decryptedString = NSString(bytes: plainTextBuffer, length: Int(plainTextBufferLength), encoding: NSUTF8StringEncoding)
            
            return decryptedString
        }
        
        return nil
    }
}

extension String {
    
    /**
    Decrypt Base64 encoded string using private key
    
    :param: keys    KeyPair object that contains the private key required for decryption
    :param: padding EncryptRSAPadding type
    
    :returns: String decrypted from Base64 encoded string
    */
    
    func decrypt(keys: KeyPair, padding: EncryptRSAPadding = .PKCS1) -> String? {
        let cipherData = NSData(base64EncodedString: self, options: NSDataBase64DecodingOptions(0))!
        
        return cipherData.decrypt(keys, padding: padding)
    }
}

// MARK: Signing Methods

extension NSData {
    
    /**
    Sign data with private key
    
    :param: keys      KeyPair object that contains the private key required for signing
    :param: algorithm EncryptRSAHMACAlgorithm type that defines the data hash
    
    :returns: signed NSData object
    */
    func sign(keys: KeyPair, algorithm: EncryptRSAHMACAlgorithm = .SHA1) -> NSData? {
        let blockSize = SecKeyGetBlockSize(keys.privateKey)
        
        let cipherBuffer = UnsafePointer<UInt8>(bytes)
        let cipherSize = size_t(length)
        
        // When PKCS1 padding is performed, the maximum length of data that can
        // be encrypted is the value returned by SecKeyGetBlockSize() - 11.
        let maxLength = algorithm.isSHADigestType() ? blockSize - 11 : blockSize
        
        if cipherSize > maxLength {
            println("String length is too long to decrypt with this key, max length is \(blockSize) and actual length is \(cipherSize)")
            
            return nil
        }
        
        let resultData = NSMutableData(length: Int(blockSize))!
        let resultBuffer = UnsafeMutablePointer<UInt8>(resultData.mutableBytes)
        var resultBufferSize = size_t(blockSize)
        
        let status = SecKeyRawSign(
            keys.privateKey,
            algorithm.toSecPadding(),
            cipherBuffer,
            cipherSize,
            resultBuffer,
            &resultBufferSize
        )
        
        if status == errSecSuccess {
            return NSData(bytes: resultBuffer, length: Int(resultBufferSize))
        }
        
        return nil
    }
}

extension String {
    
    func sign(keys: KeyPair, algorithm: EncryptRSAHMACAlgorithm = .SHA1) -> NSData? {
        let ciperData = digest(algorithm)
        
        return ciperData.sign(keys, algorithm: algorithm)
    }
}

// MARK: Verification Methods

extension NSData {
    
    func verify(signatureData: NSData, keys: KeyPair, algorithm: EncryptRSAHMACAlgorithm = .SHA1) -> Bool {
        let signedBuffer = UnsafePointer<UInt8>(bytes)
        let signedBufferSize = size_t(length)
        
        let signatureBuffer = UnsafePointer<UInt8>(signatureData.bytes)
        let signatureBufferSize = size_t(signatureData.length)
        
        let status = SecKeyRawVerify(
            keys.publicKey,
            algorithm.toSecPadding(),
            signedBuffer,
            signedBufferSize,
            signatureBuffer,
            signatureBufferSize
        )
        
        if status == errSecSuccess {
            return true
        }
        
        return false
    }
}

// MARK: Public Extension Helpers

extension String {
    
    func digest(algorithm: EncryptRSAHMACAlgorithm) -> NSData {
        let data = self.dataUsingEncoding(NSUTF8StringEncoding)!
        
        return data.digest(algorithm)
    }
}

extension NSData {
    
    func digest(algorithm: EncryptRSAHMACAlgorithm) -> NSData {
        let length = algorithm.digestLength()
        
        let resultData = NSMutableData(length: Int(length))!
        let resultBuffer = UnsafeMutablePointer<UInt8>(resultData.mutableBytes)
        
        switch algorithm {
        case .MD5:
            CC_MD5(self.bytes, CC_LONG(length), resultBuffer)
        case .SHA1:
            CC_SHA1(self.bytes, CC_LONG(length), resultBuffer)
        case .SHA224:
            CC_SHA224(self.bytes, CC_LONG(length), resultBuffer)
        case .SHA256:
            CC_SHA256(self.bytes, CC_LONG(length), resultBuffer)
        case .SHA384:
            CC_SHA384(self.bytes, CC_LONG(length), resultBuffer)
        case .SHA512:
            CC_SHA512(self.bytes, CC_LONG(length), resultBuffer)
        }
        
        return NSData(bytes: resultBuffer, length: length)
    }
    
    func toHexString() -> String {
        let count = self.length / sizeof(Byte)
        var bytesArray = [Byte](count: count, repeatedValue: 0)
        self.getBytes(&bytesArray, length:count * sizeof(Byte))
        
        var s = ""
        
        for byte in bytesArray {
            s = s + NSString(format:"%02X", byte)
        }
        
        return s;
    }
}

// MARK: Private Methods

private extension EncryptRSA {
    
    static func printStatus(status: OSStatus) {
        switch status {
        case errSecSuccess:
            println("SUCCESS")
        case errSecParam:
            println("INVALID PARAMS")
        case errSecNotAvailable:
            println("NOT AVAILABLE")
        default:
            println("OTHER STATUS \(status)")
        }
    }
    
    static func getKeyData(key: SecKeyRef) -> NSData? {
        var query = keyQueryDictionary("com.apencryptrsa.temporary_tag_for_key_data")
        query[kSecValueRef] = key
        query[kSecReturnData] = true
        
        var dataTypeRef: Unmanaged<AnyObject>?
        
        let status = SecItemAdd(query, &dataTypeRef)
        
        if status == errSecSuccess {
            let keyData = dataTypeRef?.toOpaque()
            
            if let key = keyData {
                let data: NSData = Unmanaged<NSData>.fromOpaque(key).takeUnretainedValue()
                
                SecItemDelete(query)
                
                return data
            }
        }
        
        return nil
    }
    
    static func getKeyRef(tag: String) -> SecKeyRef? {
        var queryDict = keyQueryDictionary(tag)
        queryDict[kSecReturnRef] = true
        
        var typeRef: Unmanaged<AnyObject>?
        
        let status = SecItemCopyMatching(queryDict, &typeRef)
        
        if status == errSecSuccess {
            let opaqueTypeRef = typeRef?.toOpaque()
            
            if let ref = opaqueTypeRef {
                let key: SecKeyRef = Unmanaged<SecKeyRef>.fromOpaque(ref).takeUnretainedValue()
                
                return key
            }
        }
        
        return nil
    }
    
    static func keyQueryDictionary(tag: String?) -> DictionaryType {
        var queryDict = DictionaryType()
        
        queryDict[kSecClass] = kSecClassKey
        queryDict[kSecAttrKeyType] = kSecAttrKeyTypeRSA
        queryDict[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlocked
        
        if let tag = tag {
            queryDict[kSecAttrApplicationTag] = tag.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        }
        
        return queryDict
    }
    
    static func keychainIdentifiers(tag: String) -> (pub: String, priv: String) {
        let publicId = tag.publicKeyIdentifier()
        let privateId = tag.privateKeyIdentifier()
        
        return (publicId, privateId)
    }
}

private extension String {
    
    func publicKeyIdentifier() -> String {
        return self + ".public"
    }
    
    func privateKeyIdentifier() -> String {
        return self + ".private"
    }
}

private extension EncryptRSAPadding {
    
    func toSecPadding() -> SecPadding {
        switch self {
        case .None:
            return SecPadding(kSecPaddingNone)
        case .PKCS1:
            return SecPadding(kSecPaddingPKCS1)
        case .OAEP:
            return SecPadding(kSecPaddingOAEP)
        }
    }
}

private extension EncryptRSAHMACAlgorithm {
    
    func toSecPadding() -> SecPadding {
        switch self {
        case .MD5:
            return SecPadding(kSecPaddingPKCS1MD5)
        case .SHA1:
            return SecPadding(kSecPaddingPKCS1SHA1)
        case .SHA224:
            return SecPadding(kSecPaddingPKCS1SHA224)
        case .SHA256:
            return SecPadding(kSecPaddingPKCS1SHA256)
        case .SHA384:
            return SecPadding(kSecPaddingPKCS1SHA384)
        case .SHA512:
            return SecPadding(kSecPaddingPKCS1SHA512)
        }
    }
    
    func toCCEnum() -> CCHmacAlgorithm {
        var result: Int = 0
        
        switch self {
        case .MD5:
            result = kCCHmacAlgMD5
        case .SHA1:
            result = kCCHmacAlgSHA1
        case .SHA224:
            result = kCCHmacAlgSHA224
        case .SHA256:
            result = kCCHmacAlgSHA256
        case .SHA384:
            result = kCCHmacAlgSHA384
        case .SHA512:
            result = kCCHmacAlgSHA512
        }
        
        return CCHmacAlgorithm(result)
    }
    
    func digestLength() -> Int {
        var result: CInt = 0
        
        switch self {
        case .MD5:
            result = CC_MD5_DIGEST_LENGTH
        case .SHA1:
            result = CC_SHA1_DIGEST_LENGTH
        case .SHA224:
            result = CC_SHA224_DIGEST_LENGTH
        case .SHA256:
            result = CC_SHA256_DIGEST_LENGTH
        case .SHA384:
            result = CC_SHA384_DIGEST_LENGTH
        case .SHA512:
            result = CC_SHA512_DIGEST_LENGTH
        }
        
        return Int(result)
    }
}
