//
//  APSwiftEncryptTests.swift
//  APSwiftEncryptTests
//
//  Created by Juan Alvarez on 11/3/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

import UIKit
import XCTest

let defaultTag = "com.alvarezproductions"

class SwiftEncryptRSATests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        
        EncryptRSA.removeKeyPairWith(defaultTag)
    }
    
    override func tearDown() {
        //
        
        super.tearDown()
    }
    
    func testKeyGenerationWithTag() {
        let keyPair = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: defaultTag)
        
        XCTAssertTrue(keyPair != nil, "keyPair should not be nil")
    }
    
    func testKeyGenerationShouldFailWithTagAlreadySaved() {
        let keyPair1 = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: defaultTag)
        
        let keyPair2 = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: defaultTag)
        
        XCTAssertTrue(keyPair2 == nil, "keyPair2 should be nil")
    }
    
    func testKeyGenerationWithoutTag() {
        let keyPair = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: nil)
        
        let publicKeyData = keyPair?.getPublicKeyData()
        let privateKeyData = keyPair?.getPrivateKeyData()
        
        XCTAssertTrue(keyPair != nil, "keyPair should not be nil")
    }
    
    func testKeyPairRetrieval() {
        let keyPair = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: defaultTag)!
        let retrievedKeyPair = EncryptRSA.getKeyPairWith(defaultTag)
        
        XCTAssertTrue(retrievedKeyPair != nil, "retrievedKeyPair should not be nil")
    }
    
    func testEncryption() {
        let keyPair = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: defaultTag)!
        
        let testString = "Testing Encryption"

        let encryptedString = testString.encrypt(keyPair)
        
        XCTAssertNotNil(encryptedString, "should return an encrypted string")
    }
    
    func testStringDecryption() {
        let keyPair = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: defaultTag)!
        
        let testString = "Testing Encryption"
        
        let encryptedString = testString.encrypt(keyPair)!
        let decryptedString = encryptedString.decrypt(keyPair)
        
        XCTAssertTrue(decryptedString != nil, "decryptedString should not be nil")
        XCTAssertEqual(testString, decryptedString!, "decrypted string should be the same as the original string")
    }
    
    func testDataDecryption() {
        let keyPair = EncryptRSA.generateRSAPair(.Size512, tagIdentifier: nil)!
        
        let padding = EncryptRSAPadding.PKCS1
        
        let testString = "Testing Decryption"
        
        let encryptedString = testString.encrypt(keyPair, padding: padding)!
        let encryptedStringData = NSData(base64EncodedString: encryptedString, options: NSDataBase64DecodingOptions.allZeros)!
        
        let decryptedString = encryptedStringData.decrypt(keyPair, padding: padding)
        
        XCTAssertTrue(decryptedString != nil, "decryptedString should not be nil")
        XCTAssertEqual(testString, decryptedString!, "decrypted string should be the same as the original string")
    }
    
    func testLongStringEncryptionWithPCKS1Padding() {
        let testString = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
        
        let keyPair = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: defaultTag)!
        
        let encryptedString = testString.encrypt(keyPair)
        
        XCTAssertTrue(encryptedString == nil, "should not be able to encrypt long string")
    }
    
    func testSigning() {
        let keys = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: nil)!
        let algorithm = EncryptRSAHMACAlgorithm.SHA1
        
        let result = signedDataWith(keys, algorithm: algorithm)
        
        XCTAssertNotNil(result.signature, "should return valid signature")
    }
    
    func testVerify() {
        let keys = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: nil)!
        let algorithm = EncryptRSAHMACAlgorithm.SHA1
        
        let result = signedDataWith(keys, algorithm: algorithm)
        let resultDigest = result.digest
        
        let valid = resultDigest.verify(result.signature!, keys: keys, algorithm: algorithm)
        
        XCTAssertTrue(valid, "verification should be valid")
    }
    
    func testVerifyFailWithWrongKeys() {
        let keys = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: nil)!
        let wrongKeys = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: nil)!
        let algorithm = EncryptRSAHMACAlgorithm.SHA1
        
        let result = signedDataWith(keys, algorithm: algorithm)
        let resultDigest = result.digest
        
        let valid = resultDigest.verify(result.signature!, keys: keys, algorithm: algorithm)
    }
    
    func testSignVerify() {
        let keys = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: nil)!
        let algorithm = EncryptRSAHMACAlgorithm.SHA1
        
        let string = "Testing"
        let stringDigestData = string.digest(algorithm)
        
        let signedData = stringDigestData.sign(keys, algorithm: algorithm)
        
        XCTAssertTrue(signedData != nil, "signedData must not be nil")
        
        let verifyResult = stringDigestData.verify(signedData!, keys: keys, algorithm: algorithm)
        
        XCTAssertTrue(verifyResult, "verification should work")
    }
    
    func testVerifyShouldFailWithWrongKeys() {
        let correctKeys = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: nil)!
        let wrongKeys = EncryptRSA.generateRSAPair(EncryptRSASize.Size512, tagIdentifier: nil)!
        
        let algorithm = EncryptRSAHMACAlgorithm.SHA1
        
        let string = "Testing"
        let stringDigestData = string.digest(algorithm)
        
        let signedData = stringDigestData.sign(correctKeys, algorithm: algorithm)
        
        let verifyResult = stringDigestData.verify(signedData!, keys: wrongKeys, algorithm: algorithm)
        
        XCTAssertFalse(verifyResult, "verification should fail")
    }
}

private extension SwiftEncryptRSATests {
    
    func signedDataWith(keys: KeyPair, algorithm: EncryptRSAHMACAlgorithm) -> (digest: NSData, signature: NSData?) {
        let string = "Testing"
        let digest = string.digest(algorithm)
        
        let signature = digest.sign(keys, algorithm: algorithm)
        
        return (digest: digest, signature: signature)
    }
}
