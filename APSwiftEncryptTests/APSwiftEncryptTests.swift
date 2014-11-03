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

class APSwiftEncryptTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testKeyGenerationWithTag() {
        let keyPair = APEncryptRSA.generateRSAPair(APEncryptRSASize.Size512, tagIdentifier: defaultTag)
        
        XCTAssertNotNil(keyPair!, "keyPair should not be nil")
    }
    
    func testKeyGenerationWithoutTag() {
        let keyPair = APEncryptRSA.generateRSAPair(APEncryptRSASize.Size512, tagIdentifier: nil)
        
        XCTAssertNotNil(keyPair!, "keyPair should not be nil")
    }
    
    func testKeyPairRetrieval() {
        let keyPair = APEncryptRSA.getKeyPair(defaultTag)
        
        XCTAssertNotNil(keyPair!, "keyPair should not be nil")
    }
}
