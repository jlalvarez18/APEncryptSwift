//
//  APKeychainService.swift
//  APSwiftEncrypt
//
//  Created by Juan Alvarez on 11/3/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

import Foundation
import Security

struct APKeychainQuery {
    let classKey: APSecClassKey // kSecClass
    
    var accessible: APSecAccessible? {
        didSet {
            queryDict[kSecAttrAccessible] = accessible?.getValue()
        }
    }
    var accessControl: AnyObject? // kSecAttrAccessControl
    var accessGroup: AnyObject? // kSecAttrAccessGroup
    var applicationLabel: String? {
        didSet {
            queryDict[kSecAttrApplicationLabel] = applicationLabel
        }
    }
    
    var applicationTag: NSData? // kSecAttrApplicationTag
    var synchronizable: Bool? // kSecAttrSynchronizable
    var description: String? // kSecAttrDescription
    var comment: String? // kSecAttrComment
    var label: String? // kSecAttrLabel
    var type: UInt? // kSecAttrType
    var invisible: Bool? // kSecAttrIsInvisible
    var account: String? // kSecAttrAccount
    var service: String? // kSecAttrService
    var securityDomain: String? // kSecAttrSecurityDomain
    var server: String? // kSecAttrServer
    var serverProtocol: APSecProtocol? // kSecAttrProtocol
    var authenticationType: APSecAuthenticationType? // kSecAttrAuthenticationType
    var port: Int? // kSecAttrPort
    var path: String? // kSecAttrPath
    var keySizeInBits: Int? // kSecAttrKeySizeInBits
    
    private var queryDict: [String: AnyObject] = [:]
    
    init(key: APSecClassKey) {
        classKey = key
    }
}

class APKeychainService {
    class func getKeyRef(query: APKeychainQuery) -> Any? {
        return nil
    }
    
    class func getKeyData(query: APKeychainQuery) -> NSData? {
        return nil
    }
    
    class func getKeyAttributes(query: APKeychainQuery) -> [String: AnyObject]? {
        return nil
    }
    
    class func getKeyPersistentRef(query: APKeychainQuery) -> NSData? {
        return nil
    }
}

enum APSecClassKey {
    case GenericPassword    // kSecClassGenericPassword
    case InternetPassword   // kSecClassInternetPassword
    case Certificate        // kSecClassCertificate
    case Key                // kSecClassKey
    case Identity           // kSecClassIdentity
    
    func getValue() -> String {
        switch self {
        case .GenericPassword: return kSecClassGenericPassword
        case .InternetPassword: return kSecClassInternetPassword
        case .Certificate: return kSecClassCertificate
        case .Key: return kSecClassKey
        case .Identity: return kSecClassIdentity
        }
    }
}

enum APSecAccessible {
    case WhenUnlocked                   // kSecAttrAccessibleWhenUnlocked
    case AfterFirstUnlock               // kSecAttrAccessibleAfterFirstUnlock
    case Always                         // kSecAttrAccessibleAlways
    case WhenPasscodeSetThisDeviceOnly  // kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    case WhenUnlockedThisDeviceOnly     // kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    case AfterFirstUnlockThisDeviceOnly // kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    case AlwaysThisDeviceOnly           // kSecAttrAccessibleAlwaysThisDeviceOnly
    
    func getValue() -> String {
        switch self {
        case .WhenUnlocked: return kSecAttrAccessibleWhenUnlocked
        case .AfterFirstUnlock: return kSecAttrAccessibleAfterFirstUnlock
        case .Always: return kSecAttrAccessibleAlways
        case .WhenPasscodeSetThisDeviceOnly: return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        case .WhenUnlockedThisDeviceOnly: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .AfterFirstUnlockThisDeviceOnly: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .AlwaysThisDeviceOnly: return kSecAttrAccessibleAlwaysThisDeviceOnly
        }
    }
}

enum APSecKeyClass {
    case Public     // kSecAttrKeyClassPublic
    case Private    // kSecAttrKeyClassPrivate
    case Symmetric  // kSecAttrKeyClassSymmetric
    
    func getValue() -> String {
        switch self {
        case .Public: return kSecAttrKeyClassPublic
        case .Private: return kSecAttrKeyClassPrivate
        case .Symmetric: return kSecAttrKeyClassSymmetric
        }
    }
}

enum APSecKeyType {
    case RSA // kSecAttrKeyTypeRSA
    case EC  // kSecAttrKeyTypeEC
    
    func getValue() -> String {
        switch self {
        case .RSA: return kSecAttrKeyTypeRSA
        case .EC: return kSecAttrKeyTypeEC
        }
    }
}

enum APSecProtocol {
    case FTP        // kSecAttrProtocolFTP
    case FTPAccount // kSecAttrProtocolFTPAccount
    case HTTP       // kSecAttrProtocolHTTP
    case IRC        // kSecAttrProtocolIRC
    case NNTP       // kSecAttrProtocolNNTP
    case POP3       // kSecAttrProtocolPOP3
    case SMTP       // kSecAttrProtocolSMTP
    case SOCKS      // kSecAttrProtocolSOCKS
    case IMAP       // kSecAttrProtocolIMAP
    case LDAP       // kSecAttrProtocolLDAP
    case AppleTalk  // kSecAttrProtocolAppleTalk
    case AFP        // kSecAttrProtocolAFP
    case Telnet     // kSecAttrProtocolTelnet
    case SSH        // kSecAttrProtocolSSH
    case FTPS       // kSecAttrProtocolFTPS
    case HTTPS      // kSecAttrProtocolHTTPS
    case HTTPProxy  // kSecAttrProtocolHTTPProxy
    case HTTPSProxy // kSecAttrProtocolHTTPSProxy
    case FTPProxy   // kSecAttrProtocolFTPProxy
    case SMB        // kSecAttrProtocolSMB
    case RSTP       // kSecAttrProtocolRTSP
    case RTSPProxy  // kSecAttrProtocolRTSPProxy
    case DAAP       // kSecAttrProtocolDAAP
    case EPPC       // kSecAttrProtocolEPPC
    case IPP        // kSecAttrProtocolIPP
    case NNTPS      // kSecAttrProtocolNNTPS
    case LDAPS      // kSecAttrProtocolLDAPS
    case TelnetS    // kSecAttrProtocolTelnetS
    case IMAPS      // kSecAttrProtocolIMAPS
    case IRCS       // kSecAttrProtocolIRCS
    case POP3S      // kSecAttrProtocolPOP3S
}

enum APSecAuthenticationType {
    case NTLM       // kSecAttrAuthenticationTypeNTLM.
    case MSN        // kSecAttrAuthenticationTypeMSN.
    case DPA        // kSecAttrAuthenticationTypeDPA.
    case RPA        // kSecAttrAuthenticationTypeRPA.
    case HTTPBasic  // kSecAttrAuthenticationTypeHTTPBasic.
    case HTTPDigest // kSecAttrAuthenticationTypeHTTPDigest.
    case HTMLForm   // kSecAttrAuthenticationTypeHTMLForm.
    case Default    // kSecAttrAuthenticationTypeDefault.
}