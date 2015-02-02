//
//  APKeychainService.swift
//  APSwiftEncrypt
//
//  Created by Juan Alvarez on 11/3/14.
//  Copyright (c) 2014 Alvarez Productions. All rights reserved.
//

import Foundation
import Security

class APKeychainService {
    
    // the result can be any of the following:
    // SecKeychainItemRef, SecKeyRef, SecCertificateRef, or SecIdentityRef
    class func performKeyQuery(query: APKeychainQuery) -> Any? {
        var typeRef: Unmanaged<AnyObject>?
        
        var queryDict = query.getQueryDict()
        queryDict[kSecReturnRef] = true
        
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
    
    class func performKeyDataQuery(query: APKeychainQuery) -> NSData? {
        var dataTypeRef: Unmanaged<AnyObject>?
        
        var queryDict = query.getQueryDict()
        queryDict[kSecReturnData] = true
        
        let status = SecItemCopyMatching(queryDict, &dataTypeRef)
        
        if status == errSecSuccess {
            let keyData = dataTypeRef?.toOpaque()
            
            if let key = keyData {
                let data: NSData = Unmanaged<NSData>.fromOpaque(key).takeUnretainedValue()
                
                return data
            }
        }
        
        return nil
    }
    
    typealias APDictionary = Dictionary<NSObject, AnyObject>
    
    class func performKeyAttributesQuery(query: APKeychainQuery) -> APDictionary? {
        var dataTypeRef: Unmanaged<AnyObject>?
        
        var queryDict = query.getQueryDict()
        queryDict[kSecReturnAttributes] = true
        
        let status = SecItemCopyMatching(queryDict, &dataTypeRef)
        
        if status == errSecSuccess {
            let opaque = dataTypeRef?.toOpaque()
            
            if let op = opaque {
                let keyAttr: APDictionary = Unmanaged<NSDictionary>.fromOpaque(op).takeUnretainedValue()
                
                return keyAttr
            }
        }
        
        return nil
    }
    
    class func getKeyPersistentRef(query: APKeychainQuery) -> NSData? {
        var dataTypeRef: Unmanaged<AnyObject>?
        
        var queryDict = query.getQueryDict()
        queryDict[kSecReturnPersistentRef] = true
        
        let status = SecItemCopyMatching(queryDict, &dataTypeRef)
        
        if status == errSecSuccess {
            let opaque = dataTypeRef?.toOpaque()
            
            if let op = opaque {
                let data: NSData = Unmanaged<NSData>.fromOpaque(op).takeUnretainedValue()
                
                return data
            }
        }
        
        return nil
    }
    
}

class APKeychainQuery {
    
    let classKey: APSecClassKey
    
    var accessible: APSecAccessible? {
        didSet {
            queryDict[kSecAttrAccessible] = accessible?.getValue()
        }
    }
    
    var accessControl: SecAccessControlRef? {
        didSet {
            queryDict[kSecAttrAccessControl] = accessControl
        }
    }
    
    var accessGroup: String? {
        didSet {
            queryDict[kSecAttrAccessGroup] = accessGroup
        }
    }
    
    var applicationLabel: String? {
        didSet {
            queryDict[kSecAttrApplicationLabel] = applicationLabel
        }
    }
    
    var applicationTag: String? {
        didSet {
            let tagData = applicationTag?.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
            queryDict[kSecAttrApplicationTag] = tagData?
        }
    }
    
    var synchronizable: Bool? {
        didSet {
            queryDict[kSecAttrSynchronizable] = synchronizable
        }
    }
    
    var description: String? {
        didSet {
            queryDict[kSecAttrDescription] = description
        }
    }
    
    var comment: String? {
        didSet {
            queryDict[kSecAttrComment] = comment
        }
    }
    
    var label: String? {
        didSet {
            queryDict[kSecAttrLabel] = label
        }
    }
    
    var type: UInt? {
        didSet {
            queryDict[kSecAttrType] = type
        }
    }
    
    var invisible: Bool? {
        didSet {
            queryDict[kSecAttrIsInvisible] = invisible
        }
    }
    
    var account: String? {
        didSet {
            queryDict[kSecAttrAccount] = account
        }
    }
    
    var service: String? {
        didSet {
            queryDict[kSecAttrService] = service
        }
    }
    
    var securityDomain: String? {
        didSet {
            queryDict[kSecAttrSecurityDomain] = securityDomain
        }
    }
    
    var server: String? {
        didSet {
            queryDict[kSecAttrServer] = server
        }
    }
    
    var serverProtocol: APSecProtocol? {
        didSet {
            queryDict[kSecAttrProtocol] = serverProtocol?.getValue()
        }
    }
    
    var authenticationType: APSecAuthenticationType? {
        didSet {
            queryDict[kSecAttrAuthenticationType] = authenticationType?.getValue()
        }
    }
    
    var port: Int? {
        didSet {
            queryDict[kSecAttrPort] = port
        }
    }
    
    var path: String? {
        didSet {
            queryDict[kSecAttrPath] = path
        }
    }
    
    var keySizeInBits: Int? {
        didSet {
            queryDict[kSecAttrKeySizeInBits] = keySizeInBits
        }
    }
    
    var keyType: APSecKeyType? {
        didSet {
            queryDict[kSecAttrKeyType] = keyType?.getValue()
        }
    }
    
    var itemList: [AnyObject]? {
        didSet {
            queryDict[kSecMatchItemList] = itemList
        }
    }
    
    private var queryDict: [String: AnyObject] = [:]
    
    init(key: APSecClassKey) {
        classKey = key
        
        queryDict[kSecClass] = classKey.getValue()
    }
    
    func getQueryDict() -> [String: AnyObject] {
        return queryDict
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
    
    func getValue() -> String {
        switch self {
        case .FTP: return kSecAttrProtocolFTP
        case .FTPAccount: return kSecAttrProtocolFTPAccount
        case .HTTP: return kSecAttrProtocolHTTP
        case .IRC: return kSecAttrProtocolIRC
        case .NNTP: return kSecAttrProtocolNNTP
        case .POP3: return kSecAttrProtocolPOP3
        case .SMTP: return kSecAttrProtocolSMTP
        case .SOCKS: return kSecAttrProtocolSOCKS
        case .IMAP: return kSecAttrProtocolIMAP
        case .LDAP: return kSecAttrProtocolLDAP
        case .AppleTalk: return kSecAttrProtocolAppleTalk
        case .AFP: return kSecAttrProtocolAFP
        case .Telnet: return  kSecAttrProtocolTelnet
        case .SSH: return kSecAttrProtocolSSH
        case .FTPS: return kSecAttrProtocolFTPS
        case .HTTPS: return kSecAttrProtocolHTTPS
        case .HTTPProxy: return kSecAttrProtocolHTTPProxy
        case .HTTPSProxy: return kSecAttrProtocolHTTPSProxy
        case .FTPProxy: return kSecAttrProtocolFTPProxy
        case .SMB: return kSecAttrProtocolSMB
        case .RSTP: return kSecAttrProtocolRTSP
        case .RTSPProxy: return kSecAttrProtocolRTSPProxy
        case .DAAP: return kSecAttrProtocolDAAP
        case .EPPC: return kSecAttrProtocolEPPC
        case .IPP: return kSecAttrProtocolIPP
        case .NNTPS: return kSecAttrProtocolNNTPS
        case .LDAPS: return kSecAttrProtocolLDAPS
        case .TelnetS: return kSecAttrProtocolTelnetS
        case .IMAPS: return kSecAttrProtocolIMAPS
        case .IRCS: return kSecAttrProtocolIRCS
        case .POP3S: return kSecAttrProtocolPOP3S
        }
    }
}

enum APSecAuthenticationType {
    case NTLM       // kSecAttrAuthenticationTypeNTLM
    case MSN        // kSecAttrAuthenticationTypeMSN
    case DPA        // kSecAttrAuthenticationTypeDPA
    case RPA        // kSecAttrAuthenticationTypeRPA
    case HTTPBasic  // kSecAttrAuthenticationTypeHTTPBasic
    case HTTPDigest // kSecAttrAuthenticationTypeHTTPDigest
    case HTMLForm   // kSecAttrAuthenticationTypeHTMLForm
    case Default    // kSecAttrAuthenticationTypeDefault
    
    func getValue() -> String {
        switch self {
        case .NTLM: return kSecAttrAuthenticationTypeNTLM
        case .MSN: return kSecAttrAuthenticationTypeMSN
        case .DPA: return kSecAttrAuthenticationTypeDPA
        case .RPA: return kSecAttrAuthenticationTypeRPA
        case .HTTPBasic: return kSecAttrAuthenticationTypeHTTPBasic
        case .HTTPDigest: return kSecAttrAuthenticationTypeHTTPDigest
        case .HTMLForm: return kSecAttrAuthenticationTypeHTMLForm
        case .Default: return kSecAttrAuthenticationTypeDefault
        }
    }
}