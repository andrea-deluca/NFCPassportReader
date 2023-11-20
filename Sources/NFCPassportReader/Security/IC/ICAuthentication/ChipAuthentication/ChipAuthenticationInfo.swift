//
//  ChipAuthenticationInfo.swift
//  
//
//  Created by Andrea Deluca on 18/09/23.
//

import Foundation

/// `ChipAuthenticationInfo` represents security information related to
/// Chip Authentication in electronic Machine Readable Travel Documents (eMRTD).
///
/// The ASN.1 data structure `ChipAuthenticationInfo` is defined as follows:
///
///  ```
///  ChipAuthenticationInfo ::= SEQUENCE {
///     protocol OBJECT IDENTIFIER(
///         id-CA-DH-3DES-CBC-CBC |
///         id-CA-DH-AES-CBC-CMAC-128 |
///         id-CA-DH-AES-CBC-CMAC-192 |
///         id-CA-DH-AES-CBC-CMAC-256 |
///         id-CA-ECDH-3DES-CBC-CBC |
///         id-CA-ECDH-AES-CBC-CMAC-128 |
///         id-CA-ECDH-AES-CBC-CMAC-192 |
///         id-CA-ECDH-AES-CBC-CMAC-256),
///     version INTEGER, -- MUST be 1,
///     keyId INTEGER OPTIONAL
///  }
///  ```
///
/// This data structure provides detailed information on an implementation of
/// Chip Authentication and its components represent:
///
/// - `protocol`: An object identifier that identifies the algorithms
///   to be used, i.e.key agreement, symmetric cipher and MAC).
///
/// - `version`: An integer that identifies the version of the protocol. Currently,
///   only version 1 is supported by this specification.
///
/// - `keyId`: An integer that may indicate the local key identifier (optional).
///
/// - Important: `KeyId` must be used if the eMRTD chip provides multiple public keys
///   for Chip Authentication.
///
/// - Note: It inherits from the ``SecurityInfo`` class.
///
/// - SeeAlso: ``ChipAuthenticationSecurityProtocol``, ``ChipAuthenticationPublicKeyInfo``
/// ``CAPublicKeySecurityProtocol`` and ``ChipAuthenticationHandler``

internal final class ChipAuthenticationInfo: SecurityInfo {
    internal typealias KeyIdentifier = Int
    
    /// The ``SecurityProtocol`` used for Chip Authentication.
    private(set) var securityProtocol: ChipAuthenticationSecurityProtocol
    
    /// The Key Identifier, if available.
    private(set) var keyId: KeyIdentifier?
    
    private(set) var version: Int?
    
    /// Check if the provided ``ObjectIdentifier`` (OID) is valid for Chip Authentication.
    ///
    /// - Parameter oid: The OID to check.
    ///
    /// - Returns: `true` if the OID is valid for Chip Authentication, `false` otherwise.
    
    internal static func checkRequiredIdentifier(_ oid: ObjectIdentifier) -> Bool {
        ChipAuthenticationSecurityProtocol.isValid(oid: oid)
    }
    
    /// Initialize a ``ChipAuthenticationInfo`` instance with the given OID and ASN.1 data.
    ///
    /// - Parameters:
    ///   - oid: The ``ObjectIdentifier`` (OID) associated with the security information.
    ///   - data: The ASN.1 data containing security information.
    ///
    /// - Throws: An error if the security protocol cannot be determined from the provided OID.
    
    internal required init(oid: ObjectIdentifier, data: ASN1NodeCollection) throws {
        guard let securityProtocol = ChipAuthenticationSecurityProtocol.from(oid: oid) else {
            throw NFCPassportReaderError.SecurityProtocolNotDecodable
        }
        
        self.securityProtocol = securityProtocol
        try super.init(oid: oid, data: data)
    }
    
    /// Decode the ASN.1 data to extract relevant information.
    ///
    /// - Parameter data: The ASN.1 data to decode.
    ///
    /// - Throws: An error if the data cannot be decoded successfully.
    
    override internal func decode(_ data: ASN1NodeCollection) throws {
        try data.dropFirst().enumerated().forEach { (idx, node) in
            if idx == 0 { try self.decodeVersion(node) }
            else { try self.decodeKeyId(node) }
        }
    }
}

private extension ChipAuthenticationInfo {
    private func decodeVersion(_ node: ASN1Node) throws {
        guard case .primitive(let version) = node.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard BytesRepresentationConverter.convertToHexNumber(from: version) == 1 else {
            throw NFCPassportReaderError.UnexpectedValueFound
        }
        
        self.version = Int(BytesRepresentationConverter.convertToHexNumber(from: version))
    }
    
    private func decodeKeyId(_ node: ASN1Node) throws {
        guard case .primitive(let keyId) = node.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        self.keyId = Int(BytesRepresentationConverter.convertToHexNumber(from: keyId))
    }
}
