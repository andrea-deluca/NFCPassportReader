//
//  ChipAuthenticationPublicKeyInfo.swift
//  
//
//  Created by Andrea Deluca on 15/09/23.
//

import Foundation

/// A class representing the public key information used in Chip Authentication
/// or PACE with Chip Authentication Mapping.
///
/// The ASN.1 data structure `ChipAuthenticationPublicKeyInfo` is defined as follows:
///
///  ```
///  ChipAuthenticationPublicKeyInfo ::= SEQUENCE {
///     protocol OBJECT IDENTIFIER(id-PK-DH | id-PK-ECDH),
///     chipAuthenticationPublicKey SubjectPublicKeyInfo,
///     keyId INTEGER OPTIONAL
///  }
///  ```
///
/// This data structure provides a public key for Chip Authentication or PACE with Chip Authentication Mapping
/// of the eMRTD chip and its components represent.
///
/// - `protocol`: An object identifier that identifies the type
///   of the public key (i.e. DH or ECDH).
///
/// - `chipAuthenticationPublicKey`: A ``SubjectPublicKeyInfo`` data structure that
///   contains the public key in encoded form.
///
/// An integer that identifies the version of the protocol. Currently,
///   only version 1 is supported by this specification..
///
/// - `keyId`: An integer that may indicate the local key identifier (optional).
///
/// - Important: `KeyId` must be used if the eMRTD chip provides multiple public keys
///   for Chip Authentication or if this key is used for PACE with Chip Authentication Mapping.
///
/// - Note: It inherits from the ``SecurityInfo`` class.
///
/// - SeeAlso: ``CAPublicKeySecurityProtocol``, ``ChipAuthenticationInfo``
/// ``ChipAuthenticationSecurityProtocol``, ``ChipAuthenticationHandler`` and ``SubjectPublicKeyInfo``

internal final class ChipAuthenticationPublicKeyInfo: SecurityInfo {
    internal typealias KeyIdentifier = Int
    
    /// The ``SecurityProtocol`` associated with this public key.
    private(set) var securityProtocol: CAPublicKeySecurityProtocol
    
    /// The subject public key information.
    private(set) var subjectPublicKeyInfo: SubjectPublicKeyInfo!
    
    /// The key identifier, if available.
    private(set) var keyId: KeyIdentifier?
    
    /// Check if the provided ``ObjectIdentifier`` (OID) is valid for Chip Authentication Public Key.
    ///
    /// - Parameter oid: The OID to check.
    ///
    /// - Returns: `true` if the OID is valid for Chip Authentication Public Key, `false` otherwise.
    
    internal static func checkRequiredIdentifier(_ oid: ObjectIdentifier) -> Bool {
        CAPublicKeySecurityProtocol.isValid(oid: oid)
    }
    
    /// Initialize a ``ChipAuthenticationPublicKeyInfo`` instance with the given OID and ASN.1 data.
    ///
    /// - Parameters:
    ///   - oid: The ``ObjectIdentifier`` associated with the security protocol.
    ///   - data: The ASN.1 data containing the public key information.
    ///
    /// - Throws: An error if the security protocol cannot be decoded from the OID.
    
    internal required init(oid: ObjectIdentifier, data: ASN1NodeCollection) throws {
        guard let securityProtocol = CAPublicKeySecurityProtocol.from(oid: oid) else {
            throw NFCPassportReaderError.SecurityProtocolNotDecodable
        }
        
        self.securityProtocol = securityProtocol
        try super.init(oid: oid, data: data)
    }
    
    /// Decodes the ASN.1 data, extracting the ``SubjectPublicKeyInfo`` and key identifier, if available.
    ///
    /// - Parameter data: The ASN.1 data to decode.
    ///
    /// - Throws: An error if the data cannot be decoded successfully.
    
    override internal func decode(_ data: ASN1NodeCollection) throws {
        try data.dropFirst().forEach { node in
            switch ASN1UniversalTag.decode(from: node.tag) {
            case .SEQUENCE: self.subjectPublicKeyInfo = try SubjectPublicKeyInfo(from: node)
            case .INTEGER: try decodeKeyId(node)
            default: throw NFCPassportReaderError.UnexpectedResponseStructure
            }
        }
    }
}

private extension ChipAuthenticationPublicKeyInfo {
    
    /// Decodes the key identifier from the given ASN.1 node.
    ///
    /// - Parameter node: The ASN.1 node containing the key identifier.
    
    private func decodeKeyId(_ node: ASN1Node) throws {
        guard case .primitive(let keyId) = node.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        self.keyId = Int(BytesRepresentationConverter
            .convertToHexNumber(from: keyId))
    }
}

