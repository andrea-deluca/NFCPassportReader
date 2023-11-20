//
//  SecurityInfo.swift
//  
//
//  Created by Andrea Deluca on 06/09/23.
//

import Foundation

/// A base class for representing security information contained in an ASN.1 structure.
///
/// The `SecurityInfo` class serves as a base class for various security information objects
/// used in the ASN.1 structure. It provides the foundation for decoding and extracting security information.
/// Subclasses should be created to handle specific types of security information.
///
/// The ASN.1 data structure `SecurityInfos` indicates supported security protocols and is provided by the eMRTD chip.
/// The data structures `SecurityInfos` and `SecurityInfo` are defined as follows:
///
///  ```
///  SecurityInfos ::= SET OF SecurityInfo
///
///  SecurityInfo ::= SEQUENCE {
///     protocol OBJECT IDENTIFIER,
///     requiredData ANY DEFINED BY protocol,
///     optionalData ANY DEFINED BY protocol OPTIONAL
///  }
///  ```
///
/// The `SecurityInfo` components represent:
///
/// - `protocol`: An object identifier that identifies the supported protocol.
/// - `requiredData`: An open type that contains protocol-specific mandatory data.
/// - `optionalData`: An open type that contains protocol-specific optional data.
///
/// Subclasses of `SecurityInfo` should override the ``decode(_:)`` method to handle the specific decoding
/// logic for their respective security information types.
///
/// The ``getInstance(node:)`` method is used to instantiate the appropriate subclass of `SecurityInfo`
/// based on the ``ObjectIdentifier`` (OID) found in the ASN.1 structure.
///
/// - SeeAlso: ``SecurityInfoDecoder``, ``SecurityProtocol``, ``SecurityObjectIdentifiers``
/// ``ChipAuthenticationInfo``, ``ChipAuthenticationPublicKeyInfo`` and ``PACEInfo``


internal class SecurityInfo {
    
    /// The object identifier (OID) associated with the security information.
    
    private(set) var oid: ObjectIdentifier
    
    /// The ASN.1 node collection containing the security information.
    
    private var data: ASN1NodeCollection
    
    /// Initializes a ``SecurityInfo`` instance.
    ///
    /// - Parameters:
    ///   - oid: The ``ObjectIdentifier`` (OID) associated with the security information.
    ///   - data: The ``ASN1NodeCollection`` containing the security information.
    ///
    /// Subclasses of ``SecurityInfo`` should override the ``decode(_:)`` method to handle
    /// the specific decoding logic for their respective security information types.
    
    internal required init(oid: ObjectIdentifier, data: ASN1NodeCollection) throws {
        self.oid = oid
        self.data = data
        
        try decode(data)
    }
    
    /// Decodes the security information from the given ASN.1 node collection.
    ///
    /// Subclasses of `SecurityInfo` should override this method to provide
    /// the specific decoding logic for their respective security information types.
    ///
    /// - Parameter data: The ``ASN1NodeCollection`` containing the security information.
    ///
    /// - Throws: An error if decoding fails.
    
    internal func decode(_ data: ASN1NodeCollection) throws {}
    
    /// Creates an instance of a subclass of ``SecurityInfo`` based on the provided ASN.1 node.
    ///
    /// The method extracts the ``ObjectIdentifier`` (OID) and instantiates the appropriate subclass
    /// based on the OID.
    ///
    /// - Important: If the OID is not recognized or supported, `nil` is returned.
    ///
    /// - Parameter node: The ``ASN1Node`` containing security information.
    ///
    /// - Throws: An error if decoding OID fails.
    ///
    /// - Returns: An instance of a subclass of ``SecurityInfo`` or `nil` if the OID is not recognized or supported.
    
    internal static func getInstance(node: ASN1Node) throws -> SecurityInfo? {
        guard case .constructed(let nodes) = node.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard let oidNode = nodes.firstChild else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard case .primitive(let oidBytes) = oidNode.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        let oid: ObjectIdentifier = .init(bytes: [UInt8](oidBytes))
        
        guard let securityInfo = SecurityInfoDecoder.decode(from: oid) else {
            return nil
        }
        
        return try securityInfo.init(oid: oid, data: nodes)
    }
}
