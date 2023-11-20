//
//  PACEInfo.swift
//  
//
//  Created by Andrea Deluca on 18/09/23.
//

import Foundation
import OpenSSL

/// The `PACEInfo` class represents security information related to
/// the Password Authenticated Connection Establishment (PACE) protocol used for access the IC and
/// secure communication with an eMRTD chip.
///
/// PACE is used to protect sensitive data exchanges in electronic passports.
/// This class provides details about the specific PACE protocol used, including version and domain parameters.
///
/// The ASN.1 data structure `PACEInfo` is defined as follows:
///
///  ```
///  PACEInfo ::= SEQUENCE {
///     protocol OBJECT IDENTIFIER(
///         id-PACE-DH-GM-3DES-CBC-CBC |
///         id-PACE-DH-GM-AES-CBC-CMAC-128 |
///         id-PACE-DH-GM-AES-CBC-CMAC-192 |
///         id-PACE-DH-GM-AES-CBC-CMAC-256 |
///         id-PACE-ECDH-GM-3DES-CBC-CBC |
///         id-PACE-ECDH-GM-AES-CBC-CMAC-128 |
///         id-PACE-ECDH-GM-AES-CBC-CMAC-192 |
///         id-PACE-ECDH-GM-AES-CBC-CMAC-256 |
///         id-PACE-DH-IM-3DES-CBC-CBC |
///         id-PACE-DH-IM-AES-CBC-CMAC-128 |
///         id-PACE-DH-IM-AES-CBC-CMAC-192 |
///         id-PACE-DH-IM-AES-CBC-CMAC-256 |
///         id-PACE-ECDH-IM-3DES-CBC-CBC |
///         id-PACE-ECDH-IM-AES-CBC-CMAC-128 |
///         id-PACE-ECDH-IM-AES-CBC-CMAC-192 |
///         id-PACE-ECDH-IM-AES-CBC-CMAC-256 |
///         id-PACE-ECDH-CAM-AES-CBC-CMAC-128 |
///         id-PACE-ECDH-CAM-AES-CBC-CMAC-192 |
///         id-PACE-ECDH-CAM-AES-CBC-CMAC-256),
///     version INTEGER, -- MUST be 2,
///     parameterId INTEGER OPTIONAL
///  }
///  ```
///
/// This data structure provides detailed information on an implementation of PACE and
/// its components represent:
///
/// - `protocol`: An object identifier that identifies the algorithms to
///   be used (i.e. key agreement, symmetric cipher and MAC).
///
/// - `version`: An integer that identifies the version of the protocol. Currently,
///   only version 2 is supported by this specification.
///
/// - `parameterId`: An integer that is used to indicate the domain parameter identifier (optional).
///
/// - Important: `parameterId` must be used if the eMRTD chip uses ``StandardizedDomainParameters``,
///   provides multiple explicit domain parameters for PACE or protocol is one of the `*-CAM-*` OIDs.
///
/// - Important: In case of PACE with Chip Authentication Mapping, the `parameterId` also denotes the identifier of the Chip Authentication key used,
///   i.e. the IC must provide a ``ChipAuthenticationPublicKeyInfo`` with `keyId` equal to `parameterId` from this data structure.
///
/// - Note: It inherits from the ``SecurityInfo`` class.
///
/// - SeeAlso: ``PACESecurityProtocol``, ``PACEParametersDecoder``,
/// ``PACEMapping``, ``PACEHandler``, and ``StandardizedDomainParameters``

internal final class PACEInfo: SecurityInfo {
    
    /// The ``SecurityProtocol`` used for PACE.
    private(set) var securityProtocol: PACESecurityProtocol
    
    /// The standardized domain parameters associated with PACE, if available.
    private(set) var parameters: StandardizedDomainParameters?
    
    private(set) var version: Int?
    
    /// Check if the provided ``ObjectIdentifier`` (OID) is valid for PACE.
    ///
    /// - Parameter oid: The OID to check.
    ///
    /// - Returns: `true` if the OID is valid for PACE, `false` otherwise.
    
    internal static func checkRequiredIdentifier(_ oid: ObjectIdentifier) -> Bool {
        PACESecurityProtocol.isValid(oid: oid)
    }
    
    /// Initialize a ``PACEInfo`` instance with the given OID and ASN.1 data.
    ///
    /// - Parameters:
    ///   - oid: The ``ObjectIdentifier`` (OID) associated with the security information.
    ///   - data: The ASN.1 data containing security information.
    ///
    /// - Throws: An error if the security protocol cannot be determined from the provided OID.
    
    internal required init(oid: ObjectIdentifier, data: ASN1NodeCollection) throws {
        guard let securityProtocol = PACESecurityProtocol.from(oid: oid) else {
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
            if idx > 0 { try self.decodeParameters(node) }
            else { try self.decodeVersion(node) }
        }
    }
}

private extension PACEInfo {
    private func decodeVersion(_ node: ASN1Node) throws {
        guard case .primitive(let version) = node.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard BytesRepresentationConverter.convertToHexNumber(from: version) == 2 else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        self.version = Int(BytesRepresentationConverter.convertToHexNumber(from: version))
    }
    
    private func decodeParameters(_ node: ASN1Node) throws {
        guard case .primitive(let parametersId) = node.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard let parameters = PACEParametersDecoder.decode(
            parametersId: Int(BytesRepresentationConverter
                .convertToHexNumber(from: parametersId))
        ) else { throw NFCPassportReaderError.UnexpectedResponseStructure }
        
        self.parameters = parameters
    }
}
