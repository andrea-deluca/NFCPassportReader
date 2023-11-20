//
//  SecurityObjectIdentifiers.swift
//  
//
//  Created by Andrea Deluca on 13/10/23.
//

import Foundation

/// The `SecurityObjectIdentifiers` structure defines a set of ``ObjectIdentifier`` (OIDs) used to represent
/// various security-related standards and specifications. These OIDs are commonly used in security protocols
/// and digital certificates to uniquely identify security algorithms and features.
///
/// The structure contains a set of private constants that define the components of OIDs
/// and then constructs various OIDs based on those components.
///
/// The OIDs included in this structure are organized into different categories, such as
/// ICAO ASN.1 Specifications and BSI TR 03111 ASN.1 Specifications, and are used to represent
/// specific security protocols, algorithms, and identifiers.
///
/// - SeeAlso: ``SecurityInfo``, ``SecurityInfoDecoder`` and ``SecurityProtocol``

internal struct SecurityObjectIdentifiers {
    
    // ICAO ASN.1 Specifications
    
    private static var JOINT_ISO_ITU_T: UInt8 = 2
    private static let INTERNATIONAL: UInt8 = 23
    private static let ICAO: UInt8 = 136
    
    // 2.23.136
    private static let ID_ICAO: ObjectIdentifier = .init(bytes: [JOINT_ISO_ITU_T, INTERNATIONAL, ICAO])
    // 2.23.136.1
    private static let ID_ICAO_MRTD: ObjectIdentifier = .init(ID_ICAO, bytes: 0x01)
    // 2.23.136.1.1
    internal static let ID_ICAO_MRTD_SECURITY: ObjectIdentifier = .init(ID_ICAO_MRTD, bytes: 0x01)
    
    // BSI TR 03111 ASN.1 Specifications
    
    private static let ITU_T: UInt8 = 0
    private static let IDENTIFIED_ORGANIZATION: UInt8 = 4
    private static let ETSI: UInt8 = 0
    private static let RESERVED: UInt8 = 127
    private static let ETSI_IDENTIFIED_ORGANIZATION: UInt8 = 0
    
    private static let ALGORITHMS: UInt8 = 1
    
    private static let SIGNATURES: UInt8 = 4
    
    private static let PROTOCOLS: UInt8 = 2
    private static let SMARTCARD: UInt8 = 2
    
    // 0.4.0.127.0.7
    private static let BSI_DE: ObjectIdentifier = .init(bytes: [ITU_T, IDENTIFIED_ORGANIZATION, ETSI, RESERVED, ETSI_IDENTIFIED_ORGANIZATION, 0x07])
    
    // 0.4.0.127.0.7.1.1
    private static let ID_ECC: ObjectIdentifier = .init(BSI_DE, bytes: ALGORITHMS, 0x01)
    
    // 0.4.0.127.0.7.1.1.4.1
    internal static let ECDSA_PLAIN_SIGNATURES: ObjectIdentifier = .init(ID_ECC, bytes: SIGNATURES, 0x01)
    
    // 0.4.0.127.0.7.2.2.1
    internal static let ID_PK: ObjectIdentifier = .init(BSI_DE, bytes: PROTOCOLS, SMARTCARD, 0x01)
    
    // 0.4.0.127.0.7.2.2.3
    internal static let ID_CA: ObjectIdentifier = .init(BSI_DE, bytes: PROTOCOLS, SMARTCARD, 0x03)
    
    // 0.4.0.127.0.7.2.2.4
    internal static let ID_PACE: ObjectIdentifier = .init(BSI_DE, bytes: PROTOCOLS, SMARTCARD, 0x04)
}
