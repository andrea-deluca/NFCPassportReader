//
//  PACESecurityProtocol.swift
//  
//
//  Created by Andrea Deluca on 16/10/23.
//

import Foundation

/// The `PACESecurityProtocol` enum represents various security protocols used in PACE for
/// electronic Machine Readable Travel Documents (eMRTD).
///
/// These protocols are identified by a unique ``ObjectIdentifier`` (OID) and
/// specific ``EncryptionAlgorithm``, ``KeyAgreementAlgorithm`` and ``PACEMapping`` function.
///
/// - SeeAlso: ``PACEInfo``, ``PACEMapping``, ``PACEParametersDecoder``
/// ``PACEHandler``, ``KeyAgreementAlgorithm`` and ``EncryptionAlgorithm``

internal enum PACESecurityProtocol: UInt8, SecurityProtocol {
    
    // MARK: DH-GM PACE Security Protocol Alternatives
    
    /// PACE security protocol using DH key agreement
    /// with Generic Mapping, 3DES encryption and CBC chaining mode.
    case ID_PACE_DH_GM_3DES_CBC_CBC = 0x01 // 0.4.0.127.0.7.2.2.4.1.1
    
    /// PACE security protocol using DH key agreement
    /// with Generic Mapping, AES-128 encryption and CMAC.
    case ID_PACE_DH_GM_AES_CBC_CMAC_128 = 0x02 // 0.4.0.127.0.7.2.2.4.1.2
    
    /// PACE security protocol using DH key agreement
    /// with Generic Mapping, AES-192 encryption and CMAC.
    case ID_PACE_DH_GM_AES_CBC_CMAC_192 = 0x03 // 0.4.0.127.0.7.2.2.4.1.3
    
    /// PACE security protocol using DH key agreement
    /// with Generic Mapping, AES-256 encryption and CMAC.
    case ID_PACE_DH_GM_AES_CBC_CMAC_256 = 0x04 // 0.4.0.127.0.7.2.2.4.1.4
    
    // MARK: ECDH-GM PACE Security Protocol Alternatives
    
    /// PACE security protocol using ECDH key agreement
    /// with Generic Mapping, 3DES encryption and CBC chaining mode.
    case ID_PACE_ECDH_GM_3DES_CBC_CBC = 0x05 // 0.4.0.127.0.7.2.2.4.2.1
    
    /// PACE security protocol using ECDH key agreement
    /// with Generic Mapping, AES-128 encryption and CMAC.
    case ID_PACE_ECDH_GM_AES_CBC_CMAC_128 = 0x06 // 0.4.0.127.0.7.2.2.4.2.2
    
    /// PACE security protocol using ECDH key agreement
    /// with Generic Mapping, AES-191 encryption and CMAC.
    case ID_PACE_ECDH_GM_AES_CBC_CMAC_192 = 0x07 // 0.4.0.127.0.7.2.2.4.2.3
    
    /// PACE security protocol using ECDH key agreement
    /// with Generic Mapping, AES-256 encryption and CMAC.
    case ID_PACE_ECDH_GM_AES_CBC_CMAC_256 = 0x08 // 0.4.0.127.0.7.2.2.4.2.4
    
    // MARK: DH-IM PACE Security Protocol Alternatives
    
    /// PACE security protocol using DH key agreement
    /// with Integrated Mapping, 3DES encryption and CBC chaining mode.
    case ID_PACE_DH_IM_3DES_CBC_CBC = 0x09 // 0.4.0.127.0.7.2.2.4.3.1
    
    /// PACE security protocol using DH key agreement
    /// with Integrated Mapping, AES-128 encryption and CMAC.
    case ID_PACE_DH_IM_AES_CBC_CMAC_128 = 0x0A // 0.4.0.127.0.7.2.2.4.3.2
    
    /// PACE security protocol using DH key agreement
    /// with Integrated Mapping, AES-192 encryption and CMAC.
    case ID_PACE_DH_IM_AES_CBC_CMAC_192 = 0x0B // 0.4.0.127.0.7.2.2.4.3.3
    
    /// PACE security protocol using DH key agreement
    /// with Integrated Mapping, AES-256 encryption and CMAC.
    case ID_PACE_DH_IM_AES_CBC_CMAC_256 = 0x0C // 0.4.0.127.0.7.2.2.4.3.4
    
    // MARK: ECDH-IM PACE Security Protocol Alternatives
    
    /// PACE security protocol using ECDH key agreement
    /// with Integrated Mapping, 3DES encryption and CBC chaining mode.
    case ID_PACE_ECDH_IM_3DES_CBC_CBC = 0x0D // 0.4.0.127.0.7.2.2.4.4.1
    
    /// PACE security protocol using ECDH key agreement
    /// with Integrated Mapping, AES-128 encryption and CMAC.
    case ID_PACE_ECDH_IM_AES_CBC_CMAC_128 = 0x0E // 0.4.0.127.0.7.2.2.4.4.2
    
    /// PACE security protocol using ECDH key agreement
    /// with Integrated Mapping, AES-192 encryption and CMAC.
    case ID_PACE_ECDH_IM_AES_CBC_CMAC_192 = 0x0F // 0.4.0.127.0.7.2.2.4.4.3
    
    /// PACE security protocol using ECDH key agreement
    /// with Integrated Mapping, AES-256 encryption and CMAC.
    case ID_PACE_ECDH_IM_AES_CBC_CMAC_256 = 0x10 // 0.4.0.127.0.7.2.2.4.4.4
    
    // MARK: ECDH-CAM PACE Security Protocol Alternatives
    
    /// PACE security protocol using ECDH key agreement
    /// with Chip Authentication Mapping, AES-128 encryption and CMAC.
    case ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 = 0x11 // 0.4.0.127.0.7.2.2.4.6.2
    
    /// PACE security protocol using ECDH key agreement
    /// with Chip Authentication Mapping, AES-192 encryption and CMAC.
    case ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 = 0x12 // 0.4.0.127.0.7.2.2.4.6.3
    
    /// PACE security protocol using ECDH key agreement
    /// with Chip Authentication Mapping, AES-256 encryption and CMAC.
    case ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 = 0x13 // 0.4.0.127.0.7.2.2.4.6.4
    
    /// The ``ObjectIdentifier`` (OID) representing the PACE security protocol.
    
    internal var oid: ObjectIdentifier {
        let specifications = ((self.rawValue - 1) % 4) + 1
        
        return switch (self.usedMappingFunction, self.usedKeyAgreementAlgorithm) {
        case (.GM, .DH): .init(Self.ID_PACE_DH_GM, bytes: specifications)
        case (.GM, .ECDH): .init(Self.ID_PACE_ECDH_GM, bytes: specifications)
        case (.IM, .DH): .init(Self.ID_PACE_DH_IM, bytes: specifications)
        case (.IM, .ECDH): .init(Self.ID_PACE_ECDH_IM, bytes: specifications)
        case (.CAM, .ECDH): .init(Self.ID_PACE_ECDH_CAM, bytes: specifications)
        default: fatalError("Unexpected Error decoding PACEProtocol OID")
        }
    }
    
    /// The ``EncryptionAlgorithm`` associated with the PACE security protocol.
    
    internal var usedEncryptionAlgorithm: EncryptionAlgorithm {
        return switch self {
        case .ID_PACE_DH_GM_3DES_CBC_CBC,
                .ID_PACE_DH_IM_3DES_CBC_CBC,
                .ID_PACE_ECDH_GM_3DES_CBC_CBC,
                .ID_PACE_ECDH_IM_3DES_CBC_CBC: .DESEDE2
        case .ID_PACE_DH_GM_AES_CBC_CMAC_128,
                .ID_PACE_DH_IM_AES_CBC_CMAC_128,
                .ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
                .ID_PACE_ECDH_IM_AES_CBC_CMAC_128,
                .ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: .AES(keySize: .AES128)
        case .ID_PACE_DH_GM_AES_CBC_CMAC_192,
                .ID_PACE_DH_IM_AES_CBC_CMAC_192,
                .ID_PACE_ECDH_GM_AES_CBC_CMAC_192,
                .ID_PACE_ECDH_IM_AES_CBC_CMAC_192,
                .ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: .AES(keySize: .AES192)
        case .ID_PACE_DH_GM_AES_CBC_CMAC_256,
                .ID_PACE_DH_IM_AES_CBC_CMAC_256,
                .ID_PACE_ECDH_GM_AES_CBC_CMAC_256,
                .ID_PACE_ECDH_IM_AES_CBC_CMAC_256,
                .ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: .AES(keySize: .AES256)
        }
    }
    
    /// The ``KeyAgreementAlgorithm`` associated with the PACE security protocol.
    
    internal var usedKeyAgreementAlgorithm: KeyAgreementAlgorithm {
        return switch self {
        case .ID_PACE_DH_GM_3DES_CBC_CBC,
                .ID_PACE_DH_IM_3DES_CBC_CBC,
                .ID_PACE_DH_GM_AES_CBC_CMAC_128,
                .ID_PACE_DH_IM_AES_CBC_CMAC_128,
                .ID_PACE_DH_GM_AES_CBC_CMAC_192,
                .ID_PACE_DH_IM_AES_CBC_CMAC_192,
                .ID_PACE_DH_GM_AES_CBC_CMAC_256,
                .ID_PACE_DH_IM_AES_CBC_CMAC_256: .DH
        default: .ECDH
        }
    }
    
    /// The ``PACEMapping`` associated with the PACE security protocol.
    
    internal var usedMappingFunction: PACEMapping {
        return switch self {
        case .ID_PACE_DH_GM_3DES_CBC_CBC,
                .ID_PACE_ECDH_GM_3DES_CBC_CBC,
                .ID_PACE_DH_GM_AES_CBC_CMAC_128,
                .ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
                .ID_PACE_DH_GM_AES_CBC_CMAC_192,
                .ID_PACE_ECDH_GM_AES_CBC_CMAC_192,
                .ID_PACE_DH_GM_AES_CBC_CMAC_256,
                .ID_PACE_ECDH_GM_AES_CBC_CMAC_256: .GM
        case .ID_PACE_ECDH_CAM_AES_CBC_CMAC_128,
                .ID_PACE_ECDH_CAM_AES_CBC_CMAC_192,
                .ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: .CAM
        default: .IM
        }
    }
}

private extension PACESecurityProtocol {
    // 0.4.0.127.0.7.2.2.4.1
    private static let ID_PACE_DH_GM: ObjectIdentifier =
        .init(SecurityObjectIdentifiers.ID_PACE, bytes: 0x01)
    
    // 0.4.0.127.0.7.2.2.4.2
    private static let ID_PACE_ECDH_GM: ObjectIdentifier =
        .init(SecurityObjectIdentifiers.ID_PACE, bytes: 0x02)
    
    // 0.4.0.127.0.7.2.2.4.3
    private static let ID_PACE_DH_IM: ObjectIdentifier =
        .init(SecurityObjectIdentifiers.ID_PACE, bytes: 0x03)
    
    // 0.4.0.127.0.7.2.2.4.4
    private static let ID_PACE_ECDH_IM: ObjectIdentifier =
        .init(SecurityObjectIdentifiers.ID_PACE, bytes: 0x04)
    
    // 0.4.0.127.0.7.2.2.4.6
    private static let ID_PACE_ECDH_CAM: ObjectIdentifier =
        .init(SecurityObjectIdentifiers.ID_PACE, bytes: 0x06)
}
