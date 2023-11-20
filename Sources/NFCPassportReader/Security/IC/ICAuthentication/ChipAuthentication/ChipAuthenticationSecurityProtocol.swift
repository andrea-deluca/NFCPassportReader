//
//  ChipAuthenticationSecurityProtocol.swift
//  
//
//  Created by Andrea Deluca on 16/10/23.
//

import Foundation

/// The `ChipAuthenticationASecurityProtocol` enum represents various security protocols used in Chip Authentication for
/// electronic Machine Readable Travel Documents (eMRTD).
///
/// These protocols are identified by a unique ``ObjectIdentifier`` (OID) and
/// specific ``EncryptionAlgorithm`` and ``KeyAgreementAlgorithm``.
///
/// - SeeAlso: ``ChipAuthenticationInfo``, ``ChipAuthenticationPublicKeyInfo``,
/// ``CAPublicKeySecurityProtocol``, ``ChipAuthenticationHandler``, ``EncryptionAlgorithm`` and ``KeyAgreementAlgorithm``

internal enum ChipAuthenticationSecurityProtocol: UInt8, SecurityProtocol {
    
    // MARK: DH Chip Authentication Security Protocol Alternatives
    
    /// Chip Authentication security protocol using DH key agreement with 3DES encryption and CBC chaining mode.
    case ID_CA_DH_3DES_CBC_CBC = 0x01 // 0.4.0.127.0.7.2.2.3.1.1
    
    /// Chip Authentication security protocol using DH key agreement with AES-128 encryption and CMAC.
    case ID_CA_DH_AES_CBC_CMAC_128 = 0x02 // 0.4.0.127.0.7.2.2.3.1.2
    
    /// Chip Authentication security protocol using DH key agreement with AES-192 encryption and CMAC.
    case ID_CA_DH_AES_CBC_CMAC_192 = 0x03 // 0.4.0.127.0.7.2.2.3.1.3
    
    /// Chip Authentication security protocol using DH key agreement with AES-256 encryption and CMAC.
    case ID_CA_DH_AES_CBC_CMAC_256 = 0x04 // 0.4.0.127.0.7.2.2.3.1.4
    
    // MARK: ECDH Chip Authentication Security Protocol Alternatives
    
    /// Chip Authentication security protocol using ECDH key agreement with 3DES encryption and CBC chaining mode.
    case ID_CA_ECDH_3DES_CBC_CBC = 0x10 // 0.4.0.127.0.7.2.2.3.2.1
    
    /// Chip Authentication security protocol using ECDH key agreement with AES-128 encryption and CMAC.
    case ID_CA_ECDH_AES_CBC_CMAC_128 = 0x20 // 0.4.0.127.0.7.2.2.3.2.2
    
    /// Chip Authentication security protocol using ECDH key agreement with AES-192 encryption and CMAC.
    case ID_CA_ECDH_AES_CBC_CMAC_192 = 0x30 // 0.4.0.127.0.7.2.2.3.2.3
    
    /// Chip Authentication security protocol using ECDH key agreement with AES-256 encryption and CMAC.
    case ID_CA_ECDH_AES_CBC_CMAC_256 = 0x40 // 0.4.0.127.0.7.2.2.3.2.4
    
    /// The ``ObjectIdentifier`` (OID) representing the Chip Authentication security protocol.
    
    internal var oid: ObjectIdentifier {
        if self.rawValue & 0xF0 == 0 {
            return .init(Self.ID_CA_DH, bytes: self.rawValue)
        } else {
            return .init(Self.ID_CA_ECDH, bytes: self.rawValue >> 4)
        }
    }
    
    /// The ``EncryptionAlgorithm`` associated with the Chip Authentication security protocol.
    
    internal var usedEncryptionAlgorithm: EncryptionAlgorithm {
        return switch self {
        case .ID_CA_DH_3DES_CBC_CBC, .ID_CA_ECDH_3DES_CBC_CBC: .DESEDE2
        case .ID_CA_DH_AES_CBC_CMAC_128, .ID_CA_ECDH_AES_CBC_CMAC_128: .AES(keySize: .AES128)
        case .ID_CA_DH_AES_CBC_CMAC_192, .ID_CA_ECDH_AES_CBC_CMAC_192: .AES(keySize: .AES192)
        case .ID_CA_DH_AES_CBC_CMAC_256, .ID_CA_ECDH_AES_CBC_CMAC_256: .AES(keySize: .AES256)
        }
    }
    
    /// The ``KeyAgreementAlgorithm`` associated with the Chip Authentication security protocol.
    
    internal var usedKeyAgreementAlgorithm: KeyAgreementAlgorithm {
        return switch self {
        case .ID_CA_DH_3DES_CBC_CBC: .DH
        case .ID_CA_DH_AES_CBC_CMAC_128: .DH
        case .ID_CA_DH_AES_CBC_CMAC_192: .DH
        case .ID_CA_DH_AES_CBC_CMAC_256: .DH
        default: .ECDH
        }
    }
}

private extension ChipAuthenticationSecurityProtocol {
    // 0.4.0.127.0.7.2.2.3.1
    private static let ID_CA_DH: ObjectIdentifier =
        .init(SecurityObjectIdentifiers.ID_CA, bytes: 0x01)
    
    // 0.4.0.127.0.7.2.2.3.2
    private static let ID_CA_ECDH: ObjectIdentifier =
        .init(SecurityObjectIdentifiers.ID_CA, bytes: 0x02)
}
