//
//  CAPublicKeySecurityProtocol.swift
//  
//
//  Created by Andrea Deluca on 16/10/23.
//

import Foundation

/// `CAPublicKeySecurityProtocol` represents different security protocols for Chip Authentication Public Keys
/// in electronic Machine Readable Travel Documents (eMRTD).
///
/// - SeeAlso: ``ChipAuthenticationPublicKeyInfo``, ``ChipAuthenticationInfo``
/// ``ChipAuthenticationSecurityProtocol`` and ``ChipAuthenticationHandler``

internal enum CAPublicKeySecurityProtocol: UInt8, SecurityProtocol {
    /// Security Protocol for Chip Authentication Public Keys using DH (Diffie-Hellman).
    case ID_PK_DH = 0x01 // 0.4.0.127.0.7.2.2.1.1
    
    /// Security Protocol for Chip Authentication Public Keys using ECDH (Elliptic Curve Diffie-Hellman).
    case ID_PK_ECDH = 0x02 // 0.4.0.127.0.7.2.2.1.2
    
    /// The ``ObjectIdentifier`` (OID) associated with the security protocol.
    
    internal var oid: ObjectIdentifier {
        .init(SecurityObjectIdentifiers.ID_PK, bytes: self.rawValue)
    }
    
    /// Provides a default ``ChipAuthenticationSecurityProtocol`` based on
    /// the current ``CAPublicKeySecurityProtocol``.
    ///
    /// - Tip: Use it if the decoded ``ChipAuthenticationInfo`` does not provide
    ///   any ``ChipAuthenticationSecurityProtocol`` to use.
    ///
    /// - Returns: The default Chip Authentication Security Protocol to use.
    
    internal var defaultChipAuthenticationSecurityProtocol: ChipAuthenticationSecurityProtocol {
        if self == .ID_PK_DH {
            return .ID_CA_DH_3DES_CBC_CBC
        } else { return .ID_CA_ECDH_3DES_CBC_CBC }
    }
}
