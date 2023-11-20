//
//  SecurityInfoDecoder.swift
//  
//
//  Created by Andrea Deluca on 13/10/23.
//

import Foundation

/// `SecurityInfoDecoder` is a class responsible for decoding security information based on the provided
/// ``ObjectIdentifier``. It maps specific object identifiers to their corresponding ``SecurityInfo`` types.
///
/// - SeeAlso: ``SecurityInfo``, ``SecurityProtocol``, ``SecurityObjectIdentifiers``,
/// ``ChipAuthenticationInfo``, ``ChipAuthenticationPublicKeyInfo`` and ``PACEInfo``

internal final class SecurityInfoDecoder {
    
    /// A mapping of ``ObjectIdentifier`` to ``SecurityInfo`` types. This mapping is used to determine
    /// the appropriate ``SecurityInfo`` type for a given ``ObjectIdentifier``.
    
    private static let typesMapping: [ObjectIdentifier: SecurityInfo.Type] = [
        SecurityObjectIdentifiers.ID_PK: ChipAuthenticationPublicKeyInfo.self,
        SecurityObjectIdentifiers.ID_CA: ChipAuthenticationInfo.self,
        SecurityObjectIdentifiers.ID_PACE: PACEInfo.self
    ]
    
    /// Decode a ``SecurityInfo`` type based on the provided ``ObjectIdentifier``.
    ///
    /// - Parameter oid: The ``ObjectIdentifier`` for which to determine the ``SecurityInfo`` type.
    ///
    /// - Returns: The ``SecurityInfo`` type associated with the provided ``ObjectIdentifier``, or `nil`
    ///            if no matching type is found.
    
    internal static func decode(from oid: ObjectIdentifier) -> SecurityInfo.Type? {
        // Search for the first mapping whose key is a prefix of the provided `oid`.
        typesMapping.first{ oid.starts(with: $0.key)}?.value
    }
}
