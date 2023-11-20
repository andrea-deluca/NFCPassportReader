//
//  SecurityProtocol.swift
//  
//
//  Created by Andrea Deluca on 13/10/23.
//

import Foundation

/// The `SecurityProtocol` protocol defines a set of requirements for security protocol implementations.
///
/// Implementations of this protocol must provide an ``ObjectIdentifier`` (`oid`) value that represents
/// the identifier of the security protocol.
///
/// - SeeAlso: ``SecurityInfo``, ``SecurityInfoDecoder``, ``SecurityObjectIdentifiers``
/// ``ChipAuthenticationSecurityProtocol``, ``CAPublicKeySecurityProtocol`` and ``PACESecurityProtocol``

internal protocol SecurityProtocol: CaseIterable {
    var oid: ObjectIdentifier { get }
    
    /// Returns an instance of the ``SecurityProtocol`` based
    /// on the provided ``ObjectIdentifier``, if there is a match between
    /// the ``ObjectIdentifier`` and a protocol.
    ///
    /// - Parameter oid: The security protocol OID.
    ///
    /// - Returns: An instance of a security protocol.
    
    static func from(oid: ObjectIdentifier) -> Self?
    
    /// Checks if a given ``ObjectIdentifier`` corresponds
    /// to a valid ``SecurityProtocol``.
    ///
    /// - Parameter oid: The security protocol OID that has to be checked.
    ///
    /// - Returns: `true` if the given ``ObjectIdentifier`` is valid; `false` otherwise.
    
    static func isValid(oid: ObjectIdentifier) -> Bool
}

internal extension SecurityProtocol {
    static func from(oid: ObjectIdentifier) -> Self? {
        Self.allCases.first { $0.oid == oid }
    }
    
    static func isValid(oid: ObjectIdentifier) -> Bool {
        Self.allCases.contains { $0.oid == oid }
    }
}
