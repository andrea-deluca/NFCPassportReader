//
//  CardAccess.swift
//  
//
//  Created by Andrea Deluca on 04/10/23.
//

import Foundation

/// A class representing card access data from an ASN.1 encoded structure.
///
/// `CardAccess` is a transparent EF contained in the master file and is conditionally required
/// if the optional PACE access control is invoked.
///
/// - Note: It is required if PACE is supported by the eMRTD chip and shall contain the ``PACEInfo`` required for PACE.
///
/// - SeeAlso:  ``SecurityInfo``, ``PACEInfo``, ``PACEHandler``.

internal final class CardAccess {
    
    /// Elementary File (EF) Identifier used to select
    /// and read it with APDU command.
    
    internal static let EFIdentifier: [UInt8] = [0x01, 0x1C]
    
    /// An array of security information objects.
    
    private var securityInfos: [SecurityInfo] = []
    
    /// Retrieves the PACE (Password Authenticated Connection Establishment) information
    /// from the security information.
    
    internal var paceInfo: PACEInfo? {
        securityInfos.first { securityInfo in
            if let _ = securityInfo as? PACEInfo {
                return true
            } else { return false }
        } as? PACEInfo
    }
    
    /// Initializes a ``CardAccess`` instance by parsing ASN.1 encoded data.
    ///
    /// - Parameter data: The ASN.1 encoded data for card access information.
    ///
    /// - Throws: An error if parsing or instantiation of security information objects fails.
    
    internal required init(_ data: ASN1Node) throws {
        guard case .constructed(let nodes) = data.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        try nodes.forEach { node in
            if let securityInfo = try SecurityInfo.getInstance(node: node) {
                self.securityInfos.append(securityInfo)
            }
        }
    }
}
