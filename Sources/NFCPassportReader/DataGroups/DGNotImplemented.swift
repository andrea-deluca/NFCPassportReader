//
//  DGNotImplemented.swift
//  
//
//  Created by Andrea Deluca on 06/09/23.
//

import Foundation

/// A placeholder class for a data group that is not implemented.
///
/// - SeeAlso: ``DataGroup`` and ``DGDecoder``

internal final class DGNotImplemented: DataGroup {
    
    /// Initializes a new instance of an unimplemented data group.
    ///
    /// - Parameters:
    ///   - data: The ASN.1 encoded data for the unimplemented data group.
    ///   - identifier: The identifier specifying the type of the unimplemented data group.
    ///
    /// - Throws: An error ifiInitializing the unimplemented data group fails.
    
    internal required init(_ data: ASN1Node, identifier: DGTag) throws {
        try super.init(data, identifier: identifier)
    }
}
