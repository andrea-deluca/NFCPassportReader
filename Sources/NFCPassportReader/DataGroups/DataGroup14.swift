//
//  DataGroup14.swift
//  
//
//  Created by Andrea Deluca on 05/09/23.
//

import Foundation

/// A class representing Data Group 14 information from an ASN.1 encoded structure.
///
/// DG14 contains security options for additional supported security mechanisms, i.e. PACE, Chip Auhentication,
/// Active Authentication and Terminal Authentication.
///
/// - Note: It is required if Chip Authentication or PACE-GM/-IM is supported by the eMRTD chip.
///
/// - SeeAlso: ``DataGroup`` and ``SecurityInfo``

internal final class DataGroup14: DataGroup {
    
    /// An array of security information objects contained within Data Group 14.
    
    private(set) var securityInfos: [SecurityInfo] = []
    
    /// Initializes a `DataGroup14` instance with ASN.1 encoded data and a data group identifier.
    ///
    /// - Parameters:
    ///   - data: The ASN.1 encoded data for Data Group 14.
    ///   - identifier: The identifier of the data group.
    /// - Throws: An error if decoding or instantiation of security information objects fails.
    
    
    internal required init(_ data: ASN1Node, identifier: DGTag) throws {
        try super.init(data, identifier: identifier)
    }
    
    /// Decodes the ASN.1 encoded data, extracting and storing security information objects.
    ///
    /// - Parameter data: The ASN.1 encoded data for Data Group 14.
    /// - Throws: An error if decoding or instantiation of security information objects fails.
    
    
    override internal func decode(_ data: ASN1Node) throws {
        guard case .constructed(let nodes) = data.children?.firstChild?.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        try nodes.forEach { node in
            if let securityInfo = try SecurityInfo.getInstance(node: node) {
                self.securityInfos.append(securityInfo)
            }
        }
    }
}
