//
//  DataGroup12.swift
//  
//
//  Created by Andrea Deluca on 05/09/23.
//

import Foundation

/// Represents Data Group 12 (`DG12`) from an ePassport and it contains document details of the passport.
///
/// `DG12` is used for additional information about the document.
///
/// - Note: Data elements within this group are all optional.
///
/// - SeeAlso: ``DocumentDetails`` and ``DataGroup``

internal final class DataGroup12: DataGroup {
    
    /// The document details extracted from the data group.
    
    private(set) var documentDetails: DocumentDetails?
    
    /// Initializes a ``DataGroup12`` instance with ASN.1 encoded data and a data group identifier.
    ///
    /// - Parameters:
    ///   - data: The ASN.1 encoded data for the data group.
    ///   - identifier: The identifier of the data group.
    ///
    /// - Throws: An error if decoding of the data group fails.
    
    internal required init(_ data: ASN1Node, identifier: DGTag) throws {
        try super.init(data, identifier: identifier)
    }
    
    /// Decodes the ASN.1 encoded data, extracting and storing the document details of the passport holder.
    ///
    /// - Parameter data: The ASN.1 encoded data for the data group.
    /// 
    /// - Throws: An error if decoding of document details fails.
    
    override internal func decode(_ data: ASN1Node) throws {
        guard case .constructed(let nodes) = data.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        self.documentDetails = try DocumentDetails(nodes: nodes)
    }
}
