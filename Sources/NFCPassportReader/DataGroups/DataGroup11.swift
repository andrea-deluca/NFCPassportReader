//
//  DataGroup11.swift
//  
//
//  Created by Andrea Deluca on 05/09/23.
//

import Foundation

/// Represents Data Group 11 (`DG11`) from an ePassport that contains personal details of the passport holder.
///
/// `DG11` is used for additional details about the document holder.
///
/// - Note: Data elements within this group are all optional.
///
/// - SeeAlso: ``PersonalDetails`` and ``DataGroup``

internal final class DataGroup11: DataGroup {
    
    /// The personal details extracted from the data group.
    
    private(set) var personalDetails: PersonalDetails?
    
    /// Initializes a ``DataGroup11`` instance with ASN.1 encoded data and a data group identifier.
    ///
    /// - Parameters:
    ///   - data: The ASN.1 encoded data for the data group.
    ///   - identifier: The identifier of the data group.
    ///
    /// - Throws: An error if decoding of the data group fails.
    
    internal required init(_ data: ASN1Node, identifier: DGTag) throws {
        try super.init(data, identifier: identifier)
    }
    
    /// Decodes the ASN.1 encoded data, extracting and storing the personal details of the passport holder.
    ///
    /// - Parameter data: The ASN.1 encoded data for the data group.
    ///
    /// - Throws: An error if decoding of personal details fails.
    
    override internal func decode(_ data: ASN1Node) throws {
        guard case .constructed(let nodes) = data.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        self.personalDetails = try PersonalDetails(nodes: nodes)
    }
}
