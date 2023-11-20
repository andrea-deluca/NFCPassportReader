//
//  DataGroup1.swift
//  
//
//  Created by Andrea Deluca on 04/09/23.
//

import Foundation

/// Represents Data Group 1 (`DG1`) from an ePassport. DG1 contains information about the travel document.
///
/// The Data Elements of `DG1` are intended to reflect the entire contents of the MRZ whether it
/// contains actual data or filler characters.
///
/// - Note: Details on the implementation of the ``MRZ`` are dependent on the type of LDS1 eMRTD (TD1, TD2 or TD3 formats).
///
/// - Note: `DG1` is required by the LDS of the eMRTD.
///
/// - Note: The ``MRZ`` is duplicated within `DG1` from the physical document.
///
/// - SeeAlso: ``TravelDocument``, ``TDType``, ``MRZ`` and ``DataGroup``

internal final class DataGroup1: DataGroup {
    
    /// The travel document object.
    
    private(set) var travelDocument: TravelDocument?
    
    /// Initializes a ``DataGroup1`` instance with ASN.1 encoded data and a data group identifier.
    ///
    /// - Parameters:
    ///   - data: The ASN.1 encoded data for the data group.
    ///   - identifier: The identifier of the data group.
    ///
    /// - Throws: An error if decoding of the data group fails.
    
    internal required init(_ data: ASN1Node, identifier: DGTag) throws {
        try super.init(data, identifier: identifier)
    }
    
    /// Decodes the ASN.1 encoded data, extracting and storing the associated travel document data.
    ///
    /// - Parameter data: The ASN.1 encoded data for the data group.
    ///
    /// - Throws: An error if decoding of the travel document fails.
    
    override internal func decode(_ data: ASN1Node) throws {
        guard data.children?.firstChild?.tag == 0x5F1F else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard case .primitive(let travelDocumentData) = data.children?.firstChild?.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        self.travelDocument = try TravelDocument(data: [UInt8](travelDocumentData))
    }
}
