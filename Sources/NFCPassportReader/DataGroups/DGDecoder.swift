//
//  DGDecoder.swift
//  
//
//  Created by Andrea Deluca on 04/09/23.
//

import Foundation

/// A utility class for decoding data groups from ASN.1 encoded data.
///
/// - SeeAlso: ``DataGroup`` and ``DGTag``

internal final class DGDecoder {
    
    /// A dictionary mapping DGTag values to their corresponding data group classes.
    
    private static let classes: [DGTag:DataGroup.Type] = [
        .COM: COM.self,
        .DG1: DataGroup1.self,
        .DG2: DataGroup2.self,
        .DG3: DGNotImplemented.self, // DG3 Not Implemented
        .DG4: DGNotImplemented.self, // DG4 Not Implemented
        .DG5: DGNotImplemented.self, // DG5 Not Implemented
        .DG6: DGNotImplemented.self, // DG6 Not Implemented
        .DG7: DataGroup7.self,
        .DG8: DGNotImplemented.self, // DG8 Not Implemented
        .DG9: DGNotImplemented.self, // DG9 Not Implemented
        .DG10: DGNotImplemented.self, // DG10 Not Implemented
        .DG11: DataGroup11.self,
        .DG12: DataGroup12.self,
        .DG13: DGNotImplemented.self, // DG13 Not Implemented
        .DG14: DataGroup14.self,
        .DG15: DGNotImplemented.self, // DG15 Not Implemented
        .DG16: DGNotImplemented.self, // DG16 Not Implemented
        .SOD: SOD.self
    ]
    
    /// Decodes a data group from ASN.1 encoded data.
    ///
    /// - Parameter data: The ASN.1 encoded data for the data group.
    ///
    /// - Throws: An error if decoding the data group fails or if the data group tag is unknown.
    ///
    /// - Returns: The decoded data group instance.
    
    internal static func decode(data: [UInt8]) throws -> DataGroup {
        let data = try ASN1Parser.parse(data)
        
        guard let tag = DGTag.decode(from: data.tag),
              let dataGroup = DGDecoder.classes[tag] else {
            throw NFCPassportReaderError.UnknownTag
        }
        
        return try dataGroup.init(data, identifier: tag)
    }
}
