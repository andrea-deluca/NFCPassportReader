//
//  DataGroup7.swift
//  
//
//  Created by Andrea Deluca on 05/09/23.
//

import Foundation
import UIKit

/// Represents Data Group 7 (DG7) from an ePassport. DG7 contains information about displayed signature.
///
/// - Note: DG7 is an optional Data Group and it may be not present within the eMRTD.
///
/// - SeeAlso: ``DataGroup``

internal final class DataGroup7: DataGroup {
    
    /// The binary data of the displayed signature.
    
    private(set) var displayedSignatureData: [UInt8]?
    
    /// The displayed signature image generated from the binary data.
    
    internal var displayedSignatureImage: UIImage? {
        if let displayedSignatureData = self.displayedSignatureData {
            return UIImage(data: Data(displayedSignatureData))
        } else { return nil }
    }
    
    /// Initializes a ``DataGroup7`` instance with ASN.1 encoded data and a data group identifier.
    ///
    /// - Parameters:
    ///   - data: The ASN.1 encoded data for the data group.
    ///   - identifier: The identifier of the data group.
    ///
    /// - Throws: An error if decoding of the data group fails.
    
    internal required init(_ data: ASN1Node, identifier: DGTag) throws {
        try super.init(data, identifier: identifier)
    }
    
    /// Decodes the ASN.1 encoded data, extracting and storing the binary displayed signature data.
    ///
    /// - Parameter data: The ASN.1 encoded data for the data group.
    /// 
    /// - Throws: An error if decoding of the displayed signature data fails.
    
    override internal func decode(_ data: ASN1Node) throws {
        guard case .constructed(let nodes) = data.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard case .primitive(let displayedSignature) = try nodes
            .first(where: { $0.tag == 0x5F43 })?.content
        else { throw NFCPassportReaderError.UnexpectedResponseStructure }
        
        self.displayedSignatureData = [UInt8](displayedSignature)
    }
}
