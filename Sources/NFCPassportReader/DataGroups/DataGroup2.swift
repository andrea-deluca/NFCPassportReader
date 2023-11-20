//
//  DataGroup2.swift
//  
//
//  Created by Andrea Deluca on 05/09/23.
//

import Foundation
import UIKit

/// Represents Data Group 2 (`DG2`) from an ePassport and it contains biometric data related to the passport holder's face.
///
/// `DG2` represents the globally interoperable biometric for machine assisted identity confirmation with
/// machine readable travel documents, which shall be an image of the face of the holder as an input
/// to a face recognition system. If there is more than one recording, the most recent internationally
/// interoperable encoding shall be the first entry.
///
/// - Note: This Data Group must use the Biometric Information Template (BIT) group template with nested BITs specified
/// in ISO/IEC 7816-11, which allows the possibility to store multiple biometric templates and is in harmony with the CBEFF.
///
/// - Note: To facilitate interoperability, the first biometric recorded in each Data Group
/// shall be encoded as per ISO/IEC19794-5.
///
/// - Note: `DG2` is required by the LDS of the eMRTD.
///
/// - SeeAlso: ``FaceBiometricDataEncoding`` and ``DataGroup``

internal final class DataGroup2: DataGroup {
    
    /// The number of facial images stored in this data group.
    
    private(set) var numberOfImages: Int = 0
    
    /// The encoding format of the face biometric data.
    
    private(set) var faceBiometricDataEncoding: FaceBiometricDataEncoding?
    
    /// Initializes a ``DataGroup2`` instance with ASN.1 encoded data and a data group identifier.
    ///
    /// - Parameters:
    ///   - data: The ASN.1 encoded data for the data group.
    ///   - identifier: The identifier of the data group.
    ///
    /// - Throws: An error if decoding of the data group fails.
    
    internal required init(_ data: ASN1Node, identifier: DGTag) throws {
        try super.init(data, identifier: identifier)
    }
    
    /// Decodes the ASN.1 encoded data, extracting and storing the number of
    /// face images and the face biometric data encoding.
    ///
    /// - Parameter data: The ASN.1 encoded data for the data group.
    ///
    /// - Throws: An error if decoding of the face biometric data fails.
    
    override internal func decode(_ data: ASN1Node) throws {
        guard data.children?.firstChild?.tag == 0x7F61 else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard case .constructed(let nodes) = data.children?.firstChild?.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard case .primitive(let numberOfImages) = try nodes
            .first(where: { $0.tag == ASN1UniversalTag.INTEGER })?.content
        else { throw NFCPassportReaderError.UnexpectedResponseStructure }
        
        self.numberOfImages = Int(BytesRepresentationConverter
            .convertToHexNumber(from: numberOfImages))
        
        guard case .constructed(let biometricInfo) = try nodes
            .first(where: { $0.tag == 0x7F60 })?.content
        else { throw NFCPassportReaderError.UnexpectedResponseStructure }
        
        guard case .primitive(let biometricDataBlock) = try biometricInfo
            .first(where: { $0.tag == 0x5F2E || $0.tag == 0x7F2E})?.content
        else { throw NFCPassportReaderError.UnexpectedResponseStructure }
        
        self.faceBiometricDataEncoding = try FaceBiometricDataEncoding
            .parseISO19794_5(data: [UInt8](biometricDataBlock))
    }
}
