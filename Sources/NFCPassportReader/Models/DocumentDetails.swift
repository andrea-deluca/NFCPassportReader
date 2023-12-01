//
//  DocumentDetails.swift
//  
//
//  Created by Andrea Deluca on 24/10/23.
//

import Foundation

/// Represents document details extracted from an ASN.1 node collection derived
/// from the eMRTD `DataGroup12`.

public struct DocumentDetails {
    
    /// Storage for document details with ASN.1 tag mapping.
    
    private var details: [ASN1Tag: String] = [:]
    
    public var iussingAuthority: String? { details[0x5F19] }
    
    public var dateOfIssue: String? {
        if let date = details[0x5F26] {
            let strategy = Date.ParseStrategy(
                format: "\(year: .padded(4))\(month: .twoDigits)\(day: .twoDigits)",
                timeZone: TimeZone(identifier: "UTC")!
            )
            return try? Date(date, strategy: strategy).formatted(date: .abbreviated, time: .omitted)
        } else { return details[0x5F26] }
    }
    
    public var otherPersonDetails: String? { details[0xA0] }
    public var endorsementsOrObservations: String? { details[0x5F1B] }
    public var taxOrExitRequirements: String? { details[0x5F1C] }
    
    /// Front image data of the document.
    
    private(set) var frontImage: [UInt8]?
    
    /// Rear image data of the document.
    
    private(set) var rearImage: [UInt8]?
    
    public var personalizationTime: String? { details[0x5F55] }
    public var personalizationDeviceSerialNumber: String? { details[0x5F56] }
    
    /// Initializes ``DocumentDetails`` by extracting and decoding document details from an ASN.1 node collection
    /// derived from the eMRTD ``DataGroup12``.
    ///
    /// - Parameter nodes: ASN.1 node collection containing document details.
    ///
    /// - Throws: An error if decoding errors occur during the process.
    
    internal init(nodes: ASN1NodeCollection) throws {
        try nodes.forEach { documentDetailNode in
            switch documentDetailNode.tag {
            case 0x5F1D: self.frontImage = try Self.decodeImage(documentDetailNode)
            case 0x5F1E: self.rearImage = try Self.decodeImage(documentDetailNode)
            default: if let documentDetail = try? Self.decodeDocumentDetail(documentDetailNode) {
                details.updateValue(documentDetail, forKey: documentDetailNode.tag)
            }}
        }
    }
}

internal extension DocumentDetails {
    
    /// Decodes and extracts document details from an ASN.1 node.
    ///
    /// - Parameter documentDetailNode: ASN.1 node containing document details.
    /// - Throws: An error if decoding errors occur during the process.
    /// - Returns: Decoded document detail as a string.
    
    static private func decodeDocumentDetail(_ documentDetailNode: ASN1Node) throws -> String? {
        guard case .primitive(let documentDetailData) = documentDetailNode.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        if documentDetailNode.tag == 0x5F55 {
            return parseDatetime([UInt8](documentDetailData))
        }
        
        return String(bytes: [UInt8](documentDetailData), encoding: .utf8)
    }
    
    /// Decodes and extracts image data from an ASN.1 node.
    ///
    /// - Parameter documentImageNode: ASN.1 node containing image data.
    /// - Throws: An error if decoding errors occur during the process.
    /// - Returns: Extracted image data as an array of UInt8.
    
    static private func decodeImage(_ documentImageNode: ASN1Node) throws -> [UInt8] {
        guard case .primitive(let documentImageData) = documentImageNode.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        return [UInt8](documentImageData)
    }
}

extension DocumentDetails {
    
    /// Parses datetime data and returns it as a string.
    ///
    /// - Parameter data: Datetime data in the form of an array of UInt8.
    /// - Returns: Datetime as a string.
    
    static private func parseDatetime(_ data: [UInt8]) -> String? {
        if data.count == 4 {
            return decodeBCD(value: data)
        } else { return decodeASCII(value: data) }
    }
    
    /// Decodes Binary-Coded Decimal (BCD) data and returns it as a string.
    ///
    /// - Parameter value: BCD data in the form of an array of UInt8.
    /// - Returns: Decoded BCD value as a string.
    
    static private func decodeBCD(value: [UInt8]) -> String? {
        value.map { String(format: "%02X", $0) }.joined()
    }
    
    /// Decodes ASCII data and returns it as a string.
    ///
    /// - Parameter value: ASCII data in the form of an array of UInt8.
    /// - Returns: Decoded ASCII value as a string.
    
    static private func decodeASCII(value: [UInt8]) -> String? {
        String(bytes: value, encoding: .utf8)
    }
}
