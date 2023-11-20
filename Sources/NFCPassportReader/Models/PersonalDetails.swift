//
//  PersonalDetails.swift
//  
//
//  Created by Andrea Deluca on 24/10/23.
//

import Foundation

/// Represents personal details extracted from an ASN.1 data collection derived from
/// the eMRTD `DataGroup11`.

public struct PersonalDetails {
    
    /// Storage for personal details with ASN.1 tag mapping.

    private var details: [ASN1Tag: String] = [:]
    
    public var fullName: String? { details[0x5F0E] }
    public var personalNumber: String? { details[0x5F10] }
    public var dateOfBirth: String? { details[0x5F2B] }
    public var placeOfBirth: String? { details[0x5F11] }
    public var address: String? { details[0x5F42] }
    public var telephone: String? { details[0x5F12] }
    public var profession: String? { details[0x5F13] }
    public var title: String? { details[0x5F14] }
    public var personalSummary: String? { details[0x5F15] }
    public var proofOfCitizenship: String? { details[0x5F16] }
    public var tdNumbers: String? { details[0x5F17] }
    public var custodyInfo: String? { details[0x5F18] }
    
    /// Initializes ``PersonalDetails`` by extracting and decoding personal details from an ASN.1 node collection
    /// derived from eMRTD ``DataGroup11``.
    ///
    /// - Parameter nodes: ASN.1 node collection containing personal details.
    ///
    /// - Throws: An error if decoding errors occur during the process.
    
    internal init(nodes: ASN1NodeCollection) throws {
        nodes.forEach { personalDetailNode in
            if let personalDetail = try? Self.decodePersonalDetail(personalDetailNode) {
                details.updateValue(personalDetail, forKey: personalDetailNode.tag)
            }
        }
    }
    
    /// Decodes and extracts personal details from an ASN.1 node.
    ///
    /// - Parameter personalDetailNode: ASN.1 node containing personal details.
    ///
    /// - Throws: An error if decoding errors occur during the process.
    ///
    /// - Returns: Decoded personal detail as a string.
    
    private static func decodePersonalDetail(_ personalDetailNode: ASN1Node) throws -> String? {
        guard case .primitive(let personalDetailData) = personalDetailNode.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        return String(bytes: [UInt8](personalDetailData), encoding: .utf8)
    }
}
