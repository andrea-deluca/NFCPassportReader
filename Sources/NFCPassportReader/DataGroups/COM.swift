//
//  COM.swift
//  
//
//  Created by Andrea Deluca on 04/09/23.
//

import Foundation

/// A class representing the Common (`COM`) data group in an electronic passport.
///
/// It contains LDS (Logical Data Structure) version information, Unicode version information
/// and a list of the Data Groups that are present for the application.
///
/// - Note: The LDS1 eMRTD application must have only one file EF.COM that contains
/// the common information for the application.
///
/// - SeeAlso: ``DataGroup``

internal final class COM: DataGroup {
    
    /// The LDS version.
    
    private(set) var ldsVersion: String?
    
    /// The Unicode version.
    
    private(set) var unicodeVersion: String?
    
    /// An array of available data groups in the passport.
    
    private(set) var availableDataGroups: [DGTag] = []
    
    /// Initializes a ``COM`` instance with ASN.1 encoded data and a data group identifier.
    ///
    /// - Parameters:
    ///   - data: The ASN.1 encoded data for the COM data group.
    ///   - identifier: The identifier of the data group.
    ///
    /// - Throws: An error if decoding of the data group fails.
    
    internal required init(_ data: ASN1Node, identifier: DGTag) throws {
        try super.init(data, identifier: identifier)
    }
    
    /// Decodes the ASN.1 encoded data, extracting and storing information from the ``COM`` data group.
    ///
    /// - Parameter data: The ASN.1 encoded data for the COM data group.
    ///
    /// - Throws: An error if decoding of the data group fails.
    
    override internal func decode(_ data: ASN1Node) throws {
        guard case .constructed(let nodes) = data.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        try nodes.forEach { node in
            switch node.tag {
            case 0x5F01: try decodeLdsVersion(node)
            case 0x5F36: try decodeUnicodeVersion(node)
            case 0x5C: try decodeAvailableDataGroups(node)
            default: throw NFCPassportReaderError.UnexpectedResponseStructure
            }
        }
    }
}

private extension COM {
    
    /// Decodes and sets the LDS version.
    ///
    /// - Parameter node: The ASN.1 node containing the version information.
    /// - Throws: An error if decoding of the version fails.
    
    private func decodeLdsVersion(_ node: ASN1Node) throws {
        guard case .primitive(let versionBytes) = node.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        self.ldsVersion = self.parseVersion(versionBytes: [UInt8](versionBytes))
    }
    
    /// Decodes and sets the Unicode version.
    ///
    /// - Parameter node: The ASN.1 node containing the Unicode version information.
    /// - Throws: An error if decoding of the Unicode version fails.
    
    private func decodeUnicodeVersion(_ node: ASN1Node) throws {
        guard case .primitive(let versionBytes) = node.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        self.unicodeVersion = self.parseVersion(versionBytes: [UInt8](versionBytes))
    }
    
    /// Decodes and sets the available data groups in the passport.
    ///
    /// - Parameter node: The ASN.1 node containing the available data groups information.
    /// - Throws: An error if decoding of the available data groups fails.
    
    private func decodeAvailableDataGroups(_ node: ASN1Node) throws {
        guard case .primitive(let availableDataGroups) = node.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        availableDataGroups.forEach { tag in
            if let tag = DGTag.decode(from: ASN1Tag(integerLiteral: Int(tag))) {
                self.availableDataGroups.append(tag)
            }
        }
    }
}

private extension COM {
    
    /// Parses the version information from raw bytes and returns a formatted version string.
    ///
    /// - Parameter versionBytes: The raw bytes containing version information.
    /// - Returns: The formatted version string.
    
    private func parseVersion(versionBytes: [UInt8]) -> String? {
        var numbers: [Int?] = .init(repeating: nil, count: 3)
        
        for (idx, offset) in stride(from: 0, to: versionBytes.count, by: 2).enumerated() {
            numbers[idx] = Int(String(cString: Array(versionBytes[offset ..< offset + 2] + [0])))
        }
        
        if let major = numbers[0] {
            let minor = numbers[1] != nil ? ".\(numbers[1]!)" : ""
            let patch = numbers[2] != nil ? ".\(numbers[2]!)" : ""
            
            return String(major) + minor + patch
        }
        
        return nil
    }
}
