//
//  DGTag.swift
//  
//
//  Created by Andrea Deluca on 04/09/23.
//

import Foundation

/// Enumeration of Data Group Tags used in ASN.1 encoding.
///
/// - SeeAlso: ``DataGroup`` and ``DGDecoder``

internal enum DGTag: ASN1Tag, CaseIterable {
    case COM = 0x60
    case DG1 = 0x61
    case DG2 = 0x75
    case DG3 = 0x63
    case DG4 = 0x76
    case DG5 = 0x65
    case DG6 = 0x66
    case DG7 = 0x67
    case DG8 = 0x68
    case DG9 = 0x69
    case DG10 = 0x6A
    case DG11 = 0x6B
    case DG12 = 0x6C
    case DG13 = 0x6D
    case DG14 = 0x6E
    case DG15 = 0x6F
    case DG16 = 0x70
    case SOD = 0x77
    
    /// Human-readable name for the Data Group.
    
    internal var name: String {
        switch self {
        case .COM: "COM"
        case .DG1: "DG1"
        case .DG2: "DG2"
        case .DG3: "DG3"
        case .DG4: "DG4"
        case .DG5: "DG5"
        case .DG6: "DG6"
        case .DG7: "DG7"
        case .DG8: "DG8"
        case .DG9: "DG9"
        case .DG10: "DG10"
        case .DG11: "DG11"
        case .DG12: "DG12"
        case .DG13: "DG13"
        case .DG14: "DG14"
        case .DG15: "DG15"
        case .DG16: "DG16"
        case .SOD: "SOD"
        }
    }
    
    /// Elementary File (EF) Identifier for the Data Group
    /// used to select and read it with APDU command.
    
    internal var EFIdentifier: [UInt8] {
        switch self {
        case .COM: [0x01, 0x1E]
        case .DG1: [0x01, 0x01]
        case .DG2: [0x01, 0x02]
        case .DG3: [0x01, 0x03]
        case .DG4: [0x01, 0x04]
        case .DG5: [0x01, 0x05]
        case .DG6: [0x01, 0x06]
        case .DG7: [0x01, 0x07]
        case .DG8: [0x01, 0x08]
        case .DG9: [0x01, 0x09]
        case .DG10: [0x01, 0x0A]
        case .DG11: [0x01, 0x0B]
        case .DG12: [0x01, 0x0C]
        case .DG13: [0x01, 0x0D]
        case .DG14: [0x01, 0x0E]
        case .DG15: [0x01, 0x0F]
        case .DG16: [0x01, 0x10]
        case .SOD: [0x01, 0x1D]
        }
    }
    
    /// Extracts the short EF Identifier from the ``EFIdentifier``.
    
    internal var shortEFIdentifier: UInt8 {
        self.EFIdentifier[1]
    }
    
    /// Retrieves the Data Group Tag from its human-readable name.
    ///
    /// - Parameter name: The Data Group name.
    ///
    /// - Returns: A Data Group Tag, if found.
    
    internal static func from(name: String) -> Self? {
        Self.allCases.first { $0.name == name }
    }
    
    /// Retrieves the Data Group Tag from its short EF Identifier.
    ///
    /// - Parameter shortIdentifier: The Data Group EF short identifier.
    ///
    /// - Returns: A Data Group Tag, if found
    
    internal static func from(shortIdentifier: UInt8) -> Self? {
        Self.allCases.first { $0.EFIdentifier[1] == shortIdentifier }
    }
}

extension DGTag: ASN1TagDecodable {}
