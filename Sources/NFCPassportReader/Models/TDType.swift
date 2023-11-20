//
//  TDType.swift
//  
//
//  Created by Andrea Deluca on 14/09/23.
//

import Foundation

/// An enumeration representing the type of a travel document (TD) based on
/// the Machine Readable Zone (MRZ) structure.
///
/// According to the ICAO Document 9303 and ISO/IEC 7810 standard, there are three standardized document types
/// depending on the position and the size of the MRZ within the physical document.
///
/// - Note: MRZ is duplicated within the `DataGroup1` from the physical smart card.
///
/// - SeeAlso: ``MRZ`` and ``TravelDocument``

public enum TDType: String, CaseIterable {
    
    /// Type 1 travel document (TD1).
    case TD1
    
    /// Type 2 travel document (TD2).
    case TD2
    
    /// Type 3 travel document (TD3).
    case TD3
    
    /// A textual description of the travel document type.
    
    public var description: String {
        self.rawValue
    }
    
    /// The length of the MRZ code for the specific travel document type.
    ///
    /// - Note: TD1 documents are 90 characters long, TD2 ones are 72 characters long
    /// and TD3 ones are 88 characters long
    
    public var length: Int {
        switch self {
        case .TD1: 90
        case .TD2: 72
        case .TD3: 88
        }
    }
    
    /// Determine the ``TDType`` based on the given MRZ code length.
    ///
    /// - Parameter length: The length of the MRZ code.
    ///
    /// - Returns: The corresponding ``TDType``, if one is found; otherwise, `nil`.
    
    public static func of(length: Int) -> TDType? {
        Self.allCases.first { $0.length == length }
    }
}
