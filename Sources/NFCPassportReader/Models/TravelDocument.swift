//
//  TravelDocument.swift
//  
//
//  Created by Andrea Deluca on 14/09/23.
//

import Foundation

/// A structure representing a Travel Document, which includes information
/// parsed from the Machine Readable Zone (``MRZ``).
///
/// - SeeAlso: ``MRZ`` and ``TDType``

public struct TravelDocument {
    
    /// The type of the travel document (TD).
    
    public private(set) var type: TDType
    
    /// The Machine Readable Zone (MRZ) data parsed from the document.
    
    public private(set) var mrz: MRZ
    
    /// Initialize a ``TravelDocument`` instance with the provided MRZ data.
    ///
    /// - Parameter data: The MRZ data in the form of an array of bytes.
    ///
    /// - Throws: An error if the travel document type is not recognized.
    
    internal init(data: [UInt8]) throws {
        guard let type = TDType.of(length: data.count) else {
            throw NFCPassportReaderError.TravelDocumentTypeNotRecognized
        }
        
        self.type = type
        self.mrz = .init(bytes: data, type: type)
    }
}
