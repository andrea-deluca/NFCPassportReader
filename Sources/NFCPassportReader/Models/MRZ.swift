//
//  MRZ.swift
//  
//
//  Created by Andrea Deluca on 26/10/23.
//

import Foundation

/// Structure for parsing and extracting data from a Machine Readable Zone (MRZ) of a travel document.
///
/// The MRZ typically contains information such as the document number,
/// holder's date of birth, expiry date, and more.
///
/// To use `MRZ`, provide a byte array representing the MRZ data and specify the type of
/// travel document (``TDType``) to determine the data structure.
///
/// `MRZ` provides methods to extract various data fields from the MRZ,
/// such as the document number, date of birth, expiry date, and so on,
/// based on the specified document type.
///
/// - Note: This structure is designed for parsing travel documents with Machine Readable Zones of
/// type 1 (TD1), type 2 (TD2), or type 3 (TD3) conforming to ICAO standards.
///
/// - SeeAlso: ``TDType`` and ``TravelDocument``

public struct MRZ {
    private var bytes: [UInt8]
    private var type: TDType
    
    public var code: String? { String(bytes: bytes, encoding: .utf8) }
    
    public var documentCode: String? {
        String(bytes: bytes[0..<2], encoding:.utf8)
    }
    
    public var issuingState: String? {
        String(bytes: bytes[2..<5], encoding:.utf8)
    }
    
    public var holderName: String? {
        let data = switch self.type {
        case .TD1: String(bytes: bytes[60...], encoding:.utf8)
        case .TD2: String(bytes: bytes[5..<36], encoding:.utf8)
        case .TD3: String(bytes: bytes[5..<44], encoding:.utf8)
        }
        
        if let components = data?.components(separatedBy: "<<") {
            let surname = components[0].components(separatedBy: "<").joined(separator: " ")
            let name = components[1].components(separatedBy: "<").joined(separator: " ")
            return [surname, name].joined(separator: " ")
        } else { return data }
    }
    
    internal var surname: String? {
        if let components = holderName?.components(separatedBy: "<<") {
            let surname = components[0].components(separatedBy: "<").joined(separator: " ")
            return surname
        } else { return nil }
    }
    
    internal var name: String? {
        if let components = holderName?.components(separatedBy: "<<") {
            let name = components[1].components(separatedBy: "<").joined(separator: " ")
            return name
        } else { return nil }
    }
    
    public var documentNumber: String? {
        switch self.type {
        case .TD1: String(bytes: bytes[5..<14], encoding:.utf8)
        case .TD2: String(bytes: bytes[36..<45], encoding:.utf8)
        case .TD3: String(bytes: bytes[44..<53], encoding:.utf8)
        }
    }
    
    public var documentNumberCheckDigit: String? {
        switch type {
        case .TD1: String(bytes: bytes[14..<15], encoding:.utf8)
        case .TD2: String(bytes: bytes[45..<46], encoding:.utf8)
        case .TD3: String(bytes: bytes[53..<54], encoding:.utf8)
        }
    }
    
    public var nationality: String? {
        switch self.type {
        case .TD1: String(bytes: bytes[45..<48], encoding:.utf8)
        case .TD2: String(bytes: bytes[46..<49], encoding:.utf8)
        case .TD3: String(bytes: bytes[54..<57], encoding:.utf8)
        }
    }
    
    public var dateOfBirth: String? {
        let date = switch self.type {
        case .TD1: String(bytes: bytes[30..<36], encoding:.utf8)
        case .TD2: String(bytes: bytes[49..<55], encoding:.utf8)
        case .TD3: String(bytes: bytes[57..<63], encoding:.utf8)
        }
        
        if let date = date {
            return self.parseDate(date: date)
        } else { return date }
    }
    
    public var dateOfBirthCheckDigit: String? {
        switch self.type {
        case .TD1: String(bytes: [bytes[36]], encoding:.utf8)
        case .TD2: String(bytes: [bytes[55]], encoding:.utf8)
        case .TD3: String(bytes: [bytes[63]], encoding:.utf8)
        }
    }
    
    public var sex: String? {
        switch self.type {
        case .TD1: String(bytes: [bytes[37]], encoding:.utf8)
        case .TD2: String(bytes: [bytes[56]], encoding:.utf8)
        case .TD3: String(bytes: [bytes[64]], encoding:.utf8)
        }
    }
    
    public var dateOfExpiry: String? {
        let date = switch self.type {
        case .TD1: String(bytes: bytes[38..<44], encoding:.utf8)
        case .TD2: String(bytes: bytes[57..<63], encoding:.utf8)
        case .TD3: String(bytes: bytes[65..<71], encoding:.utf8)
        }
        
        if let date = date {
            return self.parseDate(date: date)
        } else { return date }
    }
    
    public var dateOfExpiryCheckDigit: String? {
        switch self.type {
        case .TD1: String(bytes: [bytes[44]], encoding:.utf8)
        case .TD2: String(bytes: [bytes[63]], encoding:.utf8)
        case .TD3: String(bytes: [bytes[71]], encoding:.utf8)
        }
    }
    
    public var optionalData: String? {
        switch self.type {
        case .TD1:
            (String(bytes: bytes[15..<30], encoding:.utf8) ?? "") +
            (String(bytes: bytes[48..<59], encoding:.utf8) ?? "")
        case .TD2: String(bytes: bytes[64..<71], encoding:.utf8)
        case .TD3: String(bytes: bytes[72..<86], encoding:.utf8)
        }
    }
    
    public var checkDigit: String? {
        if self.type == .TD3 {
            String(bytes: [bytes[86]], encoding:.utf8)
        } else { nil }
    }
    
    public var compositeCheckDigit: String? {
        switch self.type {
        case .TD1: nil
        case .TD2: String(bytes: bytes[71..<72], encoding:.utf8)
        case .TD3: String(bytes: [bytes[87]], encoding:.utf8)
        }
    }
    
    /// Initialize ``MRZ`` from an array of bytes according to the specified
    /// provided ``TDType``.
    
    init(bytes: [UInt8], type: TDType) {
        self.bytes = bytes
        self.type = type
    }
}

internal extension MRZ {
    func parseDate(date: String) -> String? {
        let strategy = Date.ParseStrategy(
            format: "\(year: .twoDigits)\(month: .twoDigits)\(day: .twoDigits)",
            timeZone: TimeZone(identifier: "UTC")!
        )
        
        return try? Date(date, strategy: strategy).formatted(date: .abbreviated, time: .omitted)
    }
}
