//
//  MRZKeyGenerator.swift
//
//
//  Created by Andrea Deluca on 07/09/23.
//

import Foundation

/// MRZKeyGenerator is a utility class for generating Machine Readable Zone (MRZ) keys for passports.

public final class MRZKeyGenerator {
    
    /// Generates an MRZ key based on the provided passport information.
    ///
    /// - Parameters:
    ///   - passportNumber: The passport number.
    ///   - dateOfBirth: The date of birth in the format "YYMMDD".
    ///   - dateOfExpiry: The date of expiry in the format "YYMMDD".
    ///
    /// - Returns: The generated MRZ key.
    
    public static func generate(passportNumber: String, dateOfBirth: String, dateOfExpiry: String) -> String {
        let paddedPassportNumber = pad(passportNumber, fieldLength: 9)
        let paddedDateOfBirth = pad(dateOfBirth, fieldLength: 6)
        let paddedDateOfExpiry = pad(dateOfExpiry, fieldLength: 6)
        
        let passportNumberChecksum = computeChecksum(for: paddedPassportNumber)
        let dateOfBirthChecksum = computeChecksum(for: paddedDateOfBirth)
        let dateOfExpiryChecksum = computeChecksum(for: paddedDateOfExpiry)
        
        return "\(paddedPassportNumber)\(passportNumberChecksum)\(paddedDateOfBirth)\(dateOfBirthChecksum)\(paddedDateOfExpiry)\(dateOfExpiryChecksum)"
    }
}

private extension MRZKeyGenerator {
    private static func pad(_ value: String, fieldLength: Int) -> String {
        String((value + String(repeating: "<", count: fieldLength)).prefix(fieldLength))
    }
    
    private static func computeChecksum(for value: String) -> Int {
        var sum = 0
        var m = 0
        let multipliers: [Int] = [7, 3, 1]
        for char in value {
            guard let lookup = characters[String(char)],
                  let number = Int(lookup) 
            else { return 0 }
            
            sum += number * multipliers[m]
            m = ( m + 1 ) % 3
        }
        
        return (sum % 10)
    }
}

private extension MRZKeyGenerator {
    private static let characters: [String: String] = [
        "0": "0",
        "1": "1",
        "2": "2",
        "3": "3",
        "4": "4",
        "5": "5",
        "6": "6",
        "7": "7",
        "8": "8",
        "9": "9",
        "<": "0",
        " ": "0",
        "A": "10",
        "B": "11",
        "C": "12",
        "D": "13",
        "E": "14",
        "F": "15",
        "G": "16",
        "H": "17",
        "I": "18",
        "J": "19",
        "K": "20",
        "L": "21",
        "M": "22",
        "N": "23",
        "O": "24",
        "P": "25",
        "Q": "26",
        "R": "27",
        "S": "28",
        "T": "29",
        "U": "30",
        "V": "31",
        "W": "32",
        "X": "33",
        "Y": "34",
        "Z": "35"
    ]
}
