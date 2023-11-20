//
//  DisplayedMessage.swift
//  
//
//  Created by Andrea Deluca on 26/10/23.
//

import Foundation

internal enum DisplayedMessage {
    case requestPresentPassport
    case authenticatingWithPassport
    case readingDataGroupProgress(DGTag, Int)
    case error(NFCPassportReaderError)
    case successfulRead
}

internal extension DisplayedMessage {
    var description: String {
        return switch self {
        case .requestPresentPassport:
            "Hold your iPhone near an NFC readable document"
            
        case .authenticatingWithPassport:
            "Authenticating with passport..."
            
        case .readingDataGroupProgress(let dataGroup, let progress):
            "Reading \(dataGroup)...\n\n\(handleProgress(percentualProgress: progress))"
            
        case .error(let tagError):
            switch tagError {
            case .TagNotValid: "Tag not valid."
            case .MoreThanOneTagFound: "More than 1 tags was found. Please present only 1 tag."
            case .ConnectionError: "Connection error. Please try again."
            case .InvalidMRZKey: "MRZ Key not valid for this document."
            case .ResponseError(_, let reason, let sw1, let sw2):
                "Sorry, there was a problem reading the passport. \(reason). Error codes: [0x\(sw1), 0x\(sw2)]"
            default: "Sorry, there was a problem reading the passport. Please try again"
            }
            
        case .successfulRead: "Passport read successfully"
        }
    }
    
    func handleProgress(percentualProgress: Int) -> String {
        let p = (percentualProgress/20)
        let full = String(repeating: "🟢 ", count: p)
        let empty = String(repeating: "⚪️ ", count: 5-p)
        return "\(full)\(empty)"
    }
}
