//
//  ASN1BasicEncoder.swift
//  
//
//  Created by Andrea Deluca on 26/09/23.
//

import Foundation
import CryptoTokenKit

internal final class ASN1BasicEncoder {
    internal static func encode(tag: UInt64, data: [UInt8]) -> [UInt8] {
        let berEncoded = TKBERTLVRecord.init(tag: TKTLVTag(tag), value: Data(data))
        return [UInt8](berEncoded.data)
    }
    
    internal static func encode(universalTag tag: ASN1UniversalTag, data: [UInt8]) -> [UInt8] {
        Self.encode(asn1Tag: tag.rawValue, data: data)
    }
    
    internal static func encode(asn1Tag tag: ASN1Tag, data: [UInt8]) -> [UInt8] {
        Self.encode(tag: UInt64(tag.rawValue), data: data)
    }
}
