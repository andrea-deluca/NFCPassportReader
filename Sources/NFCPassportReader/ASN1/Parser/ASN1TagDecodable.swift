//
//  ASN1TagDecodable.swift
//  
//
//  Created by Andrea Deluca on 19/09/23.
//

import Foundation

internal protocol ASN1TagDecodable {
    init?(rawValue: ASN1Tag)
    static func decode(from tag: ASN1Tag) -> Self?
}

internal extension ASN1TagDecodable {
    static func decode(from tag: ASN1Tag) -> Self? {
        Self.init(rawValue: tag)
    }
}
