//
//  ASN1NodeParser.swift
//  
//
//  Created by Andrea Deluca on 13/09/23.
//

import Foundation

internal struct ASN1NodeParser {
    private(set) var tag: ASN1Tag
    private(set) var depth: Int
    
    internal var isConstructed: Bool {
        tag.form == .constructed
    }
    
    internal var encodedBytes: ArraySlice<UInt8>
    internal var dataBytes: ArraySlice<UInt8>?
}
