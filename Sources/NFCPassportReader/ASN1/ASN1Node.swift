//
//  ASN1Node.swift
//  
//
//  Created by Andrea Deluca on 08/09/23.
//

import Foundation

internal struct ASN1Node {
    private(set) var tag: ASN1Tag
    private(set) var content: Content
    private(set) var encodedBytes: ArraySlice<UInt8>
    
    internal var children: ASN1NodeCollection? {
        if case .constructed(let children) = content {
            return children
        } else { return nil }
    }
    
    internal var length: Int {
        switch content {
        case .constructed(let nodes): nodes.reduce(0) { (prev, node) in
            prev + node.length
        }
        case .primitive(let data): data.count
        }
    }

    internal init(tag: ASN1Tag, content: Content, encodedBytes: ArraySlice<UInt8>) {
        self.tag = tag
        self.content = content
        self.encodedBytes = encodedBytes
    }
    
    internal func checkTag(equalsTo tag: Int) -> Bool {
        self.tag == ASN1Tag.init(integerLiteral: tag)
    }
    
    internal enum Content {
        case constructed(ASN1NodeCollection)
        case primitive(ArraySlice<UInt8>)
    }
}
