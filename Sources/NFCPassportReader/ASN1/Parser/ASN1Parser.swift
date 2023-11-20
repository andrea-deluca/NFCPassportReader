//
//  ASN1Parser.swift
//  
//
//  Created by Andrea Deluca on 08/09/23.
//

import Foundation

internal struct ASN1Parser {
    internal static func parse(_ data: [UInt8]) throws -> ASN1Node {
        return try parse(data[...])
    }
    
    internal static func parse(_ data: ArraySlice<UInt8>) throws -> ASN1Node {
        var result = try ASN1ParseResult.parse(data)
        let firstNode = result.nodes.removeFirst()
        let rootNode: ASN1Node
        let content: ASN1Node.Content
        
        if firstNode.isConstructed {
            let nodeCollection = result.nodes.prefix { $0.depth > firstNode.depth }
            result.nodes = result.nodes.dropFirst(nodeCollection.count)
            content = .constructed(ASN1NodeCollection(nodes: nodeCollection, depth: firstNode.depth))
        } else {
            content = .primitive(firstNode.dataBytes ?? [])
        }
        
        rootNode = ASN1Node(
            tag: firstNode.tag,
            content: content,
            encodedBytes: firstNode.encodedBytes
        )
        
        precondition(result.nodes.count == 0, "ASN1ParseResult unexpectedly allowed multiple root nodes")
        
        return rootNode
    }
}
