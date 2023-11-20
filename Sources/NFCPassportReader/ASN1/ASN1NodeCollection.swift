//
//  ASN1NodeCollection.swift
//  
//
//  Created by Andrea Deluca on 08/09/23.
//

import Foundation

internal struct ASN1NodeCollection {
    private var nodes: ArraySlice<ASN1NodeParser>
    
    private(set) var depth: Int
    
    internal var children: ArraySlice<ASN1NodeParser> {
        self.nodes.filter { $0.depth == self.depth + 1 }
    }
    
    internal var count: Int { self.children.count }
    
    internal var firstChild: ASN1Node? {
        if let firstChild = children.first {
            do { return try ASN1Parser.parse(firstChild.encodedBytes)
            } catch { return nil }
        } else { return nil }
    }
    
    internal var contentBytes: [UInt8] {
        nodes.flatMap { node in
            [UInt8](node.encodedBytes)
        }
    }
    
    internal init(nodes: ArraySlice<ASN1NodeParser>, depth: Int) {
        self.nodes = nodes
        self.depth = depth
        
        precondition(self.nodes.allSatisfy { $0.depth > depth })
        if let firstDepth = self.nodes.first?.depth {
            precondition(firstDepth ==  depth + 1)
        }
    }
    
    internal func first(where conditionFn: (ASN1NodeParser) -> Bool) throws -> ASN1Node? {
        if let node = self.children.first(where: conditionFn) {
            return try ASN1Parser.parse([UInt8](node.encodedBytes))
        } else { return nil }
    }
    
    internal func first(withTag tag: Int) throws -> ASN1Node? {
        if let node = self.children.first(where: { $0.tag == ASN1Tag(integerLiteral: tag) }) {
            return try ASN1Parser.parse([UInt8](node.encodedBytes))
        } else { return nil }
    }
}

extension ASN1NodeCollection: Sequence {
    struct Iterator: IteratorProtocol {
        private(set) var nodes: ArraySlice<ASN1NodeParser>
        private(set) var depth: Int
        
        mutating func next() -> ASN1Node? {
            guard let nextNode = self.nodes.popFirst() else {
                return nil
            }
            
            assert(nextNode.depth ==  self.depth + 1)
            
            let content: ASN1Node.Content
            if nextNode.isConstructed {
                let nodeCollection = self.nodes.prefix { $0.depth > nextNode.depth }
                self.nodes = self.nodes.dropFirst(nodeCollection.count)
                content = .constructed(ASN1NodeCollection(nodes: nodeCollection, depth: nextNode.depth))
            } else {
                content = .primitive(nextNode.dataBytes ?? [])
            }
            
            return ASN1Node(
                tag: nextNode.tag,
                content: content,
                encodedBytes: nextNode.encodedBytes
            )
        }
    }
    
    func makeIterator() -> Iterator {
        Iterator(nodes: self.nodes, depth: self.depth)
    }
}
