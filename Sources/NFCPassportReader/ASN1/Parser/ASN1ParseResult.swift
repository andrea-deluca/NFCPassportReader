//
//  ASN1ParseResult.swift
//  
//
//  Created by Andrea Deluca on 13/09/23.
//

import Foundation

internal struct ASN1ParseResult {
    private static let maximumNodeDepth = 50
    var nodes: ArraySlice<ASN1NodeParser>
    
    internal static func parse(_ data: [UInt8]) throws -> ASN1ParseResult {
        try parse(data[...])
    }

    internal static func parse(_ data: ArraySlice<UInt8>) throws -> ASN1ParseResult {
        var data = data
        var nodes = [ASN1NodeParser]()
        nodes.reserveCapacity(16)
        
        try parseNode(from: &data, depth: 1, into: &nodes)
        
        guard data.count == 0 else {
            throw ASN1ParserError.InvalidASN1Object("Trailing unparsed data is present")
        }
        
        return ASN1ParseResult(nodes: nodes[...])
    }
     
    internal static func parseNode(from data: inout [UInt8], depth: Int, into nodes: inout [ASN1NodeParser]) throws {
        try parseNode(from: &data[...], depth: depth, into: &nodes)
    }
    
    
    internal static func parseNode(from data: inout ArraySlice<UInt8>, depth: Int, into nodes: inout [ASN1NodeParser]) throws {
        guard depth <= Self.maximumNodeDepth else {
            throw ASN1ParserError.InvalidASN1Object("Excessive stack depth was reached")
        }
        
        let originalData = data
        
        var rawIdentifier: [UInt8] = [data.popFirst()!]
        if rawIdentifier[0] & 0x0F == 0x0F {
            rawIdentifier.append(data.popFirst()!)
        }
        
        let tag = ASN1Tag.init(integerLiteral: Int(BytesRepresentationConverter
            .convertToHexNumber(from: rawIdentifier)))
        
        guard let wideLength = data._readASN1Length() else {
            throw ASN1ParserError.TruncateASN1Field
        }
        
        guard let length = Int(exactly: wideLength) else {
            throw ASN1ParserError.InvalidASN1Object("Excessively large field: \(wideLength)")
        }
        
        var subData = data.prefix(length)
        data = data.dropFirst(length)
        
        guard subData.count == length else {
            throw ASN1ParserError.TruncateASN1Field
        }
        
        let encodedBytes = originalData[..<subData.endIndex]
        
        let node = ASN1NodeParser(
            tag: tag,
            depth: depth,
            encodedBytes: encodedBytes,
            dataBytes: tag.form == .constructed ? nil : subData
        )
        
        nodes.append(node)
        if tag.form == .constructed {
            while subData.count > 0 {
                try parseNode(from: &subData, depth: depth + 1, into: &nodes)
            }
        }
    }
}

private enum ASN1ParserError: Error {
    case InvalidASN1Object(String)
    case TruncateASN1Field
}
