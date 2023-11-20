// 
//  ASN1Tag.swift
//  
//
//  Created by Andrea Deluca on 19/09/23.
//

import Foundation

internal final class ASN1Tag: ExpressibleByIntegerLiteral {
    private(set) var rawValue: Int
    
    internal var `class`: ASN1TagClass {
        .init(tag: BytesRepresentationConverter
            .convertToBinaryRepresentation(from: UInt64(self.rawValue)))
    }
    
    internal var form: ASN1TagForm {
        .init(tag: BytesRepresentationConverter
            .convertToBinaryRepresentation(from: UInt64(self.rawValue)))
    }
    
    internal var number: Int {
        self.rawValue & 0x001F
    }
    
    internal required init(integerLiteral value: Int){
        self.rawValue = value
    }
}

extension ASN1Tag: CustomStringConvertible {
    var description: String {
        BytesRepresentationConverter
            .converToHexRepresentation(from: UInt64(self.rawValue))
    }
}

extension ASN1Tag: Equatable {
    static func == (lhs: ASN1Tag, rhs: ASN1Tag) -> Bool {
        lhs.rawValue == rhs.rawValue
    }
    
    static func == (lhs: ASN1Tag, rhs: ASN1UniversalTag) -> Bool {
        lhs == rhs.rawValue
    }
}

extension ASN1Tag: Hashable {
    func hash(into hasher: inout Hasher) {}
}

enum ASN1TagClass: UInt8, Hashable, Sendable {
    case universal = 0x00
    case application = 0x01
    case context = 0x02
    case `private` = 0x03
    
    init(tag: UInt8) {
        switch tag >> 6 {
        case 0x00: self = .universal
        case 0x01: self = .application
        case 0x02: self = .context
        case 0x03: self = .private
        default: fatalError("Unreachable")
        }
    }
    
    init(tag: [UInt8]) {
        self.init(tag: tag[0])
    }
}

enum ASN1TagForm: Hashable, Sendable {
    case primitive
    case constructed
    
    init(tag: UInt8) {
        switch (tag >> 5) & 0x01 {
        case 0x00: self = .primitive
        case 0x01: self = .constructed
        default: fatalError("Unreachable")
        }
    }
    
    init(tag: [UInt8]) {
        self.init(tag: tag[0])
    }
}
