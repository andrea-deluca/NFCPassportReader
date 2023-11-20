//
//  ObjectIdentifier.swift
//  
//
//  Created by Andrea Deluca on 18/09/23.
//

import Foundation

/// The `ObjectIdentifier` structure represents an Object Identifier (OID) commonly used
/// in various encoding and security protocols.
///
/// An OID is a sequence of integers separated by periods, used to uniquely
/// identify objects in a hierarchical naming structure.
///
/// - Tip: The structure provides methods for creating, encoding, and working with OIDs. It also
/// supports basic operations such as concatenation and checking if one OID starts with another.

internal struct ObjectIdentifier: Hashable {
    private var data: [UInt8]
    
    /// Initializes an ``ObjectIdentifier`` with an array of `UInt8` values.
    ///
    /// - Parameter bytes: An array of `UInt8` values representing the OID.
    
    internal init(bytes: [UInt8]) {
        var data = bytes
        if data.first == 0x00 {
            data.removeFirst()
        }
        self.data = data
    }
    
    /// Initializes an ``ObjectIdentifier`` with a variadic list of `UInt8` values.
    ///
    /// - Parameter bytes: A list of `UInt8` values representing the OID.
    
    internal init(bytes: UInt8...) {
        self.init(bytes: bytes)
    }
    
    /// Initializes an ``ObjectIdentifier`` by extending an existing ``ObjectIdentifier``
    /// with additional `UInt8` values.
    ///
    /// - Parameters:
    ///   - initialValue: The initial ``ObjectIdentifier`` to extend.
    ///   - bytes: A list of additional `UInt8` values to append.
    
    internal init(_ initialValue: ObjectIdentifier, bytes: UInt8...) {
        var data: [UInt8] = initialValue.data
        bytes.forEach { data.append($0) }
        self.init(bytes: data)
    }
    
    /// Initializes an ``ObjectIdentifier`` by decoding an array of `UInt8` values representing an ASN.1 encoded OID.
    ///
    /// - Parameter encoded: An array of `UInt8` values representing the encoded OID in ASN.1 format.
    ///
    /// - Throws: An error if decoding or parsing the OID fails.
    
    internal init(encoded: [UInt8]) throws {
        try self.init(node: try ASN1Parser.parse(encoded))
    }
    
    /// Initializes an ``ObjectIdentifier`` based on an ASN.1 node representing an OID.
    ///
    /// - Parameter node: An ``ASN1Node`` representing an OID in ASN.1 format.
    ///
    /// - Throws: An error if the provided `node` is not a valid ASN.1 OID.
    
    internal init(node: ASN1Node) throws {
        guard node.tag == ASN1UniversalTag.OBJECT_IDENTIFIER,
              case .primitive(let data) = node.content
        else { throw NFCPassportReaderError.InvalidDataPassed("Passed node does not represent an OID in ASN1 format") }
        self.init(bytes: [UInt8](data))
    }
    
    /// Encodes the ``ObjectIdentifier`` as an array of `UInt8` values with ASN.1 format.
    ///
    /// - Returns: An array of `UInt8` values representing the
    ///            ASN1 format encoded OID.
    
    internal func encode() -> [UInt8] {
        ASN1BasicEncoder.encode(universalTag: .OBJECT_IDENTIFIER, data: self.data)
    }
    
    /// Encodes the ``ObjectIdentifier`` as an array of `UInt8` values with a custom tag in ASN.1 format.
    ///
    /// - Parameter tag: The custom tag value to use in the encoding.
    /// - Returns: An array of `UInt8` values representing the ASN.1 format encoded OID with the specified custom tag.
    
    internal func encode(withTag tag: UInt64) -> [UInt8] {
        ASN1BasicEncoder.encode(tag: tag, data: self.data)
    }
}

internal extension ObjectIdentifier {
    
    /// Concatenates two ``ObjectIdentifier`` instances to create a new ``ObjectIdentifier``.
    ///
    /// - Parameters:
    ///   - rhs: The right-hand side ``ObjectIdentifier`` to concatenate.
    ///   - lhs: The left-hand side ``ObjectIdentifier`` to concatenate.
    ///
    /// - Returns: A new ``ObjectIdentifier`` created by concatenating `rhs` and `lhs`.
    
    static func +(rhs: ObjectIdentifier, lhs: ObjectIdentifier) -> ObjectIdentifier {
        .init(bytes: rhs.data + lhs.data)
    }
    
    /// Checks if the current ``ObjectIdentifier`` starts with
    /// another ``ObjectIdentifier``, indicating a prefix relationship between them.
    ///
    /// - Parameter other: The ``ObjectIdentifier`` to check as a prefix.
    ///
    /// - Returns: `true` if the current ``ObjectIdentifier`` starts with `other`; otherwise, `false`.
    
    func starts(with other: ObjectIdentifier) -> Bool {
        self.description.starts(with: other.description)
    }
    
    /// Removes the first `length` elements from the beginning of the data array.
    ///
    /// - Parameter length: The number of elements to remove from the beginning of the data array.
    ///
    /// This method modifies the underlying data array by removing the specified number of elements from the beginning.
    ///
    /// - Note: If the `length` parameter is greater than or equal to the size of the data array, the data array will be emptied.
    
    mutating func removeFirst(_ length: Int) {
        if self.data.count <= length { self.data = [] }
        self.data = [UInt8](self.data[length...])
    }
}

extension ObjectIdentifier: CustomStringConvertible {
    
    /// A human-readable string representation of the ``ObjectIdentifier``,
    /// joining its `UInt8` values with periods.
    
    var description: String {
        data.map({ String($0) }).joined(separator: ".")
    }
}

extension ObjectIdentifier: ExpressibleByStringLiteral {
    typealias StringLiteralType = String
    
    var rawValue: String { description }
    
    /// Initializes an ``ObjectIdentifier`` with a string literal.
    ///
    /// - Parameter value: A string representing the object identifier in dot notation (e.g., "1.2.3").
    ///
    /// This initializer splits the input string into its components, which are then converted to `UInt8` values.
    /// The resulting array of `UInt8` values is used to represent the object identifier.
    ///
    ///
    /// - Note: The input string should follow the dot notation for object identifiers.
    /// - Warning: If the input string cannot be parsed as a valid object identifier, a runtime error will occur.
    
    init(stringLiteral value: String) {
        self.data = value.split(separator: ".")
            .map({ UInt8($0)! })
    }
}

extension ObjectIdentifier: Equatable {
    
    /// Compares two ``ObjectIdentifier`` instances for equality based on
    /// their underlying `UInt8` data.
    ///
    /// - Parameters:
    ///   - rhs: The right-hand side ``ObjectIdentifier`` to compare.
    ///   - lhs: The left-hand side ``ObjectIdentifier`` to compare.
    ///
    /// - Returns: `true` if the `UInt8` data of `rhs` and `lhs` is equal; otherwise, `false`.
    
    static func ==(rhs: ObjectIdentifier, lhs: ObjectIdentifier) -> Bool {
        rhs.data == lhs.data
    }
}
