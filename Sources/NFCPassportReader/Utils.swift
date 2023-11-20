//
//  Utils.swift
//  
//
//  Created by Andrea Deluca on 04/09/23.
//

import Foundation
import CryptoTokenKit
import OpenSSL



// MARK: - Utility Typealiases



internal typealias Byte = UInt8
internal typealias HexadecimalNumber = UInt64
internal typealias BinaryRepresentation = [UInt8]
internal typealias HexRepresentation = String



// MARK: - Utility Classes



/// Utility class for converting between binary and hexadecimal representations.

internal final class BytesRepresentationConverter {
    
    // MARK: Convert to Binary Representation
    
    /// Convert a hexadecimal number to a binary representation.
    ///
    /// - Parameters:
    ///   - hex: The hexadecimal number (`UInt64`) to convert.
    ///   - hexDigits: The minimum number of hexadecimal digits to consider (default is 2).
    ///
    /// - Returns: A binary representation (`[UInt8]`).
    
    internal static func convertToBinaryRepresentation(from hex: HexadecimalNumber, withAtLeastHexDigits hexDigits: Int = 2) -> BinaryRepresentation {
        Self.convertToBinaryRepresentation(from: String(format: "%0\(hexDigits)X", hex))
    }
    
    /// Convert a hexadecimal representation to a binary representation.
    ///
    /// - Parameter hex: The hexadecimal representation (`String`) to convert.
    ///
    /// - Returns: A binary representation (`[UInt8]`).
    
    internal static func convertToBinaryRepresentation(from hex: HexRepresentation) -> BinaryRepresentation {
        var output: [UInt8] = []
        var x = 0
        
        while x < hex.count {
            if x + 2 <= hex.count { output.append(Byte(hex[x ..< x+2], radix: 16)!)
            } else { output.append(Byte(hex[x ..< x+1], radix: 16)!) }
            
            x += 2
        }
        
        return output
    }
    
    // MARK: Convert to Hex Representation
    
    /// Convert a byte to a hexadecimal representation.
    ///
    /// - Parameter byte: The byte (`UInt8`) to convert.
    ///
    /// - Returns: A hexadecimal representation (`String`).
    
    internal static func convertToHexRepresentation(from byte: Byte) -> HexRepresentation {
        String(format: "%02X", byte)
    }
    
    /// Convert a slice of bytes to a hexadecimal representation.
    ///
    /// - Parameter bytes: The slice of bytes (`ArraySlice<UInt8>`) to convert.
    ///
    /// - Returns: A hexadecimal representation (`String`).
    
    internal static func convertToHexRepresentation(from bytes: ArraySlice<Byte>) -> HexRepresentation {
        Self.convertToHexRepresentation(from: [Byte](bytes))
    }
    
    /// Convert a sequence of bytes to a hexadecimal representation.
    ///
    /// - Parameter bytes: The sequence of bytes (`[UInt8]`) to convert.
    ///
    /// - Returns: A hexadecimal representation (`String`).
    
    internal static func convertToHexRepresentation(from bytes: BinaryRepresentation) -> HexRepresentation {
        var output = ""
        bytes.forEach { byte in
            output += Self.convertToHexRepresentation(from: byte)
        }
        return output.uppercased()
    }
    
    /// Convert a hexadecimal number to a hexadecimal representation.
    ///
    /// - Parameter hex: The hexadecimal number (`UInt64`) to convert.
    ///
    /// - Returns: A hexadecimal representation (`String`).
    
    internal static func converToHexRepresentation(from hex: HexadecimalNumber) -> HexRepresentation {
        Self.convertToHexRepresentation(from: Self.convertToBinaryRepresentation(from: hex))
    }
    
    // MARK: Convert to Hex Number
    
    /// Convert a byte to a hexadecimal number.
    ///
    /// - Parameter byte: The byte (`UInt8`) to convert.
    ///
    /// - Returns: A hexadecimal number (`UInt64`).
    
    
    internal static func convertToHexNumber(from byte: Byte) -> HexadecimalNumber {
        UInt64(Self.convertToHexRepresentation(from: byte), radix: 16)!
    }
    
    /// Convert a slice of bytes to a hexadecimal number.
    ///
    /// - Parameter bytes: The slice of bytes (`ArraySlice<UInt8>`) to convert.
    ///
    /// - Returns: A hexadecimal number (`UInt64`).
    
    internal static func convertToHexNumber(from bytes: ArraySlice<Byte>) -> HexadecimalNumber {
        Self.convertToHexNumber(from: [Byte](bytes))
    }
    
    /// Convert a sequence of bytes to a hexadecimal number.
    ///
    /// - Parameter bytes: The sequence of bytes (`[UInt8]`) to convert.
    ///
    /// - Returns: A hexadecimal number (`UInt64`).
    
    internal static func convertToHexNumber(from bytes: BinaryRepresentation) -> HexadecimalNumber {
        UInt64(Self.convertToHexRepresentation(from: bytes), radix: 16)!
    }
}



/// Utility class for padding and unpadding data to a specific block size.

internal final class DataPadder {
    
    /// Pad a `Data` object to the specified block size.
    ///
    /// - Parameters:
    ///   - data: The `Data` to be padded.
    ///   - size: The desired block size.
    ///
    /// - Returns: Padded data as an array of `UInt8`.
    
    internal static func pad(data: Data, blockSize size: Int) -> [UInt8] {
        Self.pad(data: [UInt8](data), blockSize: size)
    }
    
    /// Pad a byte array to the specified block size.
    ///
    /// - Parameters:
    ///   - data: The byte array to be padded.
    ///   - size: The desired block size.
    ///
    /// - Returns: Padded data as an array of `UInt8`.
    
    internal static func pad(data: [UInt8], blockSize size: Int) -> [UInt8] {
        var result = data + [0x80]
        while result.count % size != 0 {
            result.append(0x00)
        }
        return result
    }
    
    /// Remove padding from a padded byte array.
    ///
    /// - Parameter data: The padded byte array.
    ///
    /// - Returns: The original data with padding removed.
    
    internal static func unpad(data: [UInt8]) -> [UInt8] {
        var i = data.count - 1
        while data[i] == 0x00 {
            i -= 1
        }
        
        if data[i] == 0x80 {
            return [UInt8](data[0 ..< i])
        } else {
            // No padding
            return data
        }
    }
}



// MARK: - Utility Extensions



/// An extension to StringProtocol that adds subscripting for countable closed and open ranges.

private extension StringProtocol {
    
    /// Subscripting with a countable closed range.
    ///
    /// - Parameters:
    ///   - bounds: The countable closed range of indices.
    ///
    /// - Returns: The subsequence of characters within the specified range.
    
    subscript(bounds: CountableClosedRange<Int>) -> SubSequence {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(start, offsetBy: bounds.count)
        return self[start..<end]
    }
    
    /// Subscripting with a countable open range.
    ///
    /// - Parameters:
    ///   - bounds: The countable open range of indices.
    ///
    /// - Returns: The subsequence of characters within the specified range.
    
    subscript(bounds: CountableRange<Int>) -> SubSequence {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(start, offsetBy: bounds.count)
        return self[start..<end]
    }
    
    /// Find the index of a substring within the string.
    ///
    /// - Parameters:
    ///   - string: The substring to search for.
    ///   - options: String comparison options.
    ///
    /// - Returns: The index of the first occurrence of the substring, or nil if not found.
    
    func index(of string: Self, options: String.CompareOptions = []) -> Index? {
        return range(of: string, options: options)?.lowerBound
    }
    
}



/// An extension to `String` that adds initializer from a `BIO` buffer pointer from OpenSSL.

internal extension String {
    
    /// Initialize a `String` from data read from an OpenSSL `BIO` object.
    ///
    /// - Parameter bio: An `OpaquePointer` representing the OpenSSL `BIO` object to read data from.
    ///
    /// - Important: If the `BIO` object does not contain valid data or reading it fails,
    /// this initializer will result in a fatal error.
    
    init(bio: OpaquePointer) {
        let len = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
        var buffer = [CChar](repeating: 0, count: len+1)
        
        guard BIO_read(bio, &buffer, Int32(len)) >= 0 else {
            fatalError("An error occurs reading the BIO object")
        }
        
        // Ensure last value is 0 (null terminated)
        // otherwise we get buffer overflow!
        
        buffer[len] = 0
        
        self = String(cString:buffer)
    }
}



/// An extension to arrays of UInt8 that provides exclusive OR (XOR) functionality
/// and a random generator of a specified size.

internal extension [UInt8] {
    
    /// Perform an exclusive OR (XOR) operation between two byte arrays.
    ///
    /// - Parameters:
    ///   - rhs: The right-hand side byte array.
    ///   - lhs: The left-hand side byte array.
    ///
    /// - Returns: The result of the XOR operation as a byte array.
    
    static func xor(_ rhs: [UInt8], _ lhs: [UInt8]) -> [UInt8] {
        var result = [UInt8]()
        for i in 0 ..< rhs.count {
            result.append(rhs[i] ^ lhs[i])
        }
        return result
    }
    
    /// Perform an exclusive OR (XOR) operation between this byte array and another.
    ///
    /// - Parameter other: The other byte array to XOR with.
    ///
    /// - Returns: The result of the XOR operation as a byte array.
    
    func xor(_ other: [UInt8]) -> [UInt8] {
        [UInt8].xor(self, other)
    }
    
    /// Initialize a byte array with random values of a specified size.
    ///
    /// - Parameter size: The size of the random byte array.
    
    init(randomOfSize size: Int) {
        var result: [UInt8] = []
        for _ in 0 ..< size {
            result.append(UInt8(arc4random_uniform(UInt32(UInt8.max) + 1)))
        }
        self = result
    }
    
    /// Initialize a `[UInt8]` from an integer value.
    ///
    /// - Parameters:
    ///   - integerValue: The integer value to use for initializing the array.
    ///   - removePadding: A boolean flag that specifies whether to remove leading zeros from the value.
    ///
    /// - Returns: A `[UInt8]` initialized with the provided integer value.
    
    init(from integerValue: Int, removePadding: Bool) {
        if integerValue == 0 { self = [0] }
        
        var data = Swift.withUnsafeBytes(of: integerValue.bigEndian, Array.init)
        
        if removePadding {
            for i in 0 ..< data.count {
                if data[i] != 0 {
                    data = [UInt8](data[i...])
                    break
                }
            }
        }
        
        self = data
    }
}
