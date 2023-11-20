//
//  ASN1Utils.swift
//  
//
//  Created by Andrea Deluca on 13/09/23.
//

import Foundation

extension ArraySlice where Element == UInt8 {
    @inlinable
    mutating func _readASN1Length() -> UInt? {
        guard let firstByte = self.popFirst() else {
            return nil
        }

        switch firstByte {
        case 0x80:
            // Indefinite form. Unsupported.
            fatalError("Indefinite form of field length not supported in DER.")
        case let val where val & 0x80 == 0x80:
            // Top bit is set, this is the long form. The remaining 7 bits of this octet
            // determine how long the length field is.
            let fieldLength = Int(val & 0x7F)
            guard self.count >= fieldLength else {
                return nil
            }

            // We need to read the length bytes
            let lengthBytes = self.prefix(fieldLength)
            self = self.dropFirst(fieldLength)
            let length = UInt(bigEndianBytes: lengthBytes)

            // DER requires that we enforce that the length field was encoded in the minimum number of octets necessary.
            let requiredBits = UInt.bitWidth - length.leadingZeroBitCount
            switch requiredBits {
            case 0...7:
                // For 0 to 7 bits, the long form is unacceptable and we require the short.
                fatalError("Field length encoded in long form, but DER requires \(length) to be encoded in short form")
            case 8...:
                // For 8 or more bits, fieldLength should be the minimum required.
                let requiredBytes = (requiredBits + 7) / 8
                if fieldLength > requiredBytes {
                    fatalError("Field length encoded in excessive number of bytes")
                }
            default:
                // This is not reachable, but we'll error anyway.
                fatalError("Correctness error: computed required bits as \(requiredBits)")
            }

            return length
        case let val:
            // Short form, the length is only one 7-bit integer.
            return UInt(val)
        }
    }
}

extension FixedWidthInteger {
    @inlinable
    internal init<Bytes: Collection>(bigEndianBytes bytes: Bytes) where Bytes.Element == UInt8 {
        guard bytes.count <= (Self.bitWidth / 8) else {
            fatalError("Unable to treat \(bytes.count) bytes as a \(Self.self)")
        }

        self = 0

        // Unchecked subtraction because bytes.count must be positive, so we can safely subtract 8 after the
        // multiply. The same logic applies to the math in the loop. Finally, the multiply can be unchecked because
        // we know that bytes.count is less than or equal to bitWidth / 8, so multiplying by 8 cannot possibly overflow.
        var shift = (bytes.count &* 8) &- 8

        var index = bytes.startIndex
        while shift >= 0 {
            self |= Self(truncatingIfNeeded: bytes[index]) << shift
            bytes.formIndex(after: &index)
            shift &-= 8
        }
    }
}
