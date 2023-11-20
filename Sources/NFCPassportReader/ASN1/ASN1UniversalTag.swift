//
//  ASN1UniversalTag.swift
//  
//
//  Created by Andrea Deluca on 08/09/23.
//

import Foundation

internal enum ASN1UniversalTag: ASN1Tag, ASN1TagDecodable, Hashable {
    case OBJECT_IDENTIFIER = 0x06
    case BIT_STRING = 0x03
    case OCTECT_STRING = 0x04
    case INTEGER = 0x02
    case SEQUENCE = 0x30
    case SET = 0x31
    case NULL = 0x05
    case BOOLEAN = 0x01
    case ENUMERATED = 0x0A
    case UFT8_STRING = 0x0C
    case NUMERIC_STRING = 0x12
    case PRINTABLE_STRING = 0x13
    case TELETEX_STRING = 0x14
    case VIDEOTEX_STRING = 0x15
    case IA5_STRING = 0x16
    case GRAPHIC_STRING = 0x19
    case VISIBLE_STRING = 0x1A
    case GENERAL_STRING = 0x1B
    case UNIVERSAL_STRING = 0x1C
    case BMP_STRING = 0x1E
    case GENERALIZED_TIME = 0x18
    case UTC_TIME = 0x17
}
