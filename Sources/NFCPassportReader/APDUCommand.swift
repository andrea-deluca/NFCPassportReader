//
//  APDUCommand.swift
//  
//
//  Created by Andrea Deluca on 19/09/23.
//

import Foundation
import CoreNFC

internal struct APDUCommand {
    private static let instructionClass: UInt8 = 0x00
    private static let commandChainingInstructionClass: UInt8 = 0x10
    
    internal static func MUTUAL_AUTHENTICATE(_ data: Data) -> NFCISO7816APDU {
        .init(
            instructionClass: Self.instructionClass,
            instructionCode: 0x82,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: data,
            expectedResponseLength: 256
        )
    }
    
    internal static var GET_CHALLENGE: NFCISO7816APDU {
        .init(
            instructionClass: Self.instructionClass,
            instructionCode: 0x84,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: Data(),
            expectedResponseLength: 8
        )
    }
    
    internal static func GENERAL_AUTHENTICATE(data: Data, isLast: Bool = false) -> NFCISO7816APDU {
        .init(
            instructionClass: isLast ? Self.instructionClass : Self.commandChainingInstructionClass,
            instructionCode: 0x86,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: data,
            expectedResponseLength: 256 + 8 // TODO: Handle extra bytes (maybe GET RESPONSE APDU)
        )
    }
    
    internal static var SELECT_MASTER_FILE: NFCISO7816APDU {
        .init(
            instructionClass: Self.instructionClass,
            instructionCode: 0xA4,
            p1Parameter: 0x00,
            p2Parameter: 0x0C,
            data: Data([0x3F, 0x00]),
            expectedResponseLength: -1
        )
    }
    
    internal static var SELECT_PASSPORT_APPLICATION: NFCISO7816APDU {
        .init(
            instructionClass: 0x00,
            instructionCode: 0xA4,
            p1Parameter: 0x04,
            p2Parameter: 0x0C,
            data: Data([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]),
            expectedResponseLength: -1
        )
    }
    
    internal static func SELECT(file: [UInt8]) -> NFCISO7816APDU {
        .init(
            instructionClass: Self.instructionClass,
            instructionCode: 0xA4,
            p1Parameter: 0x02,
            p2Parameter: 0x0C,
            commandDataLength: 2,
            data: file
        )
    }
    
    internal static func READ_BINARY(offset: [UInt8], expectedResponseLength: Int) -> NFCISO7816APDU {
        .init(
            instructionClass: Self.instructionClass,
            instructionCode: 0xB0,
            p1Parameter: offset[0],
            p2Parameter: offset[1],
            data: Data(),
            expectedResponseLength: expectedResponseLength
        )
    }
}

internal extension APDUCommand {
    struct ManageSecurityEnvironment {
        private static let instructionCode: UInt8 = 0x22
        
        static func SET_KEY_AGREEMENT_TEMPLATE(data: Data) -> NFCISO7816APDU {
            .init(
                instructionClass: APDUCommand.instructionClass,
                instructionCode: Self.instructionCode,
                p1Parameter: AuthenticationTemplateUsege.internalAuthentication.p1Parameter,
                p2Parameter: AuthenticationTemplateUsege.internalAuthentication.p2Parameter,
                data: data,
                expectedResponseLength: -1
            )
        }
        
        static func SET_AUTHENTICATION_TEMPLATE(data: Data, for usage: AuthenticationTemplateUsege) -> NFCISO7816APDU {
            .init(
                instructionClass: APDUCommand.instructionClass,
                instructionCode: Self.instructionCode,
                p1Parameter: usage.p1Parameter,
                p2Parameter: usage.p2Parameter,
                data: data,
                expectedResponseLength: -1
            )
        }
        
        enum AuthenticationTemplateUsege {
            case mutualAuthentication
            case internalAuthentication
            
            var p1Parameter: UInt8 {
                switch self {
                case .internalAuthentication: 0x41
                case .mutualAuthentication: 0xC1
                }
            }
            
            var p2Parameter: UInt8 {
                switch self {
                case .internalAuthentication: 0xA6
                case .mutualAuthentication: 0xA4
                }
            }
        }
    }
}

private extension NFCISO7816APDU {
    convenience init(
        instructionClass: UInt8,
        instructionCode: UInt8,
        p1Parameter: UInt8,
        p2Parameter: UInt8,
        commandDataLength: UInt8,
        data: [UInt8])
    {
        self.init(data: Data([
            instructionClass,
            instructionCode,
            p1Parameter,
            p2Parameter,
            commandDataLength
        ] + data))!
    }
}
