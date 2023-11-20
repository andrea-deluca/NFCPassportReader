//
//  APDUResponseErrorDecoder.swift
//  
//
//  Created by Andrea Deluca on 26/10/23.
//

import Foundation

internal final class APDUResponseErrorDecoder {
    private typealias SW1Code = UInt8
    private typealias SW2Code = UInt8
    
    private static let errors: [SW1Code: [SW2Code: APDUResponseError]] = [
        0x62: [0x00: .NoInformationGiven,
               0x81: .CorruptedReturnedData,
               0x82: .EndReachedBeforeReadingLeBytes,
               0x83: .SelectedFileInvalidated,
               0x84: .SelectedFileNotFormattedAccordingToISO],
        0x63: [0x00: .InvalidSecretCode,
               0x81: .FileFilledUpByTheLastWrite,
               0x82: .CardKeyNotSupported,
               0x83: .ReaderKeyNotSupported,
               0x84: .PlaintextTransmissionNotSupported,
               0x85: .SecuredTransmissionNotSupported,
               0x86: .VolatileMemoryNotAvailable,
               0x87: .NonVolatileMemoryNotAvailable,
               0x88: .KeyNumberNotValid,
               0x89: .KeyLengthNotCorrect,
               0x0C: .CounterHasReachedValueX],
        0x65: [0x00: .NoInformationGiven,
               0x81: .MemoryFailure],
        0x67: [0x00: .WrongLength],
        0x68: [0x00: .NoInformationGiven,
               0x81: .LogicalChannelNotSupported,
               0x82: .SecureMessagingNotSupported,
               0x83: .LastCommandOfChainExpected,
               0x84: .CommandChainingNotSupported],
        0x69: [0x00: .NoInformationGiven,
               0x81: .CommandIncompatibleWithFileStructure,
               0x82: .SecurityStatusNotSatisfied,
               0x83: .AuthenticationMethodBlocked,
               0x84: .ReferencedDataInvalidated,
               0x85: .ConditionsOfUseNotSatisfied,
               0x86: .CommandNotAllowed,
               0x87: .ExpectedSMDataObjectMissing,
               0x88: .IncorrectSMDataObject],
        0x6A: [0x00: .NoInformationGiven,
               0x80: .IncorrectParametersInDataFields,
               0x81: .FunctionNotSupported,
               0x82: .FileNotFound,
               0x83: .RecordNotFound,
               0x84: .InsufficientMemorySpace,
               0x85: .InconsistentLcWithTLVStructure,
               0x86: .IncorrectParameters,
               0x87: .LcInconsistentWithParameters,
               0x88: .ReferencedDataNotFound],
        0x6B: [0x00: .WrongParameters],
        0x6D: [0x00: .InstructionCodeNotSupportedOrInvalid],
        0x6E: [0x00: .ClassNotSupported],
        0x6F: [0x00: .NoPreciseDiagnosis],
    ]
    
    internal static func decode(response: APDUResponse) -> APDUResponseError? {
        if response.sw1 == 0x61 {
            return .ResponseBytesStillAvailable(availableBytes: response.sw2)
        } else if response.sw1 == 0x64 {
            return .NonVolatileMemoryStateUnchanged
        } else if response.sw1 == 0x6C {
            return .WrongLeLength(exactLength: response.sw2)
        }
        
        
        if let errors = errors[response.sw1],
           let error = errors[response.sw2] {
            return error
        } else { return nil }
    }
}
