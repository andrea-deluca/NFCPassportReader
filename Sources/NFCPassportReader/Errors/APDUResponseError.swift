//
//  APDUResponseError.swift
//  
//
//  Created by Andrea Deluca on 26/10/23.
//

import Foundation

internal enum APDUResponseError: Error {
    case UnknwonError(sw1: UInt8, sw2: UInt8)
    case NoInformationGiven
    
    // Status Word 1 = 0x61
    case ResponseBytesStillAvailable(availableBytes: UInt8)
    
    // Status Word 1 = 0x62
    case CorruptedReturnedData
    case EndReachedBeforeReadingLeBytes
    case SelectedFileInvalidated
    case SelectedFileNotFormattedAccordingToISO
    
    // Status Word 1 = 0x63
    case InvalidSecretCode
    case FileFilledUpByTheLastWrite
    case CardKeyNotSupported
    case ReaderKeyNotSupported
    case PlaintextTransmissionNotSupported
    case SecuredTransmissionNotSupported
    case VolatileMemoryNotAvailable
    case NonVolatileMemoryNotAvailable
    case KeyNumberNotValid
    case KeyLengthNotCorrect
    case CounterHasReachedValueX
    
    // Status Word 1 = 0x64
    case NonVolatileMemoryStateUnchanged
    
    // Status Word 1 = 0x65
    case MemoryFailure
    
    // Status Word 1 = 0x67
    case WrongLength
    
    // Status Word 1 = 0x68
    case LogicalChannelNotSupported
    case SecureMessagingNotSupported
    case LastCommandOfChainExpected
    case CommandChainingNotSupported
    
    // Status Word 1 = 0x69
    case CommandIncompatibleWithFileStructure
    case SecurityStatusNotSatisfied
    case AuthenticationMethodBlocked
    case ReferencedDataInvalidated
    case ConditionsOfUseNotSatisfied
    case CommandNotAllowed
    case ExpectedSMDataObjectMissing
    case IncorrectSMDataObject
    
    // Status Word 1 = 0x6A
    case IncorrectParametersInDataFields
    case FunctionNotSupported
    case FileNotFound
    case RecordNotFound
    case InsufficientMemorySpace
    case InconsistentLcWithTLVStructure
    case IncorrectParameters
    case LcInconsistentWithParameters
    case ReferencedDataNotFound
    
    // Status Word 1 = 0x6B
    case WrongParameters
    
    // Status Word 1 = 0x6C
    case WrongLeLength(exactLength: UInt8)
    
    // Status Word 1 = 0x6D
    case InstructionCodeNotSupportedOrInvalid
    
    // Status Word 1 = 0x6E
    case ClassNotSupported
    
    // Status Word 1 = 0x6F
    case NoPreciseDiagnosis
}

extension APDUResponseError: CustomStringConvertible {
    var description: String {
        return switch self {
        case .UnknwonError: "Unkown error"
        case .NoInformationGiven: "No information given"
            
        case .ResponseBytesStillAvailable(let availableBytes): "Response bytes still available (\(availableBytes) bytes available)"
        case .CorruptedReturnedData: "Part of returned data may be corrupted"
        case .EndReachedBeforeReadingLeBytes: "End of file/record reached before reading Le bytes"
        case .SelectedFileInvalidated: "Selected file invalidated"
        case .SelectedFileNotFormattedAccordingToISO: "Selected file is not valid. FCI not formated according to ISO7816-4"
            
        case .InvalidSecretCode: "Invalid secred code or MRZ key"
        case .FileFilledUpByTheLastWrite: "File filled up by the last write. Loading/updating is not allowed"
        case .CardKeyNotSupported: "Card key not supported"
        case .ReaderKeyNotSupported: "Reader key not supported"
        case .PlaintextTransmissionNotSupported: "Plaintext transmission not supported"
        case .SecuredTransmissionNotSupported: "Secured transmission not supported"
        case .VolatileMemoryNotAvailable: "Volatile memory is not available"
        case .NonVolatileMemoryNotAvailable: "Non-volatile memory is not available"
        case .KeyNumberNotValid: "Key number not valid"
        case .KeyLengthNotCorrect: "Key length is not correct"
        case .CounterHasReachedValueX: "The counter has reached the value ‘x’ (0 = x = 15) (command dependent)"
            
        case .NonVolatileMemoryStateUnchanged: "State of non-volatile memory unchanged"
            
        case .MemoryFailure: "Memory failure"
            
        case .WrongLength: "Wrong length"
            
        case .LogicalChannelNotSupported: "Logical channel not supported"
        case .SecureMessagingNotSupported: "Secure messaging not supported"
        case .LastCommandOfChainExpected: "Last command of the chain expected"
        case .CommandChainingNotSupported: "Command chaining not supported"
            
        case .CommandIncompatibleWithFileStructure: "Command incompatible with file structure"
        case .SecurityStatusNotSatisfied: "Security condition not satisfied"
        case .AuthenticationMethodBlocked: "Authentication method blocked"
        case .ReferencedDataInvalidated: "Referenced data reversibly blocked (invalidated)"
        case .ConditionsOfUseNotSatisfied: "Conditions of use not satisfied"
        case .CommandNotAllowed: "Command not allowed (no current EF)"
        case .ExpectedSMDataObjectMissing: "Expected secure messaging (SM) object missing"
        case .IncorrectSMDataObject: "Incorrect secure messaging (SM) data object"
            
        case .IncorrectParametersInDataFields: "The parameters in the data field are incorrect"
        case .FunctionNotSupported: "Function not supported"
        case .FileNotFound: "File not found"
        case .RecordNotFound: "Record not found"
        case .InsufficientMemorySpace: "There is insufficient memory space in record or file"
        case .InconsistentLcWithTLVStructure: "Lc inconsistent with TLV structure"
        case .IncorrectParameters: "Incorrect P1 or P2 parameter"
        case .LcInconsistentWithParameters: "Lc inconsistent with P1-P2"
        case .ReferencedDataNotFound: "Referenced data not found"
            
        case .WrongParameters: "Wrong parameter(s) P1-P2"
            
        case .WrongLeLength(let exactLength): "Wrong length Le (exact length is \(exactLength) bytes)"
            
        case .InstructionCodeNotSupportedOrInvalid: "Instruction code not supported or invalid"
            
        case .ClassNotSupported: "Class not supported"
            
        case .NoPreciseDiagnosis: "No precise diagnosis (procedure byte), (ISO 7816-3)"
        }
    }
}

extension APDUResponseError: LocalizedError {
    var errorDescription: String? {
        return NSLocalizedString(self.description, comment: "APDU Response Error")
    }
}
