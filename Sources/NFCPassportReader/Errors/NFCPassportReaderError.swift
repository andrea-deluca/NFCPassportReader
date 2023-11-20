//
//  NFCPassportReaderError.swift
//  
//
//  Created by Andrea Deluca on 04/09/23.
//

import Foundation

internal enum NFCPassportReaderError: Error {
    case ResponseError(error: APDUResponseError, reason: String, sw1: String, sw2: String)
    case UnexpectedResponseStructure
    case UnexpectedValueFound
    case UnexpectedError
    case NFCNotSupported
    case NoConnectedTag
    case DO87Malformed
    case InvalidResponseChecksum
    case MissingMandatoryFields
    case CannotDecodeASN1Length
    case UnsupportedDataGroup
    case TravelDocumentTypeNotRecognized
    case UnknownTag
    case UnknownImageFormat
    case TagNotValid
    case ConnectionError
    case UserCanceled
    case InvalidMRZKey
    case MoreThanOneTagFound
    case InvalidDataPassed(String)
    case NotSupported(String)
    case PACEMappingFailed(String)
    case PassiveAuthenticationFailed(String)
    case UnkownSecurityConfiguration
    case SecurityProtocolNotDecodable
    case CMSCertificateVerificationFailed(String)
}

extension NFCPassportReaderError: CustomStringConvertible {
    var description: String {
        return switch self {
        case .ResponseError(_, let reason, _, _): reason
        case .UnexpectedResponseStructure: "Unexpected response ASN.1 structure during decoding"
        case .UnexpectedValueFound: "Unexpected value found during decoding"
        case .UnexpectedError: "Unexpected Error"
        case .NFCNotSupported: "NFC Not Supported"
        case .NoConnectedTag: "No Connected Tag"
        case .DO87Malformed: "Data Object 0x87 Malformed"
        case .InvalidResponseChecksum: "Invalid Response Checksum"
        case .MissingMandatoryFields: "Missing Mandatory Fields"
        case .CannotDecodeASN1Length: "Cannot Decode ASN1 Length"
        case .UnsupportedDataGroup: "Unsupported DataGroup"
        case .TravelDocumentTypeNotRecognized: "Travel Document Type Not Recognized"
        case .UnknownTag: "Unknown Tag"
        case .UnknownImageFormat: "Unknown Image Format"
        case .TagNotValid: "Tag Not Valid"
        case .ConnectionError: "Connection Error"
        case .UserCanceled: "User Canceled"
        case .InvalidMRZKey: "Invalid MRZ Key"
        case .MoreThanOneTagFound: "More Then One Tag Found"
        case .InvalidDataPassed(let reason): "Invalid Data Passed: \(reason)"
        case .NotSupported(let reason): "Not Supported: \(reason)"
        case .PACEMappingFailed(let reason): "PACE Mapping failed: \(reason)"
        case .PassiveAuthenticationFailed(let reason): "Passive Authentication failed: \(reason)"
        case .UnkownSecurityConfiguration: "Unkown security configuration"
        case .SecurityProtocolNotDecodable: "Security protocol not decodable"
        case .CMSCertificateVerificationFailed(let reason): "CMS Certificate verification failed: \(reason)"
        }
    }
}

extension NFCPassportReaderError: LocalizedError {
    var errorDescription: String? {
        NSLocalizedString(self.description, comment: "NFC Passport Reader Error")
    }
}
