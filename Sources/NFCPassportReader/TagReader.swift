//
//  TagReader.swift
//  
//
//  Created by Andrea Deluca on 04/09/23.
//

import Foundation
import CoreNFC

/// A class for reading data from and communicating with an NFC ISO7816 tag
/// through APDU (Application Protocol Data Unit) commands.
///
/// - SeeAlso: ``NFCPassportReader``, ``APDUCommand`` and ``APDUResponse``

internal final class TagReader {
    private var tag: NFCISO7816Tag

    private var maxDataLengthToRead: Int = 0xA0

    internal var progress : ((Int)->())?
    
    internal var secureSession: NFCSecureSession
    
    internal init(tag: NFCISO7816Tag) {
        self.tag = tag
        self.secureSession = .init()
    }
    
    /// Override the maximum data amount to read.
    ///
    /// - Parameter amount: The new maximum data amount to read.
    
    internal func overrideDataAmountToRead(amount: Int) {
        self.maxDataLengthToRead = amount
    }
    
    /// Reduce the data amount to read if it's greater than 0xA0.
    
    internal func reduceDataAmountToRead() {
        if maxDataLengthToRead > 0xA0 {
            maxDataLengthToRead = 0xA0
        }
    }
    
    /// Send an `NFCISO7816APDU` command to the tag and handle secure session if established.
    ///
    /// - Parameter cmd: The `NFCISO7816APDU` command to send.
    ///
    /// - Returns: An ``APDUResponse`` representing the response from the tag.
    ///
    /// - Throws: An error if sending the command fails or if the tag sends back
    /// an error within its response.
    
    internal func send(cmd: NFCISO7816APDU) async throws -> APDUResponse {
        var command = cmd
        
        if secureSession.isSecureSessionEstablished {
            command = try secureSession
                .secureMessaging!
                .protect(apdu: cmd)
        }
        
        let (data, sw1, sw2) = try await tag.sendCommand(apdu: command)
        var response = APDUResponse(data: [UInt8](data), sw1: sw1, sw2: sw2)
        
        if secureSession.isSecureSessionEstablished {
            response = try secureSession
                .secureMessaging!
                .unprotect(rapdu: response)
        }
        
        if let error = response.error {
            throw NFCPassportReaderError.ResponseError(
                error: error,
                reason: error.description,
                sw1: BytesRepresentationConverter
                    .convertToHexRepresentation(from: response.sw1),
                sw2: BytesRepresentationConverter
                    .convertToHexRepresentation(from: response.sw2)
            )
        }
        
        return response
    }
}

// MARK: - SELECT Commands

internal extension TagReader {
    
    /// Select the master file.
    ///
    /// - Returns: An ``APDUResponse`` representing the response from the tag.
    ///
    /// - Throws: An error if sending the command fails or if the tag sends back
    /// an error within its response.
    
    func selectMasterFile() async throws -> APDUResponse {
        try await send(cmd: APDUCommand.SELECT_MASTER_FILE)
    }
    
    /// Select the passport application file.
    ///
    /// - Returns: An ``APDUResponse`` representing the response from the tag.
    ///
    /// - Throws: An error if sending the command fails or if the tag sends back
    /// an error within its response.
    
    func selectPassportApplication() async throws -> APDUResponse {
        try await send(cmd: APDUCommand.SELECT_PASSPORT_APPLICATION)
    }
    
    /// Select a specific file by providing its file identifier.
    ///
    /// - Parameter file: The file identifier to select.
    ///
    /// - Returns: An ``APDUResponse`` representing the response from the tag.
    ///
    /// - Throws: An error if sending the command fails or if the tag sends back
    /// an error within its response.
    
    func selectFile(file: [UInt8]) async throws -> APDUResponse {
        try await send(cmd: APDUCommand.SELECT(file: file))
    }
}

// MARK: - READ Commands

internal extension TagReader {
    
    /// Read data from a specified Data Group.
    ///
    /// - Parameter dataGroup: The Data Group to read.
    ///
    /// - Returns: An array of bytes representing the data read.
    ///
    /// - Throws: An error if sending the command fails or if the tag sends back
    /// an error within its response.
    ///
    /// - SeeAlso: ``DataGroup`` and ``DGTag``
    
    func readDataGroup(_ dataGroup: DGTag?) async throws -> [UInt8] {
        guard let fileId = dataGroup?.EFIdentifier else {
            throw NFCPassportReaderError.UnsupportedDataGroup
        }
        
        try await selectFile(file: fileId).discardResponse()
        return try await readFile()
    }
    
    /// Read the ``CardAccess`` data.
    ///
    /// By default, `NFCISO7816Tag` requires a list of ISO/IEC 7816 applets (AIDs).
    /// Upon discovery of an NFC tag, the first found applet from this list is
    /// automatically selected, and you have no way of changing this.
    ///
    /// This is a problem for the `PACE` protocol because it requires reading parameters
    /// from file `EF.CardAccess` which lies outside of eMRTD applet (AID: A0000002471001)
    /// in the master file.
    ///
    /// - Returns: An array of bytes representing the ``CardAccess`` data.
    ///
    /// - Throws: An error if sending the command fails or if the tag sends back
    /// an error within its response.
    ///
    /// - SeeAlso: ``CardAccess`` and ``PACEHandler``
    
    func readCardAccess() async throws -> [UInt8] {
        try await selectMasterFile().discardResponse()
        try await selectFile(file: CardAccess.EFIdentifier).discardResponse()
        return try await self.readFile()
    }
    
    /// Read a file from the tag.
    ///
    /// - Returns: An array of bytes representing the data read.
    ///
    /// - Throws: An error if sending the command fails or if the tag sends back
    /// an error within its response.
    
    func readFile() async throws -> [UInt8] {
        // Read first 4 bytes of header to see how big the data structure is.
        let readHeaderCmd = APDUCommand.READ_BINARY(offset: [0x00, 0x00], expectedResponseLength: 4)
        var response = try await self.send(cmd: readHeaderCmd)
        
        let (length, offset) = switch response.data[1] {
        case 0x81: (Int(response.data[2]), 2)
        case 0x82: (Int(BytesRepresentationConverter.convertToHexNumber(from: response.data[2..<4])), 3)
        case let v where v < 0x80: (Int(response.data[1]), 1)
        default: throw NFCPassportReaderError.CannotDecodeASN1Length
        }
        
        var remaining = length
        var amountRead = offset + 1
        
        var data = [UInt8](response.data[..<amountRead])
        
        var readAmount = maxDataLengthToRead
        
        while remaining > 0 {
            if maxDataLengthToRead != 256 && remaining < maxDataLengthToRead {
                readAmount = remaining
            }
            
            self.progress?( Int(Float(amountRead) / Float(remaining+amountRead ) * 100))
            
            let offset = BytesRepresentationConverter
                .convertToBinaryRepresentation(
                    from: UInt64(amountRead),
                    withAtLeastHexDigits: 4)
            
            let cmd = APDUCommand.READ_BINARY(offset: offset, expectedResponseLength: readAmount)
            response = try await send(cmd: cmd)
            
            data += response.data
            remaining -= response.data.count
            amountRead += response.data.count
        }
        
        return data
    }
}

// MARK: - AUTHENTICATION Commands

internal extension TagReader {
    
    /// Get a challenge for authentication.
    ///
    /// - Returns: An ``APDUResponse`` representing the challenge.
    ///
    /// - Throws: An error if sending the command fails or if the tag sends back
    /// an error within its response.
    ///
    /// - SeeAlso: ``BACHandler``
    
    func getChallenge() async throws -> APDUResponse {
        try await send(cmd: APDUCommand.GET_CHALLENGE)
    }
    
    /// Send a mutual authentication command.
    ///
    /// - Parameter data: The data for mutual authentication.
    ///
    /// - Returns: An ``APDUResponse`` representing the response from the tag.
    ///
    /// - Throws: An error if sending the command fails or if the tag sends back
    /// an error within its response.
    ///
    /// - SeeAlso: ``BACHandler``
    
    func sendMutualAuthenticate(data: Data) async throws -> APDUResponse {
        try await send(cmd: APDUCommand.MUTUAL_AUTHENTICATE(data))
    }
    
    /// Send a Manage Security Environment (MSE) command for key agreement.
    ///
    /// - Parameters:
    ///    - publicKey: The public key data for key agreement.
    ///    - keyId: The optional key ID data.
    ///
    /// - Returns: An ``APDUResponse`` representing the response from the tag.
    ///
    /// - Throws: An error if sending the command fails or if the tag sends back
    /// an error within its response.
    ///
    /// - SeeAlso: ``KeyAgreementAlgorithm`` and ``ChipAuthenticationHandler``
    
    func sendMSEKAT(publicKey: Data, keyId: Data?) async throws -> APDUResponse {
        let data = keyId != nil ? publicKey + keyId! : publicKey
        return try await send(cmd: APDUCommand.ManageSecurityEnvironment.SET_KEY_AGREEMENT_TEMPLATE(data: data))
    }
    
    /// Send a Manage Security Environment (MSE) command for setting an authentication template.
    ///
    /// - Parameters:
    ///    - data: The data for the authentication template.
    ///    - usage: The usage type of the authentication template.
    ///
    /// - Returns: An ``APDUResponse`` representing the response from the tag.
    ///
    /// - Throws: An error if sending the command fails or if the tag sends back
    /// an error within its response.
    ///
    /// - SeeAlso: ``PACEHandler`` and ``ChipAuthenticationHandler``
    
    func sendMSESetAT(data: Data, for usage: APDUCommand.ManageSecurityEnvironment.AuthenticationTemplateUsege) async throws -> APDUResponse {
        return try await send(cmd: APDUCommand.ManageSecurityEnvironment.SET_AUTHENTICATION_TEMPLATE(data: data, for: usage))
    }
    
    /// Send a general authentication command.
    ///
    /// - Parameters:
    ///    - data: The data for authentication.
    ///    - isLast: A flag indicating if this is the last authentication step.
    ///
    /// - Returns: An ``APDUResponse`` representing the response from the tag.
    ///
    /// - Throws: An error if sending the command fails or if the tag sends back
    /// an error within its response.
    ///
    /// - SeeAlso: ``PACEHandler`` and ``ChipAuthenticationHandler``
    
    func sendGeneralAuthenticate(data: Data, isLast: Bool = false) async throws -> APDUResponse {
        try await send(cmd: APDUCommand.GENERAL_AUTHENTICATE(data: data, isLast: isLast))
    }
}
