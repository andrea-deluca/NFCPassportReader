//
//  SecureMessaging.swift
//  
//
//  Created by Andrea Deluca on 11/09/23.
//

import Foundation
import CommonCrypto
import CoreNFC

/// A class responsible for protecting APDU commands sent and unprotecting APDU responses received
/// during a `secure session` in NFC communication.
///
/// The `SecureMessaging` class is in charge of safeguarding the confidentiality and integrity
/// of APDU commands and responses exchanged in a ``NFCSecureSession``. It employs either 3DES or AES in
/// encrypt-then-authenticate mode, ensuring the data is padded, encrypted, and authenticated.
///
/// ## Session Initiation
///
/// Secure Messaging is initiated when a secure session is established. Session keys are derived using a
/// key derivation function (KDF), and the data is padded, encrypted, and authenticated in this mode.
///
/// ## Session Termination
///
/// Secure Messaging is terminated if a Secure Messaging error occurs or a plain APDU is received.
/// In such cases, the stored session keys are deleted, and the terminal's access rights are reset.
///
/// ## 3DES Modes of Operation
///
/// - Encryption: Two-key 3DES in CBC mode with a zero IV, using padding method 2.
///
/// - Message Authentication: Cryptographic checksums are calculated using MAC algorithm 3
///    with block cipher DES, zero IV, and padding method 2. The MAC length must be 8 bytes.
///
/// - Send Sequence Counter (SSC): For Secure Messaging following Basic Access Control (BAC),
///   the SSC is initialized by concatenating the four least significant bytes of RND.IC and RND.IFD.
///   In all other cases, the SSC is initialized to zero.
///
/// ## AES Modes of Operation
///
/// - Encryption: AES in CBC mode with a specific IV.
/// - Message Authentication: AES in CMAC mode with a MAC length of 8 bytes.
/// - Send Sequence Counter (SSC): The SSC is initialized to zero.
///
/// - SeeAlso: ``NFCSecureSession``, ``SecurityConfiguration``
/// ``SecureChannel`` and ``SessionKeyGenerator``

internal final class SecureMessaging {
    
    private var securityConfig: SecurityConfiguration
    private var secureChannel: SecureChannel
    
    internal init(secureChannel: SecureChannel, securityConfig: SecurityConfiguration) {
        self.securityConfig = securityConfig
        self.secureChannel = secureChannel
    }
    
    /// Protects an APDU command during a secure session.
    ///
    /// To protect an APDU command, the ``SecureMessaging`` class performs the following actions:
    ///
    /// 1. Masks and pads the Command Header (CLA|INS|P1|P2). The class byte (CLA) is replaced with 0x0C.
    /// 2. Pads and encrypts the data with the session key KSenc.
    /// 3. Builds the Data Object DO'87'.
    /// 4. Builds the Data Object DO'97'.
    /// 5. Computes the concatenation M = CmdHeader || DO'87' || DO'97'.
    /// 6. Increments the session SSC and computes the MAC over N = SSC || M (padded) with the session key KSmac.
    /// 7. Builds the Data Object DO'8E'.
    /// 8. Constructs the protected APDU and returns it.
    ///
    /// - Parameter apdu: The APDU command to be protected.
    ///
    /// - Returns: The protected APDU command.
    
    internal func protect(apdu: NFCISO7816APDU) throws -> NFCISO7816APDU {
        // Increment SSC with 1
        secureChannel.incrementSSC()
        
        // Mask class byte and pad command header.
        let cmdHeader = prepareHeader(for: apdu)
        
        // Pad and encrypt data with KSEnc.
        let encryptedData = try prepareData(for: apdu)
        
        // Build DO‘87’
        let DO87 = try buildDO87(data: encryptedData)
        
        // Build DO‘97’
        let DO97 = try buildDO97(apdu: apdu)
        
        // Concatenate CmdHeader, DO‘87’ and DO'97'
        let M = cmdHeader + DO87 + DO97
        
        // Compute MAC of M
        
        // Concatenate SSC and M and add padding
        let N = DataPadder.pad(data: secureChannel.ssc + M, blockSize: securityConfig.encryption.params.blockSize)
        
        // Compute MAC over N with KSMAC
        let CC = try securityConfig.encryption.mac(key: secureChannel.KSmac, message: N).prefix(8)
        
        // Build DO‘8E
        let DO8E = buildDO8E(mac: [UInt8](CC))
        
        // Construct and send protected APDU
        let data = DO87 + DO97 + DO8E
        let Lc = data.count > 255 ? [0x00] +
        BytesRepresentationConverter.convertToBinaryRepresentation(from: UInt64(data.count), withAtLeastHexDigits: 4)
        : BytesRepresentationConverter.convertToBinaryRepresentation(from: UInt64(data.count))
        let protectedAPDU = [UInt8](cmdHeader[0..<4]) + Lc + data + (data.count > 255 ? [0x00, 0x00] : [0x00])
        
        return NFCISO7816APDU(data: Data(protectedAPDU))!
    }
    
    /// Unwraps an APDU response received during a secure session.
    ///
    /// To unprotect an APDU response, the ``SecureMessaging`` class performs the following actions:
    ///
    /// 1. Verifies the RAPDU CC by computing the MAC of the concatenation of DO'87' and DO'99'.
    /// 2. Decrypts the data of DO'87' with KSEnc.
    /// 3. Builds the unprotected APDU response.
    ///
    /// - Parameter rapdu: The APDU response to be unprotected.
    ///
    /// - Returns: The unprotected APDU response.
    
    internal func unprotect(rapdu: APDUResponse) throws -> APDUResponse {
        // Verify RAPDU CC by computing MAC of concatenation DO‘87’ and DO‘99’
        
        // Increment SSC with 1
        secureChannel.incrementSSC()
        
        var offset = 0
        
        // There is an error, so the IPF can return the response as it is.
        // Important things here are status words to detect the right error.
        if rapdu.sw1 != 0x90 || rapdu.sw2 != 0x00 {
            return rapdu
        }
        
        // Construct the response as it has been sent by the IC.
        let response = rapdu.data + [rapdu.sw1, rapdu.sw2]
        
        // Extract the DO'87' and derive its data from the response, if present.
        let (DO87, DO87Data) = try extractDO87(data: response)
        if !DO87.isEmpty { offset += DO87.count }
        
        // Check if other bytes are present.
        guard response.count >= offset + 5 else {
            let sw1 = response.count >= offset + 3 ? response[offset + 2] : 0x00
            let sw2 = response.count >= offset + 4 ? response[offset + 3] : 0x00
            return .init(data: [], sw1: sw1, sw2: sw2)
        }
        
        // Extract the DO'99' from the response, if present.
        let DO99 = extractDO99(data: [UInt8](response[offset...]))
        if DO99.isEmpty { return .init(data: [], sw1: rapdu.sw1, sw2: rapdu.sw2) }
        
        // Derive status words from DO'99'.
        // They should be the same in APDUResponse struct given as arg.
        let sw1 = DO99[2]
        let sw2 = DO99[3]
        
        offset += 4
        
        // Extract the DO'8E' from the response, if present
        let DO8E = extractDO8E(data: [UInt8](response[offset...]))
        if DO8E.isEmpty { throw NFCPassportReaderError.MissingMandatoryFields }
        
        // Derive the MAC from DO'8E' to verify RAPDU.
        let CC = [UInt8](DO8E[2...])
        
        // Concatenate SSC, DO‘87’ and DO‘99’ and add padding.
        let K = DataPadder.pad(data: secureChannel.ssc + DO87 + DO99, blockSize: securityConfig.encryption.params.blockSize)
        
        // Compute MAC with KSMAC.
        let CCb = try securityConfig.encryption.mac(key: secureChannel.KSmac, message: K).prefix(8)
        
        // Compare CCb with data of DO‘8E’ of RAPDU.
        // The MUST be equal.
        if CC != [UInt8](CCb) { throw NFCPassportReaderError.InvalidResponseChecksum }
        
        // Now the IPF can decrypt data of DO‘87’ with session key KSEnc to compute
        // actual response data, if present. Then it can build and return
        // the actual APDU response.
        let decryptedData: [UInt8]
        if !DO87.isEmpty {
            let data = switch securityConfig.encryption {
            case .DESEDE2:
                try securityConfig.encryption.decrypt(key: secureChannel.KSenc, message: DO87Data)
            case .AES:
                try securityConfig.encryption.decrypt(
                    key: secureChannel.KSenc,
                    message: DO87Data,
                    iv: securityConfig.encryption.encrypt(
                        key: secureChannel.KSenc,
                        message: secureChannel.ssc,
                        options: UInt32(kCCOptionECBMode)
                    )
                )
            default: throw NFCPassportReaderError.NotSupported("Algorithm not supported")
            }
            decryptedData =  DataPadder.unpad(data: data)
        } else { decryptedData = [] }
        
        return .init(data: decryptedData, sw1: sw1, sw2: sw2)
    }
}

private extension SecureMessaging {
    private func prepareHeader(for apdu: NFCISO7816APDU) -> [UInt8] {
        let maskedHeader = [0x0C, apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter]
        return DataPadder.pad(data: maskedHeader, blockSize: securityConfig.encryption.params.blockSize)
    }
    
    private func prepareData(for apdu: NFCISO7816APDU) throws -> [UInt8] {
        guard let data = apdu.data else {
            return []
        }
        
        let paddedData =  DataPadder.pad(data: data, blockSize: securityConfig.encryption.params.blockSize)
        let encryptedData = switch securityConfig.encryption {
        case .DESEDE2:
            try securityConfig.encryption.encrypt(key: secureChannel.KSenc, message: paddedData)
        case .AES:
            try securityConfig.encryption.encrypt(
                key: secureChannel.KSenc,
                message: paddedData,
                iv: securityConfig.encryption.encrypt(
                    key: secureChannel.KSenc,
                    message: secureChannel.ssc,
                    options: UInt32(kCCOptionECBMode)
                )
            )
        default: throw NFCPassportReaderError.NotSupported("Algorithm not supported")
        }
        
        return encryptedData
    }
    
    private func buildDO87(data: [UInt8]) throws -> [UInt8] {
        if !data.isEmpty {
            return ASN1BasicEncoder.encode(tag: 0x87, data: [0x01] + data)
        } else { return [] }
    }
    
    private func extractDO87(data: [UInt8]) throws -> ([UInt8], [UInt8]) {
        if data[0] == 0x87 {
            let parsedData = try ASN1Parser.parse(
                ASN1BasicEncoder.encode(universalTag: .SEQUENCE, data: data)
            )
            
            guard case .constructed(let nodes) = parsedData.content else {
                throw NFCPassportReaderError.DO87Malformed
            }
            
            guard let do87Node = nodes.firstChild else {
                throw NFCPassportReaderError.DO87Malformed
            }
            
            guard case .primitive(let content) = do87Node.content else {
                throw NFCPassportReaderError.DO87Malformed
            }
            
            let contentBytes = [UInt8](content)
            
            if contentBytes[0] != 0x01 {
                throw NFCPassportReaderError.DO87Malformed
            }
            
            return ([UInt8](do87Node.encodedBytes), [UInt8](contentBytes[1...]))
        } else { return ([], []) }
    }
    
    private func buildDO8E(mac: [UInt8]) -> [UInt8] {
        ASN1BasicEncoder.encode(tag: 0x8E, data: mac)
    }
    
    private func extractDO8E(data: [UInt8]) -> [UInt8] {
        if data[0] == 0x8E {
            return [UInt8](data[0..<10])
        } else { return [] }
    }
    
    private func buildDO97(apdu: NFCISO7816APDU) throws -> [UInt8] {
        if apdu.expectedResponseLength > 0 {
            let Le: [UInt8] = switch apdu.expectedResponseLength {
            case 0x0100: [0x00]
            case 0x10000: [0x00, 0x00]
            default: BytesRepresentationConverter.convertToBinaryRepresentation(from: UInt64(apdu.expectedResponseLength))
            }
            return ASN1BasicEncoder.encode(tag: 0x97, data: Le)
        } else { return [] }
    }
        
    private func extractDO99(data: [UInt8]) -> [UInt8] {
        if data[0] == 0x99 && data[1] == 0x02 {
            return [UInt8](data[0..<4])
        } else { return [] }
    }
}
