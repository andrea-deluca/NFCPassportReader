//
//  PACEHandler.swift
//  
//
//  Created by Andrea Deluca on 11/09/23.
//

import Foundation
import OpenSSL

/// `PACEHndler` is responsible for performing PACE access control protocol to allow the access to the IC.
///
/// PACE is a password authenticated Diffie-Hellman key agreement protocol that provides secure communication
/// and password-based authentication of the eMRTD chip and the inspection system, i.e. eMRTD chip and
/// inspection system share the same password.
///
/// - Note: PACE establishes ``NFCSecureSession`` between an eMRTD chip and an inspection system
/// based on weak (short) passwords.
///
/// - SeeAlso: ``CardAccess``, ``SecurityInfo``, ``PACEInfo``, ``PACESecurityProtocol``
/// ``PACEMapping``, ``PACEParametersDecoder``, ``KeyAgreementAlgorithm`` and ``NFCSecureSession``

internal final class PACEHandler {
    private static let MRZ_PACE_KEY_REFERENCE: UInt8 = 0x01
    private static let CAN_PACE_KEY_REFERENCE: UInt8 = 0x02
    
    private var tagReader: TagReader
    private var paceInfo: PACEInfo
    
    /// A property that indicates if PACE is supported.
    
    private(set) var isPACESupported: Bool
    
    /// Initializes the PACEHandler with a ``TagReader`` and ``CardAccess``.
    ///
    /// - Parameters:
    ///   - tagReader: The ``TagReader`` used to communicate with the card.
    ///   - cardAccess: The ``CardAccess`` information, including ``PACEInfo`` if supported.
    ///
    /// - Throws: An error if PACE is not supported.
    
    internal init(tagReader: TagReader, cardAccess: CardAccess) throws {
        guard let paceInfo = cardAccess.paceInfo else {
            throw NFCPassportReaderError.NotSupported("PACE not supported")
        }
        
        self.paceInfo = paceInfo
        self.tagReader = tagReader
        self.isPACESupported = true
    }
    
    /// Perform the PACE protocol using the MRZ key.
    ///
    /// - Parameter mrzKey: The MRZ (Machine Readable Zone) key for deriving the PACE key.
    ///
    /// - Throws: An error if PACE is not supported or if any step of the PACE protocol fails.
    
    internal func performPACE(mrzKey: String) async throws {
        guard isPACESupported else {
            throw NFCPassportReaderError.NotSupported("PACE not supported")
        }
        
        let paceKey = try derivePaceKey(from: mrzKey)
        
        let encodedPACEInfoOid = paceInfo.oid.encode(withTag: 0x80)
        let encodedPACEUsedKeyType = ASN1BasicEncoder.encode(tag: 0x83, data: [Self.MRZ_PACE_KEY_REFERENCE])
        let encodedPACEParametersId = ASN1BasicEncoder.encode(tag: 0x84, data: [UInt8(PACEParametersDecoder.getParametersId(from: paceInfo.parameters!) ?? 0)])
        
        let encodedPACEInfoData = Data(encodedPACEInfoOid + encodedPACEUsedKeyType + encodedPACEParametersId)
        try await tagReader.sendMSESetAT(data: encodedPACEInfoData, for: .mutualAuthentication).discardResponse()
        
        let decryptedNonce = try await self.computeDecryptedNonce(withKey: paceKey)
        let ephemeralParams = try await self.computeEphemeralParams(decryptedNonce: decryptedNonce)
        let sharedSecret = try await self.performKeyAgreement(ephemeralParams: ephemeralParams)
        
        tagReader.secureSession.clear()
        tagReader.secureSession.configure(with: SecurityConfiguration(
            encryptionAlgorithm: paceInfo.securityProtocol.usedEncryptionAlgorithm
        ))
        
        try tagReader.secureSession.establish(secret: sharedSecret)
    }
}

private extension PACEHandler {

    /// Calculate the decrypted nonce.
    ///
    /// - Parameter paceKey: The PACE key derived from the MRZ key.
    ///
    /// - Throws: An error if reading/decrypting the nonce fails.
    ///
    /// - Returns: The decrypted nonce.
    
    private func computeDecryptedNonce(withKey paceKey: [UInt8]) async throws -> [UInt8] {
        let data = ASN1BasicEncoder.encode(tag: 0x7C, data: [])
        let response = try await tagReader.sendGeneralAuthenticate(data: Data(data), isLast: false)
        let parsedRssponseData = try ASN1Parser.parse(response.data)
        
        guard parsedRssponseData.tag == 0x7C else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard let child = parsedRssponseData.children?.firstChild,
              child.tag == 0x80,
              case .primitive(let encryptedNonce) = child.content
        else { throw NFCPassportReaderError.UnexpectedResponseStructure }
        
        return try paceInfo
            .securityProtocol
            .usedEncryptionAlgorithm
            .decrypt(key: paceKey, message: [UInt8](encryptedNonce))
    }
    
    /// Calculate ephemeral parameters for key exchange.
    ///
    /// - Parameter decryptedNonce: The decrypted nonce received from the IC that will be used
    /// to perfom mapping function and compute the ephemeral parameters that will be used during
    /// actual ``KeyAgreementAlgorithm``.
    ///
    /// - Throws: An error if key agreement for mapping operations and ephemeral params computation fails.
    ///
    /// - Returns: The ephemeral params that will be used during actual ``KeyAgreementAlgorithm``.
    
    private func computeEphemeralParams(decryptedNonce: [UInt8]) async throws -> OpaquePointer {
        let ephemeralMappingKeyPair: OpaquePointer = try KeyAgreementAlgorithm.generateKeyPair(
            for: paceInfo.securityProtocol.usedKeyAgreementAlgorithm,
            using: paceInfo.parameters!
        )
        
        defer { EVP_PKEY_free(ephemeralMappingKeyPair) }
        
        let ephemeralMappingPublicKey = try KeyAgreementAlgorithm.extractPublicKey(from: ephemeralMappingKeyPair)
        
        let data = ASN1BasicEncoder.encode(
            tag: 0x7C,
            data: ASN1BasicEncoder.encode(
                tag: 0x81,
                data: ephemeralMappingPublicKey
            )
        )
        
        let response = try await tagReader.sendGeneralAuthenticate(data: Data(data), isLast: false)
        let parsedRssponseData = try ASN1Parser.parse(response.data)
        
        guard parsedRssponseData.tag == 0x7C else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard let child = parsedRssponseData.children?.firstChild,
              child.tag == 0x82,
              case .primitive(let icMappingPublicKey) = child.content
        else { throw NFCPassportReaderError.UnexpectedResponseStructure }
        
        let mappingSharedSecret = try KeyAgreementAlgorithm.computeSharedSecret(
            personalKeyPair: ephemeralMappingKeyPair,
            externalPublicKey: [UInt8](icMappingPublicKey),
            using: paceInfo.securityProtocol.usedKeyAgreementAlgorithm
        )
        
        defer { paceInfo.securityProtocol.usedKeyAgreementAlgorithm.free(sharedSecret: mappingSharedSecret) }
        
        guard let nonce = BN_bin2bn(decryptedNonce, Int32(decryptedNonce.count), nil) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to convert picc nonce to big number")
        }
        
        defer { BN_free(nonce) }
        
        let ephemeralParams = try PACEMapping.map(
            nonce: nonce,
            sharedSecret: mappingSharedSecret,
            config: ephemeralMappingKeyPair,
            with: paceInfo.securityProtocol.usedMappingFunction,
            using: paceInfo.securityProtocol.usedKeyAgreementAlgorithm
        )
        
        return ephemeralParams
    }
    
    /// Perform the key agreement.
    ///
    /// - Parameter ephemeralParams: The ephemeral parameters computed by both the IFD and the IC
    /// to generate ephemeral key pairs and perfom ``KeyAgreementAlgorithm`` and compute a shared secret.
    ///
    /// - Throws: An error if key agreement fails.
    ///
    /// - Returns: The computed shared secret.

    private func performKeyAgreement(ephemeralParams: OpaquePointer) async throws -> [UInt8] {
        let ephemeralKeyPair: OpaquePointer = try KeyAgreementAlgorithm.generateKeyPair(withParamsFrom: ephemeralParams)
        
        defer { EVP_PKEY_free(ephemeralKeyPair) }
        
        let icPublicKeyBytes = try await self.performKeyExchange(ephemeralKeyPair: ephemeralKeyPair)
        
        let sharedSecret = try paceInfo
            .securityProtocol
            .usedKeyAgreementAlgorithm
            .computeSharedSecret(
                personalKeyPair: ephemeralKeyPair,
                externalPublicKey: icPublicKeyBytes
            )
        
        defer { paceInfo.securityProtocol.usedKeyAgreementAlgorithm.free(sharedSecret: sharedSecret) }
        
        let sharedSecretBytes = try paceInfo
            .securityProtocol
            .usedKeyAgreementAlgorithm
            .convertToBytes(
                key: sharedSecret,
                keyPair: ephemeralKeyPair
            )
        
        let generator = SessionKeyGenerator(securityConfig: .init(encryptionAlgorithm: paceInfo.securityProtocol.usedEncryptionAlgorithm))
        let KSmac = try generator.deriveKey(keySeed: sharedSecretBytes, mode: .MAC_MODE)
        
        guard let authToken = try? generateAuthenticationToken(
            publicKey: KeyAgreementAlgorithm
                .decodePublicKey(from: icPublicKeyBytes, withParams: ephemeralKeyPair),
            KSmac: KSmac
        ) else { throw NFCPassportReaderError.InvalidDataPassed("Unable to generate autentication token") }
        
        let expectedIcAuthToken = try generateAuthenticationToken(
            publicKey: ephemeralKeyPair,
            KSmac: KSmac
        )
        
        let data = ASN1BasicEncoder.encode(
            tag: 0x7C,
            data: ASN1BasicEncoder.encode(
                tag: 0x85,
                data: authToken
            )
        )
        
        let response = try await tagReader.sendGeneralAuthenticate(data: Data(data), isLast: true)
        let parsedRssponseData = try ASN1Parser.parse(response.data)
        
        guard parsedRssponseData.tag == 0x7C else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard let child = parsedRssponseData.children?.firstChild,
              child.tag == 0x86,
              case .primitive(let icAuthToken) = child.content
        else { throw NFCPassportReaderError.UnexpectedResponseStructure }
        
        guard [UInt8](icAuthToken) == expectedIcAuthToken else {
            throw NFCPassportReaderError.InvalidDataPassed("Error PICC Token mismatch")
        }
        
        return sharedSecretBytes
    }
    
    /// Perform the key exchange.
    ///
    /// - Parameter ephemeralKeyPair: The ephemeral key pair generated to perfom ``KeyAgreementAlgorithm``
    /// and compute shared secret with the IC.
    ///
    /// - Throws: An error if key exchange fails.
    ///
    /// - Returns: The IC ephemeral public key.
    
    private func performKeyExchange(ephemeralKeyPair: OpaquePointer) async throws -> [UInt8] {
        let ephemeralPublicKey = try KeyAgreementAlgorithm.extractPublicKey(from: ephemeralKeyPair)
        
        let data = ASN1BasicEncoder.encode(
            tag: 0x7C,
            data: ASN1BasicEncoder.encode(
                tag: 0x83,
                data: ephemeralPublicKey
            )
        )
        
        let response = try await tagReader.sendGeneralAuthenticate(data: Data(data), isLast: false)
        let parsedRssponseData = try ASN1Parser.parse(response.data)
        
        guard parsedRssponseData.tag == 0x7C else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        guard let child = parsedRssponseData.children?.firstChild,
              child.tag == 0x84,
              case .primitive(let icPublicKeyBytes) = child.content
        else { throw NFCPassportReaderError.UnexpectedResponseStructure }
        
        
        return [UInt8](icPublicKeyBytes)
    }
    
    /// Generate the authentication token.
    ///
    /// - Parameters:
    ///    - publicKey: The public key to use to compute authentication token.
    ///    - KSMac: The key will be used to compute MAC during the new possible session
    ///    that will established if PACE will be successfully done.
    ///
    /// - Throws: An error if generation fails.
    ///
    /// - Returns: The authentication token.
    
    private func generateAuthenticationToken(publicKey: OpaquePointer, KSmac: [UInt8]) throws -> [UInt8] {
        let publicKeyBytes = try KeyAgreementAlgorithm.extractPublicKey(from: publicKey)
        
        let keyType = EVP_PKEY_base_id(publicKey)
        let tag: UInt64 = if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX { 0x84 } else { 0x86 }
        
        let encodedPublicKey = ASN1BasicEncoder.encode(tag: tag, data: publicKeyBytes)
        let encodedOid = paceInfo.oid.encode()
        
        var encodedData = ASN1BasicEncoder.encode(tag: 0x7F49, data: encodedOid + encodedPublicKey)
        
        if paceInfo.securityProtocol.usedEncryptionAlgorithm == .DESEDE2 {
            encodedData = DataPadder.pad(data: encodedData, blockSize: paceInfo.securityProtocol.usedEncryptionAlgorithm.params.blockSize)
        }
        
        let authToken = try paceInfo
            .securityProtocol
            .usedEncryptionAlgorithm
            .mac(key: KSmac, message: encodedData)
            .prefix(8)
        
        return [UInt8](authToken)
    }
    
    /// Derive the PACE key from the MRZ key.
    ///
    /// - Parameter mrzKey: The MRZ (Machine Readable Zone) key.
    ///
    /// - Throws: An error if derivation fails.
    ///
    /// - Returns: An encoded key based on the MRZ key that can be used for PACE.
    
    private func derivePaceKey(from mrzKey: String) throws -> [UInt8] {
        let buffer = [UInt8].init(mrzKey.utf8)
        let digest = try HashAlgorithm.hash(buffer, with: .SHA1)
        
        let generator = SessionKeyGenerator(securityConfig: SecurityConfiguration(
            encryptionAlgorithm: paceInfo.securityProtocol.usedEncryptionAlgorithm
        ))
        
        return try generator.deriveKey(keySeed: digest, mode: .PACE_MODE)
    }
}
