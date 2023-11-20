//
//  ChipAuthenticationHandler.swift
//  
//
//  Created by Andrea Deluca on 11/09/23.
//

import Foundation
import OpenSSL
import CryptoKit

/// `ChipAuthenticationHandler` is responsible for performing chip authentication
/// to verify the authenticity of the chip.
///
/// Chip Authentication prevents copying the ``SOD`` and proves that it has been read from the authentic contactless IC
/// and that it has not been substituted.
///
/// The protocol provides implicit authentication of both the eMRTD chip itself and the stored data
/// by performing Secure Messaging using the new session keys.
///
/// - SeeAlso: ``DataGroup14``, ``SecurityInfo``, ``ChipAuthenticationInfo``,
/// ``ChipAuthenticationSecurityProtocol``, ``ChipAuthenticationPublicKeyInfo``,
/// ``CAPublicKeySecurityProtocol`` and ``NFCSecureSession``

internal final class ChipAuthenticationHandler {
    private typealias KeyId = Int
    
    private static let COMMAND_CHAINING_CHUNK_SIZE = 224
    
    private var tagReader: TagReader
    private var chipAuthenticationInfos: [KeyId : ChipAuthenticationInfo] = [:]
    private var chipAuthenticationPublicKeyInfos: [ChipAuthenticationPublicKeyInfo] = []
    
    /// A computed property that indicates if Chip Authentication is supported
    /// based on the available public keys.
    
    internal var isChipAuthenticationSupported: Bool {
        !chipAuthenticationPublicKeyInfos.isEmpty
    }
    
    /// Initializes the ChipAuthenticationHandler with ``TagReader`` and ``DataGroup14``.
    
    internal init(tagReader: TagReader, dg14: DataGroup14) {
        self.tagReader = tagReader
        
        // Among all Security Infos in DG14, looking for Chip Authentication ones.
        
        dg14.securityInfos.forEach { securityInfo in
            
            // If it is a ChipAuthenticationInfo, check for the presence of its Key Id
            // and, in that case, store the Info.
            //
            // If it is a ChipAuthenticationPublicKeyInfo, store it.
            //
            // Otherwise, if it is any other kind of Security Info, do nothing and continue.
            
            if let chipAuthenticationInfo = securityInfo as? ChipAuthenticationInfo,
               let keyId = chipAuthenticationInfo.keyId {
                chipAuthenticationInfos[keyId] = chipAuthenticationInfo
            } else if let chipAuthenticationPublicKeyInfo = securityInfo as? ChipAuthenticationPublicKeyInfo {
                chipAuthenticationPublicKeyInfos.append(chipAuthenticationPublicKeyInfo)
            }
        }
    }
    
    /// Try perfoming the Chip Authentication Protocol to verify the authenticity of the chip and
    /// restart ``NFCSecureSession`` using the new session keys.
    ///
    /// - Throws: An error if Chip Authentication failed or if it is not supported.
    
    internal func performCA() async throws {
        guard isChipAuthenticationSupported else {
            throw NFCPassportReaderError.NotSupported("Chip Authentication not supported")
        }
        
        // For each public key found try performing the Chip Authentication Protocol with that public key
        for publicKey in chipAuthenticationPublicKeyInfos {
            try await performCA(with: publicKey)
        }
    }
}

private extension ChipAuthenticationHandler {
    
    private func performCA(with publicKeyInfo: ChipAuthenticationPublicKeyInfo) async throws {
        let chipAuthenticationProtocol: ChipAuthenticationSecurityProtocol
        
        if let chipAuthenticationInfo = chipAuthenticationInfos[publicKeyInfo.keyId ?? 0] {
            // A ChipAuthenticationInfo, with same Key Id of the ChipAuthenticationPublicKeyInfo given
            // or the first found, exists, so its Security Protocol may be taken.
            chipAuthenticationProtocol = chipAuthenticationInfo.securityProtocol
        } else {
            // A ChipAuthenticationInfo does not exists, so the Security Protocol is inferred from
            // the ChipAuthenticationPublicKeyInfo.
            chipAuthenticationProtocol = publicKeyInfo.securityProtocol.defaultChipAuthenticationSecurityProtocol
        }
        
        // Try perfoming the Chip Authentication Protocol with that public key and that securty protocol.
        try await performCA(
            keyId: publicKeyInfo.keyId,
            protocol: chipAuthenticationProtocol,
            subjectPublicKeyInfo: publicKeyInfo.subjectPublicKeyInfo
        )
    }
    
    private func performCA(keyId: Int?, protocol caProtocol: ChipAuthenticationSecurityProtocol, subjectPublicKeyInfo: SubjectPublicKeyInfo) async throws {
        // The terminal generates an ephemeral Diffie-Hellman key pair (SKDH_IFD, PKDH_IFD, DIC).
        let ephemeralKeyPair = try KeyAgreementAlgorithm
            .generateKeyPair(withParamsFrom: subjectPublicKeyInfo.publicKey)
        
        defer { EVP_PKEY_free(ephemeralKeyPair) }
        
        let ephemeralPublicKey = try KeyAgreementAlgorithm.extractPublicKey(from: ephemeralKeyPair)
        
        // Sends the ephemeral public key PKDH_IFD to the eMRTD chip.
        try await sendPublicKey(keyId: keyId, protocol: caProtocol, publicKey: ephemeralPublicKey)
        
        // Both the eMRTD chip and the terminal compute the following:
        
        //  1. The shared secret K = KA(SKIC, PKDH_IFD, DIC) = KA(SKDH_IFD, PKIC, DIC)
        let sharedSecret = try caProtocol
            .usedKeyAgreementAlgorithm
            .computeSharedSecret(
                personalKeyPair: ephemeralKeyPair,
                externalPublicKey: subjectPublicKeyInfo.subjectPublicKeyBytes
            )
        
        defer { caProtocol.usedKeyAgreementAlgorithm.free(sharedSecret: sharedSecret) }
        
        let sharedSecretBytes = try caProtocol
            .usedKeyAgreementAlgorithm
            .convertToBytes(
                key: sharedSecret,
                keyPair: ephemeralKeyPair
            )
        
        //  2. The session keys KSMAC = KDF_MAC(K) and KSEnc = KDFEnc(K) derived from K for Secure Messaging.
        try restartSecureSession(caProtocol: caProtocol, sharedSecret: sharedSecretBytes)
    }
    
    /// Send generated public key to the IC.
    ///
    /// Depending on the used symmetric algorithm, two implementations of Chip Authentication are available.
    ///
    /// The following command SHALL be used to implement Chip Authentication with 3DES Secure Messaging:
    ///  1. MSE:Set KAT
    ///
    /// The following sequence of commands SHALL be used to implement Chip Authentication with AES Secure Messaging
    /// and MAY be used to implement Chip Authentication with 3DES Secure Messaging:
    ///
    ///  1. MSE:Set AT
    ///  2. GENERAL AUTHENTICATE
    
    private func sendPublicKey(keyId: Int?, protocol caProtocol: ChipAuthenticationSecurityProtocol, publicKey: [UInt8]) async throws {
        // Reference of a private key (CONDITIONAL).
        // This data object is REQUIRED if the private key is ambiguous,
        // i.e. more than one key pair is available for Chip Authentication.
        let keyId = keyId == nil ? nil : Data(ASN1BasicEncoder.encode(tag: 0x84, data: [UInt8](from: keyId!, removePadding: true)))
        
        // MSE:Set KAT may only be used for id-CA-DH-3DES-CBC-CBC
        // and id-CA-ECDH-3DES-CBC-CBC, i.e. Secure Messaging is restricted to 3DES.
        if caProtocol.usedEncryptionAlgorithm == .DESEDE2 {
            // Send MSE:Set KAT command to the IC
            try await self.tagReader.sendMSEKAT(
                // Ephemeral Public Key: PKDH_IFD encoded as plain public key value (REQUIRED).
                publicKey: Data(ASN1BasicEncoder.encode(tag: 0x91, data: publicKey)),
                // Reference of a private key (CONDITIONAL)
                keyId: keyId
            ).discardResponse()
        } else {
            // Cryptographic mechanism reference:
            // OID of the protocol to select: value only, tag 0x06 is omitted (REQUIRED).
            let oid = caProtocol.oid.encode(withTag: 0x80)
            
            // The command MSE:Set AT is used to select and initialize the protocol.
            // The use of MSE:Set AT for Chip Authentication is indicated by a Chip Authentication OID contained
            // as cryptographic mechanism reference with tag 0x80.
            let data = keyId != nil ? oid + keyId! : oid
            try await self.tagReader.sendMSESetAT(data: Data(data), for: .internalAuthentication).discardResponse()
            
            // General Authenticate command is a chaining command, so more than one command
            // may be sent in a serializable way to send the whole data.
            // For this reason, public key is divided into segments with size COMMAND_CHAINING_CHUNK_SIZE = 224 byte.
            let segments = self.chunk(
                data: ASN1BasicEncoder.encode(tag: 0x80, data: publicKey),
                segmentSize: Self.COMMAND_CHAINING_CHUNK_SIZE
            )
            
            for (idx, segment) in segments.enumerated() {
                // The command GENERAL AUTHENTICATE is used to perform the Chip Authentication.
                try await self.tagReader.sendGeneralAuthenticate(
                    // Dynamic Authentication Data:
                    // Protocol specific data objects (ephemeral public key segment with tag 0x80).
                    data: Data(segment),
                    // Keep track if the segment is the last one, so that instruction class in APDU command
                    // can be changed and the IC can know that chaining command has ended
                    isLast: idx == segments.count - 1
                ).discardResponse()
            }
        }
    }
    
    private func restartSecureSession(caProtocol: ChipAuthenticationSecurityProtocol, sharedSecret: [UInt8]) throws {
        tagReader.secureSession.clear()
        
        tagReader.secureSession.configure(
            with: SecurityConfiguration(
                encryptionAlgorithm: caProtocol.usedEncryptionAlgorithm
            ))
        
        try tagReader.secureSession.establish(secret: sharedSecret)
    }
}

private extension ChipAuthenticationHandler {
    
    /// Chunks up a byte array into a number of segments of the given size,
    /// and a final segment if there is a remainder.
    ///
    /// - Parameters:
    ///   - segmentSize: The number of bytes per segment.
    ///   - data: The data to be partitioned.
    ///
    /// - Returns: A list with the segments.
    
    private func chunk(data: [UInt8], segmentSize: Int) -> [[UInt8]] {
        stride(from: 0, to: data.count, by: segmentSize).map {
            Array(data[$0 ..< min($0 + segmentSize, data.count)])
        }
    }
}
