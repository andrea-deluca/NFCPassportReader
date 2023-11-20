//
//  BACHandler.swift
//  
//
//  Created by Andrea Deluca on 11/09/23.
//

import Foundation

/// The `BACHandler` class acts as a handler for Basic Access Control (BAC), which allows access to the contactless
/// Integrated Circuit (IC) of an eMRTD by implementing a Chip Access Control mechanism.
///
/// BAC is a cryptographic protocol that enables the inspection system to prove its authorization to access
/// the contactless IC using information derived from the physical document, such as the Machine Readable Zone (MRZ) information.
///
/// The BAC mechanism is purely based on symmetric cryptography and provides protection against skimming, misuse
/// and eavesdropping during communication between the eMRTD and the inspection system.
///
/// ## Protocol Specification
///
/// Authentication and Key Establishment is provided by a three-pass challenge-response protocol
/// according to ISO/IEC 11770-2 Key Establishment Mechanism 6 using 3DES [FIPS 46-3] as block cipher.
/// A cryptographic checksum according to ISO/IEC 9797-1 MAC Algorithm 3 is calculated over and appended
/// to the ciphertexts. Exchanged nonces MUST be of size 8 bytes, exchanged keying material MUST be of size 16 bytes.
/// The IFD (i.e. the inspection system) and the contactless IC MUST NOT use distinguishing identifiers as nonces.
///
/// ## Cryptographic Specifications
///
/// - **Encryption of Challenge and Response:**
///   Two-key 3DES in CBC mode with zero IV is used for computation of EIFD and EIC.
///   Padding for the input data must not be used when performing the EXTERNAL AUTHENTICATE command.
///
/// - **Authentication of Challenge and Response:**
///   Cryptographic checksums MIFD and MIC are calculated using ISO/IEC 9797-1 MAC Algorithm 3
///   with block cipher DES and zero IV, following ISO/IEC 9797-1 padding method 2. The MAC length is 8 bytes.
///
/// - SeeAlso: ``DocumentBasicAccessKeys``

internal final class BACHandler {
    private var tagReader: TagReader
    
    private var rndic: [UInt8] = []
    private var kic: [UInt8] = []
    
    private var rndifd: [UInt8] = []
    private var kifd: [UInt8] = []
    
    internal init(tagReader: TagReader) {
        self.tagReader = tagReader
    }
    
    /// Perform Basic Access Control (BAC) to allow access to the contactless IC of the eMRTD.
    ///
    /// BAC is initiated by deriving ``DocumentBasicAccessKeys`` from the MRZ information read from the eMRTD.
    /// A challenge is then requested from the Inspection System (IFD) to the IC, and an EXTERNAL AUTHENTICATE
    /// command with mutual authenticate function is sent to the IC. If the process is successful,
    /// session keys are derived and a ``NFCSecureSession`` is established.
    ///
    /// - Parameter mrzKey: The MRZ-based key used to derive the ``DocumentBasicAccessKeys``.
    ///
    /// - Throws: An error if BAC fails or if the MRZ key is invalid.
    
    
    internal func performBAC(mrzKey: String) async throws {
        // Next commands should be sent without Secure Messaging applied beacuse a secure channel will be
        // established once BAC will be successfully completed.
        tagReader.secureSession.clear()
        tagReader.secureSession.configure(
            with: SecurityConfiguration(encryptionAlgorithm: .DESEDE2)
        )
        
        let documentBasicAccessKeys = try DocumentBasicAccessKeys(mrzKey: mrzKey)
        
        // The IFD requests a challenge RND.IC by sending the GET CHALLENGE command.
        // The IC generates and responds with a nonce RND.IC.
        let challengeResponse = try await tagReader.getChallenge()
        self.rndic = challengeResponse.data
        
        // Send the EXTERNAL AUTHENTICATE command with mutual authenticate function using the data EIFD || MIFD.
        let mutualAuthenticationCommandData = try computeMutualAuthenticationCommandData(documentBasicAccessKeys: documentBasicAccessKeys)
        let mutualAuthenticationResponse = try await tagReader.sendMutualAuthenticate(data: Data(mutualAuthenticationCommandData))
        
        guard mutualAuthenticationResponse.data.count > 0 else {
            throw NFCPassportReaderError.InvalidMRZKey
        }
        
        // Decrypt the cryptogram EIC.
        let eic = try tagReader.secureSession
            .securityConfig!
            .encryption
            .decrypt(
                key: documentBasicAccessKeys.Kenc,
                message: [UInt8](mutualAuthenticationResponse.data[0..<32])
            )
        
        // Extract K.IC from EIC = K.IC || M.IC.
        self.kic = [UInt8](eic[16..<32])
        
        let sharedSecret = self.kic.xor(self.kifd)
        let ssc = [UInt8](self.rndic.suffix(4) + self.rndifd.suffix(4))
        
        // Derive session keys KSEnc and KSMAC using the key derivation mechanism with (K.IC xor K.IFD) as shared secret.
        try tagReader.secureSession.establish(secret: sharedSecret, sendSquenceCounter: ssc)
    }
}

private extension BACHandler {
    
    /// Prepares the data to send the EXTERNAL AUTHENTICATE command to the IC
    /// during mutual authentication.
    ///
    /// The method generates a nonce (RND.IFD) and keying material (K.IFD), computes the cryptogram (EIFD),
    /// and calculates the checksum (MIFD). The resulting data for the EXTERNAL AUTHENTICATE command is prepared
    /// to be sent with the mutual authenticate function.
    ///
    /// - Parameter documentBasicAccessKeys: The ``DocumentBasicAccessKeys`` used for encryption (Kenc)
    ///   and message authentication (Kmac).
    ///
    /// - Throws: An error if data preparation fails.
    ///
    /// - Returns: The data for the EXTERNAL AUTHENTICATE command.
    
    private func computeMutualAuthenticationCommandData(documentBasicAccessKeys: DocumentBasicAccessKeys) throws -> [UInt8] {
        // Generate a nonce RND.IFD and keying material K.IFD.
        self.rndifd = .init(randomOfSize: 8)
        self.kifd = .init(randomOfSize: 16)
        
        // Generate the concatenation S = RND.IFD || RND.IC || K.IFD.
        let s = self.rndifd + self.rndic + self.kifd
        
        // Compute the cryptogram EIFD = E(KEnc, S).
        let eifd = try tagReader.secureSession
            .securityConfig!
            .encryption
            .encrypt(key: documentBasicAccessKeys.Kenc, message: s)
        
        // Compute the checksum MIFD = MAC(KMAC, EIFD).
        let mifd = try tagReader.secureSession
            .securityConfig!
            .encryption
            .mac(key: documentBasicAccessKeys.Kmac, message: DataPadder.pad(data: eifd, blockSize: EncryptionAlgorithm.DESEDE2.params.blockSize))
        
        // compure the EXTERNAL AUTHENTICATE command data EIFD || MIFD.
        return eifd + mifd
    }
}


