//
//  DocumentBasicAccessKeys.swift
//  
//
//  Created by Andrea Deluca on 21/09/23.
//

import Foundation

/// The `DocumentBasicAccessKeys` class represents the Document Basic Access Keys derived from the
/// Machine Readable Zone (MRZ) key.
///
/// These keys are used for encryption (Kenc) and message authentication (Kmac) in Basic Access Control (BAC).
/// The MRZ key is hashed using SHA-1, and the key seed is generated from the hash. The final keys Kenc and Kmac are derived using
/// a key derivation mechanism with the key seed.
///
/// - Note: The ``BACHandler`` class use these keys to establish access to the IC.
///
/// - SeeAlso: ``BACHandler``

internal final class DocumentBasicAccessKeys {
    
    /// The encryption key (Kenc) used for data encryption in BAC.
    
    private(set) var Kenc: [UInt8]
    
    /// The message authentication key (Kmac) used for data integrity in BAC.
    
    private(set) var Kmac: [UInt8]
    
    /// Initializes Document Basic Access Keys using the MRZ key.
    ///
    /// - Parameter mrzKey: The MRZ key used to derive the Document Basic Access Keys.
    ///
    /// - Throws: An error if key derivation fails.
    
    internal init(mrzKey: String) throws {
        let digest = try HashAlgorithm.hash([UInt8](mrzKey.data(using: .utf8)!), with: .SHA1)
        let Kseed = [UInt8](digest[0..<16])
        
        let generator = SessionKeyGenerator(securityConfig: .init(encryptionAlgorithm: .DESEDE2))
        self.Kenc = try generator.deriveKey(keySeed: Kseed, mode: .ENC_MODE)
        self.Kmac = try generator.deriveKey(keySeed: Kseed, mode: .MAC_MODE)
    }
}
