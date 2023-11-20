//
//  SecurityConfiguration.swift
//  
//
//  Created by Andrea Deluca on 16/10/23.
//

import Foundation

/// Represents a security configuration for cryptographic operations.
///
/// This class encapsulates a security configuration, including encryption algorithm and key derivation settings.
///
/// - SeeAlso: ``NFCSecureSession``, ``SecureChannel``, ``SecureMessaging``
/// ``SessionKeyGenerator``, ``EncryptionAlgorithm`` and``HashAlgorithm``

internal final class SecurityConfiguration {
    
    /// The encryption algorithm used in the security configuration.
    
    private(set) var encryption: EncryptionAlgorithm
    
    /// The key derivation algorithm based on the encryption algorithm.
    
    internal var keyDerivation: HashAlgorithm {
        return switch encryption {
        case .DES, .DESEDE2: .SHA1
        case .AES(keySize: .AES128): .SHA1
        case .AES(keySize: .AES192), .AES(keySize: .AES256): .SHA256
        }
    }
    
    /// Initializes a ``SecurityConfiguration`` with the specified ``EncryptionAlgorithm``.
    ///
    /// - Parameter encryptionAlgorithm: The `encryption algorithm` to use in the security configuration.
    
    internal init(encryptionAlgorithm: EncryptionAlgorithm) {
        self.encryption = encryptionAlgorithm
    }
}
