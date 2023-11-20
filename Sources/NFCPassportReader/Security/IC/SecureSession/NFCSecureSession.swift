//
//  NFCSecureSession.swift
//  
//
//  Created by Andrea Deluca on 21/09/23.
//

import Foundation

/// A class that manages the secure session for NFC communication, including
/// security configuration, secure channels, and secure messaging.
///
/// The `NFCSecureSession` class is responsible for establishing secure communication sessions
/// for NFC (Near Field Communication) using ``SecurityConfiguration``, ``SecureChannel``, and ``SecureMessaging``.
///
/// - Tip: It enables secure data exchange and provides methods for configuring, establishing, and clearing the secure session.
///
/// - SeeAlso: ``SecurityConfiguration``, ``SecureChannel``,
/// ``SecureMessaging`` and ``SessionKeyGenerator``

internal final class NFCSecureSession {
    private(set) var securityConfig: SecurityConfiguration?
    private(set) var secureChannel: SecureChannel?
    private(set) var secureMessaging: SecureMessaging?
    
    /// Indicates whether a secure session has been successfully established.
    ///
    /// Returns `true` if the ``SecurityConfiguration``, ``SecureChannel``, and ``SecureMessaging``
    /// have all been set, indicating a successful secure session establishment.
    
    internal var isSecureSessionEstablished: Bool {
        self.securityConfig != nil &&
        self.secureChannel != nil &&
        self.secureMessaging != nil
    }
    
    /// Configures the secure session with the specified ``SecurityConfiguration``.
    ///
    /// - Parameter config: The ``SecurityConfiguration`` to be used for the secure session.
    
    
    internal func configure(with config: SecurityConfiguration) {
        self.securityConfig = config
    }
    
    /// Establishes a secure session with the provided secret key and optional send sequence counter.
    ///
    /// - Parameters:
    ///   - secret: The secret key for session key derivation.
    ///   - sendSquenceCounter: An optional send sequence counter (default is nil).
    ///
    /// - Throws: An error if the ``SecurityConfiguration`` is not set or if key derivation fails.
    
    internal func establish(secret: [UInt8], sendSquenceCounter: [UInt8]? = nil) throws {
        guard let config = self.securityConfig else {
            throw NFCPassportReaderError.UnkownSecurityConfiguration
        }
        
        let generator = SessionKeyGenerator(securityConfig: config)
        let KSenc = try generator.deriveKey(keySeed: secret, mode: .ENC_MODE)
        let KSmac = try generator.deriveKey(keySeed: secret, mode: .MAC_MODE)
        let ssc = sendSquenceCounter ?? [UInt8](repeating: 0x00, count: config.encryption.params.blockSize)
        
        let channel = SecureChannel(KSenc: KSenc, KSmac: KSmac, ssc: ssc)
        self.secureChannel = channel
        
        self.secureMessaging = .init(secureChannel: channel, securityConfig: config)
    }
    
    /// Clears the current secure session,
    /// resetting all associated properties to nil.
    
    internal func clear() {
        self.securityConfig = nil
        self.secureChannel = nil
        self.secureMessaging = nil
    }
}
