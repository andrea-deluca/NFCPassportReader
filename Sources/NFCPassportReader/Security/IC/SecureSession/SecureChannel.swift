//
//  SecureChannel.swift
//  
//
//  Created by Andrea Deluca on 16/10/23.
//

import Foundation

/// Represents a secure communication channel with cryptographic parameters.
///
/// This class defines a secure communication channel with encryption keys (KSenc, KSmac)
/// and a Send Sequence Counter (SSC) for secure messaging during a session. The SSC is an unsigned integer
/// and its bit size matches the block size of the block cipher used for secure messaging,
/// which is 64 bits for `3DES` and 128 bits for AES.
///
/// - SeeAlso: ``NFCSecureSession``, ``SecurityConfiguration``,
/// ``SecureMessaging`` and ``SessionKeyGenerator``

internal final class SecureChannel {
    
    /// The encryption key for data confidentiality.
    private(set) var KSenc: [UInt8]
    
    /// The key for message authentication.
    private(set) var KSmac: [UInt8]
    
    /// The Send Sequence Counter (SSC) for secure messaging.
    ///
    /// The SSC is an unsigned integer and its bit size matches
    /// the block size of the block cipher used for secure messaging. It should be
    /// incremented before generating a command or response APDU. For the first command,
    /// the SSC is incremented from the starting value `x` to `x+1`, and for the first response,
    /// it becomes `x+2`.
    
    private(set) var ssc: [UInt8]
    
    /// Initializes a secure channel with the provided encryption keys and SSC.
    ///
    /// - Parameters:
    ///   - KSenc: The encryption key for data confidentiality.
    ///   - KSmac: The key for message authentication.
    ///   - ssc: The Send Sequence Counter (SSC) for secure messaging.
    
    internal init(KSenc: [UInt8], KSmac: [UInt8], ssc: [UInt8]) {
        self.KSenc = KSenc
        self.KSmac = KSmac
        self.ssc = ssc
    }
    
    /// Increment the Send Sequence Counter (SSC).
    ///
    /// The SSC should be incremented before generating a command or response APDU.
    /// For the first command, the value of SSC is increased from the starting value `x`
    /// to `x+1`. For the first response, it becomes `x+2`.
    
    internal func incrementSSC() {
        let newValue =  BytesRepresentationConverter.convertToHexNumber(from: ssc) + 1
        self.ssc = withUnsafeBytes(of: newValue.bigEndian, Array.init)
    }
}
