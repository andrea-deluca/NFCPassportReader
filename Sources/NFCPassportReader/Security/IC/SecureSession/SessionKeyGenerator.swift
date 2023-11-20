//
//  SessionKeyGenerator.swift
//
//
//  Created by Andrea Deluca on 11/09/23.
//

import Foundation

/// A generator for session keys using specified key derivation mechanisms.
///
/// The `SessionKeyGenerator` class is responsible for deriving session keys based on defined
/// key derivation mechanisms. These session keys are used for various purposes,
/// such as encryption, message authentication and security protocols.
///
/// ## Key Derivation Function
///
/// The key derivation function `KDF(K, c)` takes the shared secret value `K` and a 32-bit,
/// big-endian integer `c` as inputs. It produces an octet string `keydata` as output,
/// which is computed as `keydata = H(K || c)`. The hash function `H()` used in the key derivation
/// must have a bit-length greater than or equal to the derived key's bit-length.
///
/// - Note: The hash value is interpreted as a big-endian byte output.
///
/// ### Using 3DES
///
/// To derive 128-bit (112-bit excluding parity bits) 3DES keys, the SHA-1 hash function
/// is used, and the following additional steps must be performed:
///
///  - Use octets 1 to 8 of `keydata` to form `keydataA` and octets 9 to 16 to form `keydataB`.
///    Additional octets are not used.
///  - Optionally, adjust the parity bits of `keydataA` and `keydataB` to form correct DES keys.
///
/// ### Using AES
///
/// To derive 128-bit AES keys, the SHA-1 hash function is used, and the following additional step must be performed:
///
///  - Use octets 1 to 16 of `keydata`. Additional octets are not used.
///
/// For 192-bit and 256-bit AES keys, SHA-256 is used as the hash function.
///
/// For 192-bit AES keys, the following additional step must be performed:
///  - Use octets 1 to 24 of keydata; additional octets are not used.
///
/// ## KeyDerivationFunctionMode
///
/// The `SessionKeyGenerator` includes an enum called ``KeyDerivationFunctionMode``, which defines different modes
/// for deriving session keys. Each mode corresponds to a specific use case:
///
/// - `ENC_MODE`: For deriving session keys used in encryption.
/// - `MAC_MODE`: For deriving session keys used in message authentication.
/// - `PACE_MODE`: For deriving session keys used in the PACE protocol.
///
/// - SeeAlso: ``NFCSecureSession``, ``SecurityConfiguration``
/// ``SecureChannel`` and ``SecureMessaging``

internal final class SessionKeyGenerator {
    private var securityConfig: SecurityConfiguration
    
    internal init(securityConfig: SecurityConfiguration) {
        self.securityConfig = securityConfig
    }
    
    /// Derives a session key based on the provided key seed, nonce, and key derivation function mode.
    ///
    /// - Parameters:
    ///   - keySeed: The key seed for key derivation.
    ///   - nonce: An optional nonce value (default is nil).
    ///   - mode: The key ``KeyDerivationFunctionMode``.
    ///
    /// - Throws: An error if key derivation fails.
    ///
    /// - Returns: The derived session key.
    
    internal func deriveKey(keySeed: [UInt8], nonce: [UInt8]? = nil, mode: KeyDerivationFunctionMode) throws -> [UInt8] {
        let data = prepareData(keySeed: keySeed, nonce: nonce, counter: mode.counter)
        let digest = try securityConfig.keyDerivation.hash(data)
        
        let key: [UInt8] = switch securityConfig.encryption {
        case .DESEDE2:
            
            // Actually DES-EDE2 is used, so it requires 3 DES keys k1, k2, k3 where k1 = k3.
            // For this reason, the key length is 192 bit (or 156 bit without parity bits) but
            // the actual length is 128 bit (or 112 bit without parity bits): 64 (or 56) bit for each key.
            //
            // NOTE: DES-EDE is a 3DES where the encryption is performed as ENC(k1, DEC(k2, ENC(k3, M))).
            // Each operation (ENC/DEC) is a DES operation and this 3DES version is used to make interoperability
            // with DES smarter.
            //
            // Here, the first and the second  octects are used as k1 (for ENC operation) and k2 (for DEC operation).
            // Then, the first octect is extracted again for k3, known k3 has to be equal to k1 for ENC operation.
            
            [UInt8].init(
                digest[0..<securityConfig.encryption.params.keySize * 8 / 12]
                + digest[0..<securityConfig.encryption.params.keySize * 8 / 24])
        default:
            [UInt8](digest[0..<securityConfig.encryption.params.keySize * 8 / 8])
        }
        
        return key
    }
    
    /// This enum contains all the different modes using to derive session keys.
    ///
    /// The KDF input requires a 32-bit, big-endian integer counter `c`,
    /// and its value is different according to the session key uses. Here, the following uses/modes are defined:
    ///
    ///  - `ENC_MODE`: To derive a session key for encryption.
    ///  - `MAC_MODE`: To derive a session key for authentication of data.
    ///  - `PACE_MODE`: To derive a session key for the PACE protocol.
    
    internal enum KeyDerivationFunctionMode: UInt8 {
        case ENC_MODE = 0x01
        case MAC_MODE = 0x02
        case PACE_MODE = 0x03
        
        var counter: [UInt8] {
            [0x00, 0x00, 0x00, self.rawValue]
        }
    }
}

private extension SessionKeyGenerator {
    private func prepareData(keySeed: [UInt8], nonce: [UInt8]?, counter: [UInt8]) -> [Data] {
        var data: [Data] = [Data(keySeed)]
        data.append(contentsOf: [Data(nonce ?? []), Data(counter)])
        return data
    }
}
