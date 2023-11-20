//
//  EncryptionAlgorithm.swift
//  
//
//  Created by Andrea Deluca on 28/09/23.
//

import Foundation
import CommonCrypto
import OpenSSL

/// The enum represents various encryption algorithms used to protect sensitive data.
///
/// The `EncryptionAlgorithm` enum also provides a `params` property of type ``EncryptionAlgorithmParams``
/// to obtain encryption algorithm parameters and methods to encrypt/decrypt messages or to compute
/// MAC using the chosen algorithm.
///
/// - SeeAlso: ``EncryptionAlgorithmParams``, ``HashAlgorithm`` and ``KeyAgreementAlgorithm``

internal enum EncryptionAlgorithm: Hashable {
    typealias Options = CCOptions
    
    /// DES (Data Encryption Standard) is a block cipher algorithm that transforms fixed-length plaintext
    /// with a series of complex operations into a ciphertext of the same length.
    ///
    /// In the case of DES the block size is 64 bits. DES also uses a key to modify the transformation
    /// so that the decryption operation can only be performed by knowing the key itself. The key is
    /// 64 bits long but only 56 of these are actually used by the algorithm. Eight bits are used
    /// only for parity checking and then discarded, which is why the effective key length is reported
    /// as 56 bits.
    ///
    /// Note that DES is considered insecure due to its small key size.
    
    case DES
    
    /// Triple DES (3DES) is an improved version of DES that uses three 56-bit DES keys for enhanced
    /// security. It operates by applying DES encryption three times in different modes.
    /// The variant DES-EDE2 uses two identical keys, resulting in a 112-bit effective key length.
    ///
    /// Cause the 56 bit DES key is insecure, the 3DES has been choosen as
    /// an alternative of the DES algorithm bacause it can improve security easily.
    /// It uses three DES keys, so it improves the key length with no changes on the
    /// algorithm, that is repeated three times.
    ///
    /// In general, the simplest version of the 3DES involves the following
    /// encryption operation: `ENC(k1, ENC(k2, ENC(k3, M)))`, where each operation is
    /// a DES operation, k1, k2 and k3 are DES keys and M is the message to encrypt. This
    /// variant is called DES-EEE cause all the operations perform encryption (E).
    ///
    /// To make interoperability between 3DES and DES easier, another version, called
    /// DES-EDE, exists and it involves the following: `ENC(k1, DEC(k2, ENC(k3, M)))`.
    ///
    /// Depending on the number of different DES keys used, 3DES may be usually mentioned as
    /// DES-(MODE)(KEYS), e.g. DES-EDE2 or DES-EEE3.
    ///
    /// NOTE: DES-EDE1 is equivalent to DES.
    ///
    /// ## Security
    ///
    /// In general 3DES with 3 different DES keys (3TDES) has a 168 bit key length, i.e. three
    /// DES keys of 56 bit length each (or 192 bit with parity bits). However, the guaranteed security
    /// is just 112 bit.
    ///
    /// The DES-EDE2 uses k1 = k3, so the key is 112 bit length with an actual key length of 128 bit.
    
    case DESEDE2
    
    /// Given its security and its public specifications, it is assumed that in the near future AES will be used
    /// all over the world as happened to its predecessor, the DES, which later lost its effectiveness due to
    /// intrinsic vulnerabilities.
    ///
    /// AES was adopted by the National Institute of Standards and Technology (NIST) and the US FIPS PUB in
    /// November 2001 after 5 years of studies, standardizations and final selection among the various
    /// proposed algorithms. In AES, the block has a fixed size of 128 bits and the key can be 128, 192 or 256 bits.
    
    case AES(keySize: AESKeySize)
    
    internal var params: EncryptionAlgorithmParams {
        .init(algorithm: self)
    }
    
    /// Encrypt the given message with the given key.
    ///
    /// - Parameters:
    ///    - key: The secret that has to be used to encrypt the message.
    ///    - message: The message that has to be encrypted.
    ///    - iv: The initialization vector (Optional).
    ///    - options: Other option that may be applied to the cipher algorithm (Optional).
    ///
    /// - Throws: An error if the encryption failed.
    ///
    /// - Returns: The encrypted message as array of bytes.
    
    internal func encrypt(key: [UInt8], message: [UInt8], iv: [UInt8]? = nil, options: Options = 0) throws -> [UInt8] {
        try self.perform(
            operation: EncryptionAlgorithmOperation.encrypt,
            key: key,
            message: message,
            iv: iv ?? .init(repeating: 0x00, count: self.params.blockSize),
            options: options
        )
    }
    
    /// Decrypt the given message with the given key.
    ///
    /// - Parameters:
    ///    - key: The secret that has to be used to decrypt the message.
    ///    - message: The message that has to be decrypted.
    ///    - iv: The initialization vector (Optional).
    ///    - options: Other option that may be applied to the cipher algorithm (Optional).
    ///
    /// - Throws: An error if the decryption failed.
    ///
    /// - Returns: The decrypted message as array of bytes.
    
    internal func decrypt(key: [UInt8], message: [UInt8], iv: [UInt8]? = nil, options: Options = 0) throws -> [UInt8] {
        try self.perform(
            operation: EncryptionAlgorithmOperation.decrypt,
            key: key,
            message: message,
            iv: iv ?? .init(repeating: 0x00, count: self.params.blockSize),
            options: options
        )
    }
    
    /// Produce the MAC (Message Authentication Code) for the given message with
    /// the given key.
    ///
    /// A Block Cipher algorithm, such as DES and AES, can be used to produce a MAC for a
    /// message to provide message authenticity and integrity.
    ///
    /// - Parameters:
    ///    - key: The secret that has to be used to produce the MAC of the message.
    ///    - message: The message that has to be MACed.
    ///
    /// - Throws: An error if MAC computation failed.
    ///
    /// - Returns: The MAC as array of bytes.
    
    internal func mac(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        switch self {
        case .DES, .DESEDE2: try self.DESmac(key: key, message: message)
        case .AES: try self.AESmac(key: key, message: message)
        }
    }
}

private extension EncryptionAlgorithm {
    
    /// Perform encryption/decryption the given message with the given key.
    ///
    /// - Parameters:
    ///    - operation: Encrypt or decrypt operation.
    ///    - key: The secret that has to be used.
    ///    - message: The message that has to be encrypted/decrypted.
    ///    - iv: The initialization vector.
    ///    - options: Other option that may be applied to the cipher algorithm (Optional).
    ///
    /// - Throws: An error if the encryption operation failed.
    ///
    /// - Returns: The encrypted/decrypted message as array of bytes.
    
    private func perform(operation: UInt32, key: [UInt8], message: [UInt8], iv: [UInt8], options: Options = 0) throws -> [UInt8] {
        let dataLength = message.count
        let cryptLength = message.count + self.params.blockSize
        var cryptData = Data(count: cryptLength)
        
        var encryptedBytes = 0
        
        let cryptStatus = key.withUnsafeBytes { keyBytes in
            message.withUnsafeBytes { dataBytes in
                iv.withUnsafeBytes { ivBytes in
                    cryptData.withUnsafeMutableBytes { cryptBytes in
                        CCCrypt(
                            operation,
                            self.params.algorithm,
                            options,
                            keyBytes.baseAddress,
                            self.params.keySize,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress,
                            dataLength,
                            cryptBytes.bindMemory(to: UInt8.self).baseAddress,
                            cryptLength,
                            &encryptedBytes
                        )
                    }
                }
            }
        }
        
        if cryptStatus == kCCSuccess {
            cryptData.count = encryptedBytes
            return [UInt8](cryptData)
        } else { throw EncryptionAlgorithmError.EncryptionOperationFailed(status: cryptStatus) }
    }
    
    /// Produce the MAC (Message Authentication Code) with DES for the given message with
    /// the given key.
    ///
    /// - Parameters:
    ///    - key: The secret that has to be used to produce the MAC of the message.
    ///    - message: The message that has to be MACed.
    ///
    /// - Throws: An error if any encryption operations during MAC computation failed.
    ///
    /// - Returns: The MAC as array of bytes.
    
    private func DESmac(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        let size = message.count / 8
        var y: [UInt8] = .init(repeating: 0x00, count: Self.DES.params.blockSize)
        
        for i in 0 ..< size {
            let tmp = [UInt8](message[i * 8 ..< i * 8 + 8])
            y = try Self.DES.encrypt(key: [UInt8](key[0..<8]), message: tmp, iv: y)
        }
        
        let iv: [UInt8] = .init(repeating: 0x00, count: Self.DES.params.blockSize)
        let b = try Self.DES.decrypt(key: [UInt8](key[8..<16]), message: y, iv: iv, options: UInt32(kCCOptionECBMode))
        let a = try Self.DES.encrypt(key: [UInt8](key[0..<8]), message: b, iv: iv, options: UInt32(kCCOptionECBMode))
        
        return a
    }
    
    /// Produce the MAC (Message Authentication Code) with AES for the given message with
    /// the given key.
    ///
    /// - Parameters:
    ///    - key: The secret that has to be used to produce the MAC of the message.
    ///    - message: The message that has to be MACed.
    ///
    /// - Throws: An error if the AES key size recognized is not valid.
    /// - Throws: An error MAC computation failed.
    ///
    /// - Returns: The MAC as array of bytes.
    
    private func AESmac(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        guard let ctx = CMAC_CTX_new() else {
            throw EncryptionAlgorithmError.MACComputationFailed("Unable to instantiate a new CMAC_CTX")
        }
        
        defer { CMAC_CTX_free(ctx) }
        
        var key = key
        
        var mac = [UInt8](repeating: 0x00, count: 32)
        var maclength = 0
        
        let cipher: OpaquePointer = switch AESKeySize.init(rawValue: self.params.keySize * 8)  {
        case .AES128: EVP_aes_128_cbc()
        case .AES192: EVP_aes_192_cbc()
        case .AES256: EVP_aes_256_cbc()
        default: throw EncryptionAlgorithmError.InvalidAESKeySize
        }
        
        guard CMAC_Init(ctx, &key, self.params.keySize, cipher, nil) == 1 else {
            throw EncryptionAlgorithmError.MACComputationFailed("Unable to init CMAC object")
        }
        
        guard CMAC_Update(ctx, message, message.count) == 1 else {
            throw EncryptionAlgorithmError.MACComputationFailed("Unable to update the CMAC object")
        }
        
        guard CMAC_Final(ctx, &mac, &maclength) == 1 else {
            throw EncryptionAlgorithmError.MACComputationFailed("Unable to finalize CMAC")
        }
        
        return [UInt8](mac[0..<maclength])
    }
}

/// The `AESKeySize` enum represents the key sizes available for AES (Advanced Encryption Standard)
/// encryption. AES supports key sizes of 128, 192, and 256 bits.

internal enum AESKeySize: Int {
    /// A 128-bit AES encryption key.
    case AES128 = 128
    
    /// A 192-bit AES encryption key.
    case AES192 = 192
    
    /// A 256-bit AES encryption key.
    case AES256 = 256
}

/// The `EncryptionAlgorithmParams` struct stores parameters associated with various encryption algorithms,
/// allowing for easy access and retrieval. These parameters include the algorithm identifier, block size,
/// and key size.
///
/// - SeeAlso: ``EncryptionAlgorithm``

internal struct EncryptionAlgorithmParams {
    typealias Algorithm = CCAlgorithm
    typealias Blocksize = Int
    typealias Keysize = size_t
    
    /// The identifier of the encryption algorithm.
    private(set) var algorithm: Algorithm
    
    /// The size of the encryption algorithm's block in bytes.
    private(set) var blockSize: Blocksize
    
    /// The size of the encryption algorithm's key in bytes.
    private(set) var keySize: Keysize
    
    
    /// Initialize the struct with algorithm-specific parameters based on the provided ``EncryptionAlgorithm``.
    ///
    /// - Parameter algorithm: The ``EncryptionAlgorithm`` for which to retrieve parameters.
    
    internal init(algorithm: EncryptionAlgorithm) {
        switch algorithm {
        case .DES:
            self.algorithm = Algorithm(kCCAlgorithmDES)
            self.blockSize = kCCBlockSizeDES
            self.keySize = Keysize(kCCKeySizeDES)
        case .DESEDE2:
            self.algorithm = Algorithm(kCCAlgorithm3DES)
            self.blockSize = kCCBlockSize3DES
            self.keySize = Keysize(kCCKeySize3DES)
        case .AES(let keySize):
            self.algorithm = Algorithm(kCCAlgorithmAES)
            
            // Block size is the same for all the possible AES key sizes
            self.blockSize = kCCBlockSizeAES128
            
            self.keySize = switch keySize {
            case .AES128: Keysize(kCCKeySizeAES128)
            case .AES192: Keysize(kCCKeySizeAES192)
            case .AES256: Keysize(kCCKeySizeAES256)
            }
        }
    }
}

/// The `EncryptionAlgorithmOperation` struct provides constants for encryption and decryption operations
/// when using the CommonCrypto library. It includes `encrypt` and `decrypt` operations.

private struct EncryptionAlgorithmOperation {
    typealias Operation = CCOperation
    
    static let encrypt: Operation = Operation(kCCEncrypt)
    static let decrypt: Operation = Operation(kCCDecrypt)
}

private enum EncryptionAlgorithmError: Error {
    case EncryptionOperationFailed(status: CCCryptorStatus)
    case InvalidAESKeySize
    case MACComputationFailed(_ reason: String)
}
