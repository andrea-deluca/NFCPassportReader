//
//  KeyAgreementAlgorithm.swift
//  
//
//  Created by Andrea Deluca on 10/10/23.
//

import Foundation
import OpenSSL

/// The Key Agreement is a cryptographic method that allows users to compute shared secret key,
/// after their public keys have been exchanged, allowing the use of a cryptographic algorithm.
///
/// - SeeAlso: ``HashAlgorithm``, ``EncryptionAlgorithm``, ``StandardizedDomainParameters``
/// and ``StandardizedDomainParametersType``

internal enum KeyAgreementAlgorithm {
    /// Diffie-Hellman Key Agreement
    case DH
    
    /// Elliptic-Curve Diffie-Hellman Key Agreement
    case ECDH
    
    
    
    // MARK: - Key Pair Generation
    
    
    
    /// Generate a new key pair for the specified ``KeyAgreementAlgorithm`` and
    /// ``StandardizedDomainParameters``.
    ///
    /// - Parameters:
    ///    - algorithm: The used ``KeyAgreementAlgorithm`` (DH or ECDH).
    ///    - params: The used ``StandardizedDomainParameters``. It may be a standardized
    ///    elliptic curve for ECDH or an algebric set for DH. Parameters includes the prime p,
    ///    the generator g and the size of the prime-order subgroup generated by g.
    ///
    /// - Returns: A reference to the generated key pair.
    ///
    /// - Important: The returned reference to the key pair has to be freed by the caller. The pointer
    ///   will reference a `EVP_PKEY` structure (so use `EVP_PKEY_free` then).
    
    internal static func generateKeyPair(for algorithm: KeyAgreementAlgorithm, using params: StandardizedDomainParameters) throws -> OpaquePointer {
        try algorithm.generateKeyPair(params: params)
    }
    
    /// Generate a new key pair using the specified ``StandardizedDomainParameters``.
    ///
    /// - Parameters:
    ///    - params: The used ``StandardizedDomainParameters``. It may be a standardized
    ///    elliptic curve for ECDH or an algebric set for DH. Parameters includes the prime p,
    ///    the generator g and the size of the prime-order subgroup generated by g.
    ///
    /// - Returns: A reference to the generated key pair.
    ///
    /// - Important: The returned reference to the key pair has to be freed by the caller. The pointer
    ///   will reference a `EVP_PKEY` structure (so use `EVP_PKEY_free` then).
    
    internal func generateKeyPair(params: StandardizedDomainParameters) throws -> OpaquePointer {
        return switch self {
        case .DH: try self.generateKeyPairForDH(params: params)
        case .ECDH: try self.generateKeyPairForECDH(params: params)
        }
    }
    
    /// Generate a key pair based on the parameters of an existing public key.
    ///
    /// - Parameter publicKey: A reference to an existing public key.
    ///
    /// - Returns: A reference to the generated key pair.
    ///
    /// - Throws: An error if key pair generation fails.
    ///
    /// - Important: The returned reference to the key pair has to be freed by the caller. The pointer
    ///   will reference a `EVP_PKEY` structure (so use `EVP_PKEY_free` then).
    
    internal static func generateKeyPair(withParamsFrom publicKey: OpaquePointer) throws -> OpaquePointer {
        var keyPair: OpaquePointer?
        guard let ctx = EVP_PKEY_CTX_new(publicKey, nil) else {
            throw KeyAgreementError.KeysGenerationFailed("Unable to instantiate a PKEY_CTX from given public key")
        }
        
        defer { EVP_PKEY_CTX_free(ctx) }
        
        guard EVP_PKEY_keygen_init(ctx) == 1 else {
            throw KeyAgreementError.KeysGenerationFailed("Key pair generation failed")
        }
        
        guard EVP_PKEY_keygen(ctx, &keyPair) == 1 else {
            throw KeyAgreementError.KeysGenerationFailed("Key pair generation failed")
        }
        
        guard let keyPair = keyPair else {
            throw KeyAgreementError.KeysGenerationFailed("Key pair generation failed")
        }
        
        return keyPair
    }
    
    
    
    // MARK: - Shared Secret Computation
    
    
    
    /// Compute the shared secret from the personal private key and the external public key
    /// using the specified ``KeyAgreementAlgorithm``.
    ///
    /// - Parameters:
    ///    - personalKeyPair: The personal key pair object containg personal public/private keys
    ///    and used params.
    ///    - externalPublicKey: The bytes representing the external public key.
    ///    - algorithm: The used ``KeyAgreementAlgorithm`` (DH or ECDH)
    ///
    /// - Returns: A reference to the computed shared secret.
    ///
    /// - Tip: If you want to convert the returned reference to the shared secret into a byte
    /// representation as `[UInt8]`, you can use ``convertToBytes(key:keyPair:for:)`` or
    /// ``convertToBytes(key:keyPair:)`` functions.
    ///
    /// - Important: The returned reference to the shared secret has to be freed by the caller. If the used
    ///   algorithm is DH, the pointer will reference a `BN` structure (so use `BN_free` then), otherwise
    ///   the pointer will reference a `EC_POINT` stucture (so use `EC_POINT_free` then).
    ///   If you don't know the used ``KeyAgreementAlgorithm`` or it is dynamic, you can also call
    ///   ``free(sharedSecret:)`` or ``free(sharedSecret:for:)`` functions.
    
    internal static func computeSharedSecret(personalKeyPair: OpaquePointer, externalPublicKey: [UInt8], using algorithm: KeyAgreementAlgorithm) throws -> OpaquePointer {
        try algorithm.computeSharedSecret(personalKeyPair: personalKeyPair, externalPublicKey: externalPublicKey)
    }
    
    /// Compute the shared secret from the personal private key and the external public key.
    ///
    /// - Parameters:
    ///    - personalKeyPair: The personal key pair object containg personal public/private keys
    ///    and used params.
    ///    - externalPublicKey: The bytes representing the external public key.
    ///
    /// - Returns: A reference to the computed shared secret.
    ///
    /// - Tip: If you want to convert the returned reference to the shared secret into a byte
    /// representation as `[UInt8]`, you can use ``convertToBytes(key:keyPair:for:)`` or
    /// ``convertToBytes(key:keyPair:)`` functions.
    ///
    /// - Important: The returned reference to the shared secret has to be freed by the caller. If the used
    ///   algorithm is DH, the pointer will reference a `BN` structure (so use `BN_free` then), otherwise
    ///   the pointer will reference a `EC_POINT` stucture (so use `EC_POINT_free` then).
    ///   If you don't know the used ``KeyAgreementAlgorithm`` or it is dynamic, you can also call
    ///   ``free(sharedSecret:)`` or ``free(sharedSecret:for:)`` functions.
    
    internal func computeSharedSecret(personalKeyPair: OpaquePointer, externalPublicKey: [UInt8]) throws -> OpaquePointer {
        return switch self {
        case .DH: try self.computeSharedSecretUsingDH(personalKeyPair, externalPublicKey)
        case .ECDH: try self.computeSharedSecretUsingECDH(personalKeyPair, externalPublicKey)
        }
    }
    
    
    
    // MARK: - Utils methods
    
    
    
    /// Extract and return the public key from an `OpaquePointer` key pair.
    ///
    /// - Parameter keyPair: An `OpaquePointer` representing a key pair.
    ///
    /// - Returns: An array of bytes representing the extracted public key.
    ///
    /// - Throws: An error if the extraction process fails or if the key type is not supported.
    
    internal static func extractPublicKey(from keyPair: OpaquePointer) throws -> [UInt8] {
        let keyType = EVP_PKEY_base_id(keyPair)
        
        if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX {
            return try Self.DH.extractPublicKey(from: keyPair)
        } else if keyType == EVP_PKEY_EC {
            return try Self.ECDH.extractPublicKey(from: keyPair)
        } else { throw KeyAgreementError.UnableToExtractPublicKey("Key type not supported") }
    }
    
    /// Extract and return the public key from an `OpaquePointer` key pair.
    ///
    /// - Parameter keyPair: An `OpaquePointer` representing a key pair.
    ///
    /// - Returns: An array of bytes representing the extracted public key.
    ///
    /// - Throws: An error if the extraction process fails.
    
    internal func extractPublicKey(from keyPair: OpaquePointer) throws -> [UInt8] {
        return switch self {
        case .DH: try self.extractPublicKeyUsingDH(keyPair: keyPair)
        case .ECDH: try self.extractPublicKeyUsingECDH(keyPair: keyPair)
        }
    }
    
    /// Decode a public key from a byte array using the specified `OpaquePointer` parameters.
    ///
    /// - Parameters:
    ///   - bytes: The byte array representing the public key.
    ///   - params: `OpaquePointer` parameters for the decoding operation.
    ///
    /// - Returns: An `OpaquePointer` representing the decoded public key.
    ///
    /// - Throws: An error if the decoding process fails or if the key type is not supported.
    ///
    /// - Important: The returned reference to the public key has to be freed by the caller. The pointer
    ///   will reference a `EVP_PKEY` structure (so use `EVP_PKEY_free` then).
    
    internal static func decodePublicKey(from bytes: [UInt8], withParams params: OpaquePointer) throws -> OpaquePointer {
        
        let keyType = EVP_PKEY_base_id(params)
        
        if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX {
            return try Self.DH.decodePublicKey(from: bytes, withParams: params)
        } else if keyType == EVP_PKEY_EC {
            return try Self.ECDH.decodePublicKey(from: bytes, withParams: params)
        } else { throw KeyAgreementError.PublicKeyDecodingFailed("Key type not supported") }
    }
    
    /// Decode a public key from a byte array using the specified `OpaquePointer` parameters.
    ///
    /// - Parameters:
    ///   - bytes: The byte array representing the public key.
    ///   - params: `OpaquePointer` parameters for the decoding operation.
    ///
    /// - Returns: An `OpaquePointer` representing the decoded public key.
    ///
    /// - Throws: An error if the decoding process fails.
    ///
    /// - Important: The returned reference to the public key has to be freed by the caller. The pointer
    ///   will reference a `EVP_PKEY` structure (so use `EVP_PKEY_free` then).
    
    internal func decodePublicKey(from bytes: [UInt8], withParams params: OpaquePointer) throws -> OpaquePointer {
        return switch self {
        case .DH: try self.decodePublicKeyUsingDH(bytes: bytes, params: params)
        case .ECDH: try self.decodePublicKeyUsingECDH(bytes: bytes, params: params)
        }
    }
    
    /// Convert a key into an array of bytes using the specified ``KeyAgreementAlgorithm``.
    ///
    /// - Parameters:
    ///   - key: A key as an `OpaquePointer`.
    ///   - keyPair: A key pair as an `OpaquePointer?` (default `nil`).
    ///   - algorithm: The ``KeyAgreementAlgorithm`` used to perform the conversion.
    ///
    /// - Returns: An array of bytes representing the shared secret.
    ///
    /// - Throws: An error if the conversion fails.
    ///
    /// - Tip: `keyPair` is required just using ECDH.
    
    internal static func convertToBytes(key: OpaquePointer, keyPair: OpaquePointer? = nil, for algorithm: KeyAgreementAlgorithm) throws -> [UInt8] {
        try algorithm.convertToBytes(key: key, keyPair: keyPair)
    }
    
    /// Convert a key into an array of bytes.
    ///
    /// - Parameters:
    ///   - sharedSecret: A key as an `OpaquePointer`.
    ///   - keyPair: A key pair as an `OpaquePointer?` (default `nil`).
    ///
    /// - Returns: An array of bytes representing the shared secret.
    ///
    /// - Throws: An error if the conversion fails.
    ///
    /// - Tip: `keyPair` is required just using ECDH.
    
    internal func convertToBytes(key: OpaquePointer, keyPair: OpaquePointer? = nil) throws -> [UInt8] {
        switch self {
        case .DH: return try self.convertToBytesUsingDH(key: key)
        case .ECDH:
            guard let keyPair = keyPair else {
                throw KeyAgreementError.ConvertionToBytesFailed("Key pair is required using ECDH")
            }
            return try self.convertToBytesUsingECDH(key: key, keyPair: keyPair)
        }
    }
    
    /// Free the shared secret reference computed with the given ``KeyAgreementAlgorithm``.
    ///
    /// - Parameters:
    ///    - sharedSecret: The shared secret reference.
    ///    - algorithm: The ``KeyAgreementAlgorithm`` used to compute the secret.
    
    internal static func free(sharedSecret: OpaquePointer, for algorithm: KeyAgreementAlgorithm) {
        algorithm.free(sharedSecret: sharedSecret)
    }
    
    /// Free the shared secret reference.
    ///
    /// - Parameters:
    ///    - sharedSecret: The shared secret reference.
    
    internal func free(sharedSecret: OpaquePointer) {
        switch self {
        case .DH: BN_clear_free(sharedSecret)
        case .ECDH: EC_POINT_free(sharedSecret)
        }
    }
}



// MARK: - DH Functions



private extension KeyAgreementAlgorithm {
    private func generateKeyPairForDH(params: StandardizedDomainParameters) throws -> OpaquePointer {
        let keyPair: OpaquePointer = EVP_PKEY_new()
        
        // Create a new DH object based on a 1024/2048 bit MODP Group with
        // 160/224/256 bit Prime Order Subgroup. It creates a new DH object initialized
        // to work with the specified parameters. The DH object contains the parameters
        // but does not yet have an associated private or public key.
        // Once you obtain the DH object, you can use it to generate a key pair
        // (private and public keys) on the specified parameters.
        
        let DHObj: OpaquePointer = switch params {
        case .PARAM_ID_GFP_1024_160: DH_get_1024_160()
        case .PARAM_ID_GFP_2048_224: DH_get_2048_224()
        case .PARAM_ID_GFP_2048_256: DH_get_2048_256()
        default: throw KeyAgreementError.InvalidStandardizedDomainParametersType
        }
        
        defer { DH_free(DHObj) }
        
        // The DH_generate_key function in OpenSSL is used to generate a DH key pair
        // within a DH structure. Specifically, DH_generate_key generates
        // a private key and its corresponding public key. This function takes
        // an DH structure as input and modifies it to contain the generated keys.
        
        guard DH_generate_key(DHObj) == 1 else {
            throw KeyAgreementError.KeysGenerationFailed("Key pair generation failed")
        }
        
        EVP_PKEY_set1_DH(keyPair, DHObj)
        return keyPair
    }
    
    private func computeSharedSecretUsingDH(_ personalKeyPair: OpaquePointer, _ externalPublicKey: [UInt8]) throws -> OpaquePointer {
        
        // The function EVP_PKEY_get1_DH in OpenSSL is used to obtain
        // a DH structure from an EVP_PKEY object.
        
        guard let DHObj = EVP_PKEY_get1_DH(personalKeyPair) else {
            throw KeyAgreementError.SharedSecretComputationFailed("Unable to get DH object from personal key pair")
        }
        
        // The function BN_bin2bn in OpenSSL is used to convert a binary representation
        // of a number into a Big Number (BN) object. OpenSSL uses BN objects to represent
        // large integers in cryptographic operations, such as Diffie-Hellman (DH).
        
        let BN_externalPublicKey = BN_bin2bn(externalPublicKey, Int32(externalPublicKey.count), nil)
        defer { BN_free(BN_externalPublicKey) }
        
        // The function DH_compute_key in OpenSSL is used to calculate the shared secret key
        // resulting from a Diffie-Hellman (DH) key exchange between two parties.
        
        var sharedSecret = [UInt8](repeating: 0x00, count: Int(DH_size(DHObj)))
        DH_compute_key(&sharedSecret, BN_externalPublicKey, DHObj)
        
        // Again, the function BN_bin2bn in OpenSSL is used to convert a binary representation
        // of a number into a Big Number (BN) object.
        
        guard let BN_sharedSecret = BN_bin2bn(sharedSecret, Int32(sharedSecret.count), nil) else {
            throw KeyAgreementError.SharedSecretComputationFailed("Unable to convert the shared secret bytes to BigNum")
        }
        
        return BN_sharedSecret
    }
    
    private func convertToBytesUsingDH(key: OpaquePointer) throws -> [UInt8] {
        let size = Int((BN_num_bits(key) + 7) / 8)
        
        var bytes: [UInt8] = .init(repeating: 0x00, count: size)
        guard BN_bn2bin(key, &bytes) != 0 else {
            throw KeyAgreementError.ConvertionToBytesFailed("Conversion from BigNum to bytes failed")
        }
        
        return bytes
    }
    
    private func decodePublicKeyUsingDH(bytes: [UInt8], params: OpaquePointer) throws -> OpaquePointer {
        guard let DHObj = DH_new() else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to instantiate a new DH object")
        }
        
        defer { DH_free(DHObj) }
        
        guard let BN_publicKey = BN_bin2bn(bytes, Int32(bytes.count), nil) else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to convert public key bytes into BigNum")
        }
        
        guard DH_set0_key(DHObj, BN_publicKey, nil) != 0 else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to set BN public key for DH objct")
        }
        
        guard let publicKey = EVP_PKEY_new() else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to instantiate a new EVP_PKEY object")
        }
        
        guard EVP_PKEY_set1_DH(publicKey, DHObj) == 1 else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to set EVP_PKEY public key with params")
        }
        
        return publicKey
    }
    
    private func extractPublicKeyUsingDH(keyPair: OpaquePointer) throws -> [UInt8] {
        guard let DHObj = EVP_PKEY_get0_DH(keyPair) else {
            throw KeyAgreementError.UnableToExtractPublicKey("Unable to get DH object from given key pair")
        }
        
        var publicKey: OpaquePointer?
        DH_get0_key(DHObj, &publicKey, nil)
        
        guard let publicKey = publicKey else {
            throw KeyAgreementError.UnableToExtractPublicKey("Public key not stored in DH object")
        }
        
        return try self.convertToBytesUsingDH(key: publicKey)
    }
}



// MARK: - ECDH Functions



private extension KeyAgreementAlgorithm {
    private func generateKeyPairForECDH(params: StandardizedDomainParameters) throws -> OpaquePointer {
        guard params.type == .ECP else {
            throw KeyAgreementError.InvalidStandardizedDomainParametersType
        }
        
        let keyPair: OpaquePointer = EVP_PKEY_new()
        
        // The EC_KEY_new_by_curve_name function in OpenSSL is used to create a new
        // EC_KEY object based on a specified elliptic curve identified by its
        // "numeric identifier". It creates a new EC_KEY object initialized to work
        // with the specified elliptic curve. The EC_KEY object contains the curve
        // parameters but does not yet have an associated private or public key.
        // Once you obtain the EC_KEY object through this function, you can use it to
        // generate a key pair (private and public keys) on the specified elliptic curve.
        
        guard let ECKeyObj = EC_KEY_new_by_curve_name(params.numericIdentifier) else {
            throw KeyAgreementError.KeysGenerationFailed("Unable to create a new EC_KEY object by curve name")
        }
        
        defer { EC_KEY_free(ECKeyObj) }
        
        // The EC_KEY_generate_key function in OpenSSL is used to generate an elliptic
        // key pair within an EC_KEY structure. Specifically, EC_KEY_generate_key generates
        // a private key and its corresponding public key. This function takes
        // an EC_KEY structure as input and modifies it to contain the generated keys.
        
        guard EC_KEY_generate_key(ECKeyObj) == 1 else {
            throw KeyAgreementError.KeysGenerationFailed("Key pair generation failed")
        }
        
        EVP_PKEY_set1_EC_KEY(keyPair, ECKeyObj)
        return keyPair
    }
    
    private func computeSharedSecretUsingECDH(_ personalKeyPair: OpaquePointer, _ externalPublicKey: [UInt8]) throws -> OpaquePointer {
        
        // The function EVP_PKEY_get1_EC_KEY in OpenSSL is used to obtain
        // a EC_KEY structure from an EVP_PKEY object.
        
        guard let ECKeyObj = EVP_PKEY_get1_EC_KEY(personalKeyPair) else {
            throw KeyAgreementError.SharedSecretComputationFailed("Unable to get EC_KEY object from personal key pair")
        }
        
        // The OpenSSL function EC_KEY_get0_private_key is used to obtain the private key
        // associated with an elliptic curve (EC) key represented by an EC_KEY object.
        // In other words, it allows you to retrieve the private key from an EC key pair.
        
        let personalPrivateKey = EC_KEY_get0_private_key(ECKeyObj)
        
        // The OpenSSL function EC_KEY_get0_group is used to obtain a pointer to the
        // EC_GROUP structure associated with an EC_KEY object, representing the elliptic
        // curve group.
        
        guard let ellipticCurve = EC_KEY_get0_group(ECKeyObj) else {
            throw KeyAgreementError.SharedSecretComputationFailed("Unable to get EC_GROUP from EC_KEY object")
        }
        
        // Instantiate a new EC_POINT for the given elliptic curve. It prepares the data structure
        // to contain the external public key point.
        
        guard let externalPublicPoint = EC_POINT_new(ellipticCurve) else {
            throw KeyAgreementError.SharedSecretComputationFailed("Unable to instantiate a new EC_POINT")
        }
        
        defer { EC_POINT_free(externalPublicPoint) }
        
        // The function EC_POINT_oct2point in OpenSSL is used to convert a binary representation
        // of a point on an elliptic curve (EC) into an EC_POINT object. This function is used
        // when you want to create a point on the elliptic curve from a binary representation.
        
        guard EC_POINT_oct2point(ellipticCurve, externalPublicPoint, externalPublicKey, externalPublicKey.count, nil) == 1 else {
            throw KeyAgreementError.SharedSecretComputationFailed("Unable to convert the external public key bytes to EC_POINT")
        }
        
        // Instantiate a new EC_POINT for the given elliptic curve. It prepares the data structure
        // to contain the computed shared secret point.
        
        guard let sharedSecret = EC_POINT_new(ellipticCurve) else {
            throw KeyAgreementError.SharedSecretComputationFailed("Unable to instantiate a new EC_POINT")
        }
        
        // The OpenSSL function EC_POINT_mul is used to perform scalar multiplication on
        // an elliptic curve point in the context of elliptic curve cryptography (ECC). Specifically,
        // it computes the scalar multiplication of a given point on an elliptic curve by a
        // scalar value (integer). The shared secret in ECDH is computed multipling personal private key
        // integer d_A by the external public key EC point P_B = d_B * g.
        
        guard EC_POINT_mul(ellipticCurve, sharedSecret, nil, externalPublicPoint, personalPrivateKey, nil) == 1 else {
            throw KeyAgreementError.SharedSecretComputationFailed("Shared secret computation by means EC points failed")
        }
        
        return sharedSecret
    }
    
    private func convertToBytesUsingECDH(key: OpaquePointer, keyPair: OpaquePointer) throws -> [UInt8] {
        guard let ECKeyObj = EVP_PKEY_get1_EC_KEY(keyPair) else {
            throw KeyAgreementError.ConvertionToBytesFailed("Unable to get EC_KEY object from given key pair")
        }
        
        defer { EC_KEY_free(ECKeyObj) }
        
        guard let group = EC_KEY_get0_group(ECKeyObj) else {
            throw KeyAgreementError.ConvertionToBytesFailed("Unable to get EC_GROUP from EC_KEY object")
        }
        
        let conversionForm = EC_KEY_get_conv_form(ECKeyObj)
        
        let size = EC_POINT_point2oct(group, key, conversionForm, nil, 0, nil)
        
        var bytes: [UInt8] = .init(repeating: 0x00, count: size)
        guard EC_POINT_point2oct(group, key, conversionForm, &bytes, size, nil) == 1 else {
            throw KeyAgreementError.ConvertionToBytesFailed("Conversion from EC_POINT to bytes failed")
        }
        
        return bytes
    }
    
    private func decodePublicKeyUsingECDH(bytes: [UInt8], params: OpaquePointer) throws -> OpaquePointer {
        guard let ellipticCurve = EVP_PKEY_get1_EC_KEY(params) else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to get EC from params")
        }
        
        defer { EC_KEY_free(ellipticCurve) }
        
        guard let group = EC_KEY_get0_group(ellipticCurve) else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to get EC_GROUP from EC")
        }
        
        guard let point = EC_POINT_new(group) else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to instantiate a new EC_POINT from group")
        }
        
        defer { EC_POINT_free(point) }
        
        guard let key = EC_KEY_new() else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to instantiate a new EC_KEY")
        }
        
        defer { EC_KEY_free(key) }
        
        guard EC_POINT_oct2point(group, point, bytes, bytes.count, nil) == 1 else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to convert bytes into EC_POINT")
        }
        
        guard EC_KEY_set_group(key, group) == 1,
              EC_KEY_set_public_key(key, point) == 1 else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to set group or public key EC_POINT for the new EC_KEY")
        }
        
        guard let publicKey = EVP_PKEY_new() else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to instantiate a new EVP_PKEY object")
        }
        
        guard EVP_PKEY_set1_EC_KEY(publicKey, key) == 1 else {
            throw KeyAgreementError.PublicKeyDecodingFailed("Unable to set public key for the new EVP_PKEY objecr")
        }
        
        return publicKey
    }
    
    private func extractPublicKeyUsingECDH(keyPair: OpaquePointer) throws -> [UInt8] {
        guard let ECKeyObj = EVP_PKEY_get0_EC_KEY(keyPair),
              let publicKey = EC_KEY_get0_public_key(ECKeyObj) else {
            throw KeyAgreementError.UnableToExtractPublicKey("Unable to get public key EC_POINT from given key pair")
        }
        
        return try self.convertToBytesUsingECDH(key: publicKey, keyPair: keyPair)
    }
}

private enum KeyAgreementError: Error {
    case InvalidStandardizedDomainParametersType
    case KeysGenerationFailed(_ reason: String)
    case SharedSecretComputationFailed(_ reason: String)
    case ConvertionToBytesFailed(_ reason: String)
    case PublicKeyDecodingFailed(_ reason: String)
    case UnableToExtractPublicKey(_ reason: String)
}
