//
//  PACEMapping.swift
//  
//
//  Created by Andrea Deluca on 11/10/23.
//

import Foundation
import OpenSSL

/// `PACEMapping` manages the possible algorithm-specific mapping functions used during the PACE
/// security protocol for accessing the contactless IC.
///
/// In PACE, a nonce `s` is encrypted using a chosen block cipher `E()` and a derived key `Kπ`.
/// This nonce is then mapped to a random generator using an algorithm-specific mapping function `Map`.
///
/// PACE supports three mapping functions:
///
/// 1. Generic Mapping (GM): This mapping uses either DH or ECDH. The function `Map:g → ĝ` is defined
///    differently for DH and ECDH:
///    - Using DH: `ĝ = g^s * h`, where `h` is calculated by anonymous Diffie-Hellman Key Agreement.
///    - Using ECDH: `Ĝ = s × G + H`, where `H` is calculated by anonymous EC Diffie-Hellman Key Agreement.
///
/// 2. Integrated Mapping (IM): IM uses either DH or ECDH. It utilizes a pseudo-random function `Rp(s,t)`
///    and a function `f_g(x)` to map nonces to group elements.
///
/// 3. Chip Authentication Mapping (CAM): The mapping phase of PACE-CAM is identical to PACE-GM.
///
/// - Important: The description includes high-level details of PACE mapping.
///   For precise specifications, consult relevant standards documents.
///
/// - SeeAlso: ``PACEInfo``, ``PACESecurityProtocol``, ``PACEParametersDecoder``, ``PACEHandler``,
/// ``StandardizedDomainParameters`` and ``KeyAgreementAlgorithm``

internal enum PACEMapping {
    
    /// Generic Mapping
    case GM
    
    /// Integrated Mapping
    case IM
    
    /// Chip Authentication Mapping
    case CAM
    
    /// Maps the nonce to a random generator using the specified algorithm-specific
    /// mapping function and key agreement algorithm.
    ///
    /// - Parameters:
    ///   - nonce: The decrypted nonce from the IC.
    ///   - sharedSecret: The shared secret/key computed with a ``KeyAgreementAlgorithm`` for mapping.
    ///   - config: The current structure containing Key Agreement Algorithm data.
    ///   - mapping: The mapping function to use.
    ///   - algorithm: The ``KeyAgreementAlgorithm`` to use.
    ///
    /// - Throws: An error if mapping is not yet supported or if mapping fails.
    ///
    /// - Returns: A reference to the new mapped parameters data structure for use in subsequent
    ///   Key Agreement Algorithm operations.
    ///
    /// - Important: The returned reference must be freed by the caller after use. The
    ///   pointer will reference a `EVP_KEY` structure (so use `EVP_PKEY_free` then).
    
    internal static func map(
        nonce: OpaquePointer,
        sharedSecret: OpaquePointer,
        config: OpaquePointer,
        with mapping: PACEMapping,
        using algorithm: KeyAgreementAlgorithm
    ) throws -> OpaquePointer {
        try mapping.map(nonce: nonce, sharedSecret: sharedSecret, config: config, using: algorithm)
    }
    
    /// Maps the nonce to a random generator using the specified algorithm-specific
    /// mapping function and key agreement algorithm.
    ///
    /// - Parameters:
    ///   - nonce: The decrypted nonce from the IC.
    ///   - sharedSecret: The shared secret/key computed with a ``KeyAgreementAlgorithm`` for mapping.
    ///   - config: The current structure containing Key Agreement Algorithm data.
    ///   - algorithm: The ``KeyAgreementAlgorithm`` to use.
    ///
    /// - Throws: An error if mapping is not yet supported or if mapping fails.
    ///
    /// - Returns: A reference to the new mapped parameters data structure for use in subsequent
    ///   Key Agreement Algorithm operations.
    ///
    /// - Important: The returned reference must be freed by the caller after use. The
    ///   pointer will reference a `EVP_KEY` structure (so use `EVP_PKEY_free` then).
    
    internal func map(
        nonce: OpaquePointer,
        sharedSecret: OpaquePointer,
        config: OpaquePointer,
        using algorithm: KeyAgreementAlgorithm
    ) throws -> OpaquePointer {
        return switch self {
        case .GM, .CAM:
            switch algorithm {
            case .DH: try self.generalMapWithDH(nonce: nonce, sharedSecret: sharedSecret, config: config)
            case .ECDH: try self.generalMapWithECDH(nonce: nonce, sharedSecret: sharedSecret, config: config)
            }
        case .IM: throw NFCPassportReaderError.PACEMappingFailed("IM mapping not implemented")
        }
    }
}

private extension PACEMapping {
    private func generalMapWithDH(nonce: OpaquePointer, sharedSecret: OpaquePointer, config: OpaquePointer) throws -> OpaquePointer {
        
        // Get the DH object from the given config EVP_PKEY object.
        
        guard let DHObj = EVP_PKEY_get1_DH(config) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to get DH mapping key")
        }
        
        // Duplicate current params contained by the DH object.
        
        guard let params = DHparams_dup(DHObj) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to get initialized ephemeral parameters from DH Mapping Key")
        }
        
        defer { DH_free(params) }
        
        var p: OpaquePointer?
        var q: OpaquePointer?
        var g: OpaquePointer?
        
        // Get the current prime p, order q and generator g from params.
        
        DH_get0_pqg(params, &p, &q, &g)
        
        // Instantiate a new BigNum that will contain generator g.
        
        guard let BN_g = BN_new() else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to instanciate a new BigNum for generator g")
        }
        
        defer { BN_free(BN_g) }
        
        // Instantiate a new BigNum that will contain the new mapped generator g'
        
        guard let BN_mappedGenerator = BN_new() else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to instanciate a new BigNum for new mapped generator")
        }
        
        defer { BN_free(BN_mappedGenerator) }
        
        let BN_ctx = BN_CTX_new()
        
        // Compute the new mapped generator g' = (g^s mod p) * h mod p,
        // where g is the current generator, s is the decrypted nonce received from
        // the IC, h is the computed shared secret/key for mapping and p is the
        // prime number parameter.
        
        guard BN_mod_exp(BN_g, g, nonce, p, BN_ctx) == 1,
              BN_mod_mul(BN_mappedGenerator, BN_g, sharedSecret, p, BN_ctx) == 1
        else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to generate new mapped parameters")
        }
        
        // Set new parameters. The prime p and the order q do not change but
        // just the generator is mapped into a new value.
        
        guard DH_set0_pqg(params, BN_dup(p), BN_dup(q), BN_dup(BN_mappedGenerator)) == 1 else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to set new parameters within DH params object")
        }
        
        // Instantiate a new EVP_PKEY object that will contain the new DH object
        // with mapped parameters.
        
        guard let DHmappedObj = EVP_PKEY_new() else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to create new EVP_PKEY object for new mappped DH object")
        }
        
        // Set mapped parameters into the new DH object.
        
        guard EVP_PKEY_set1_DH(DHmappedObj, params) == 1 else {
            EVP_PKEY_free(DHmappedObj)
            throw NFCPassportReaderError.PACEMappingFailed("Unable to set new mapped DH object within EVP_PKEY object")
        }
        
        return DHmappedObj
    }
    
    private func generalMapWithECDH(nonce: OpaquePointer, sharedSecret: OpaquePointer, config: OpaquePointer) throws -> OpaquePointer {
        
        // Get the EC_KEY object containing current params from the given
        // config EVP_PKEY object.
        
        let params = EVP_PKEY_get1_EC_KEY(config)
        
        // Duplicate the used elliptic curve EC_GROUP from current params.
        
        guard let ellipticCurve = EC_GROUP_dup(EC_KEY_get0_group(params)) else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to get EC_GROUP from EC_KEY params object")
        }
        
        defer { EC_GROUP_free(ellipticCurve) }
        
        // Instantiate a new BigNum that will contain the curve order
        
        guard let order = BN_new() else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to instantiate a new BigNum for curve order")
        }
        
        defer { BN_free(order) }
        
        // Instantiate a new BigNum that will contain the curve cofactor.
        
        guard let cofactor = BN_new() else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to instantiate a new BigNum for curve cofactor")
        }
        
        defer { BN_free(cofactor) }
        
        // Get the current curve order.
        
        guard EC_GROUP_get_order(ellipticCurve, order, nil) == 1 else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to get curve order from EC_GROUP")
        }
        
        // Get the current curve cofacotr.
        
        guard EC_GROUP_get_cofactor(ellipticCurve, cofactor, nil) == 1 else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to get curve cofactor from EC_GROUP")
        }
        
        // Instantiate a new EC_POINT from the used elliptic curve that will contain
        // the new mapped generator point G'.
        
        guard let mappedGeneratorPoint = EC_POINT_new(ellipticCurve) else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to instantiate EC_POINT for new mapped generator")
        }
        
        defer { EC_POINT_free(mappedGeneratorPoint) }
        
        // Compute the new mapped generator point G' = (G * s) + H, where G is
        // the current generator point, s is the decrypted nonce and H is the computed
        // shared secret/key point for mapping.
        // The function EC_POINT_mul in OpenSSL automatically insert the current
        // generator G within the operation (for this reason it is not passed to the
        // fucntion). In particular, it returns into the second arg a point of the
        // elliptic curve passed as first arg the result given by
        // (G * 3rd arg) + (4th arg * 5th arg), where third and fifth args have to be
        // scalar BigNum (integers) and the fourth one has to be a EC_POINT of the curve.
        
        guard EC_POINT_mul(ellipticCurve, mappedGeneratorPoint, nonce, sharedSecret, BN_value_one(), nil) == 1 else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to compute new mapped generator")
        }
        
        // Instantiate a new EVP_PKEY object that will contain the new EC_KEY object
        // with mapped parameters.
        
        guard let ECKeyMappedObj = EVP_PKEY_new() else {
            throw NFCPassportReaderError.PACEMappingFailed("Unable to create new EVP_PKEY object for new mappped EC_KEY object")
        }
        
        // Instantiate a new EC_KEY object with current params.
        
        let mappedParams = EC_KEY_dup(config)
        
        defer { EC_KEY_free(mappedParams) }
        
        // Set mapped parameters into the new EC_KEY object.
        
        guard EVP_PKEY_set1_EC_KEY(ECKeyMappedObj, mappedParams) == 1,
              
                // Set new params for the used elliptic curve.
              // It sets the new mapped generator point, the curve order and cofactor.
                EC_GROUP_set_generator(ellipticCurve, mappedGeneratorPoint, order, cofactor) == 1,
              
                // Check if the elliptict curve with new params is still valid.
              EC_GROUP_check(ellipticCurve, nil) == 1,
              
                // Set the elliptic curve with new mapped params within new EC_KEY object.
              EC_KEY_set_group(mappedParams, ellipticCurve) == 1
        else {
            EVP_PKEY_free(ECKeyMappedObj)
            throw NFCPassportReaderError.PACEMappingFailed("Unable to configure new mapped parameters")
        }
        
        return ECKeyMappedObj
        
    }
}
