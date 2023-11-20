//
//  StandardizedDomainParameters.swift
//  
//
//  Created by Andrea Deluca on 12/10/23.
//

import Foundation
import OpenSSL

/// The `StandardizedDomainParameters` enumeration represents a set of
/// standardized domain parameters used in ``KeyAgreementAlgorithm`` during keys computation.
///
/// Each standardized domain parameters have associated an integer ``NID`` (Numeric Identifier)
/// that is defined by the entity has studied and standardized that domain paramaters set.
///
/// - SeeAlso: ``StandardizedDomainParametersType`` and ``KeyAgreementAlgorithm``

internal enum StandardizedDomainParameters {
    internal typealias NID = Int32
    
    // Galois Field Standardized Domain Parameters
    
    case PARAM_ID_GFP_1024_160
    case PARAM_ID_GFP_2048_224
    case PARAM_ID_GFP_2048_256
    
    // Elliptic Curve Standardized Domain Parameters
    
    case PARAM_ID_ECP_NIST_P192_R1
    case PARAM_ID_ECP_BRAINPOOL_P192_R1
    case PARAM_ID_ECP_NIST_P224_R1
    case PARAM_ID_ECP_BRAINPOOL_P224_R1
    case PARAM_ID_ECP_NIST_P256_R1
    case PARAM_ID_ECP_BRAINPOOL_P256_R1
    case PARAM_ID_ECP_BRAINPOOL_P320_R1
    case PARAM_ID_ECP_NIST_P384_R1
    case PARAM_ID_ECP_BRAINPOOL_P384_R1
    case PARAM_ID_ECP_BRAINPOOL_P512_R1
    case PARAM_ID_ECP_NIST_P521_R1
    
    private var NID_X9_42_S163K1: NID { 967 }
    private var NID_X9_42_S224K1: NID { 979 }
    private var NID_X9_42_S256K1: NID { 973 }
    
    /// Returns the Numeric Identifier (``NID``) corresponding to each
    /// set of standardized domain parameters.
    
    internal var numericIdentifier: NID {
        return switch self {
        case .PARAM_ID_GFP_1024_160: NID_X9_42_S163K1
        case .PARAM_ID_GFP_2048_224: NID_X9_42_S224K1
        case .PARAM_ID_GFP_2048_256: NID_X9_42_S256K1
        case .PARAM_ID_ECP_NIST_P192_R1: NID_X9_62_prime192v1
        case .PARAM_ID_ECP_BRAINPOOL_P192_R1: NID_brainpoolP192r1
        case .PARAM_ID_ECP_NIST_P224_R1: NID_secp224r1
        case .PARAM_ID_ECP_BRAINPOOL_P224_R1: NID_brainpoolP224r1
        case .PARAM_ID_ECP_NIST_P256_R1: NID_X9_62_prime256v1
        case .PARAM_ID_ECP_BRAINPOOL_P256_R1: NID_brainpoolP256r1
        case .PARAM_ID_ECP_BRAINPOOL_P320_R1: NID_brainpoolP320r1
        case .PARAM_ID_ECP_NIST_P384_R1: NID_secp384r1
        case .PARAM_ID_ECP_BRAINPOOL_P384_R1: NID_brainpoolP384r1
        case .PARAM_ID_ECP_BRAINPOOL_P512_R1: NID_brainpoolP512r1
        case .PARAM_ID_ECP_NIST_P521_R1: NID_secp521r1
        }
    }
    
    /// Returns the type of standardized domain parameters
    /// (Galois Field Parameters or Elliptic Curve Parameters).
    
    internal var type: StandardizedDomainParametersType {
        return switch self {
        case .PARAM_ID_GFP_1024_160, .PARAM_ID_GFP_2048_224, .PARAM_ID_GFP_2048_256: .GFP
        default: .ECP
        }
    }
}

/// The `StandardizedDomainParametersType` enumeration represents the
/// type of ``StandardizedDomainParameters``.
///
/// - SeeAlso: ``StandardizedDomainParameters`` and ``KeyAgreementAlgorithm``

internal enum StandardizedDomainParametersType {
    /// Galois Field Parameters
    case GFP
    
    /// Elliptic Curve Parameters
    case ECP
}
