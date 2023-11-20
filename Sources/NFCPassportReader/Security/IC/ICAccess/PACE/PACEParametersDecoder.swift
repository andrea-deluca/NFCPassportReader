//
//  PACEParametersDecoder.swift
//  
//
//  Created by Andrea Deluca on 13/10/23.
//

import Foundation

/// The `PACEParametersDecoder` class is responsible for decoding
/// ``StandardizedDomainParameters`` used during PACE based on their identifiers.
///
/// - SeeAlso: ``PACEInfo``, ``PACESecurityProtocol``, ``PACEMapping``,
/// ``PACEHandler``, and ``StandardizedDomainParameters``

internal final class PACEParametersDecoder {
    internal typealias ParametersIdentifier = Int
    
    /// A dictionary mapping parameters identifiers to the corresponding ``StandardizedDomainParameters``.
    
    private static let parameters: [ParametersIdentifier: StandardizedDomainParameters] = [
        // MARK:  Galois Field Standardized Domain Parameters
        
        0: .PARAM_ID_GFP_1024_160,
        1: .PARAM_ID_GFP_2048_224,
        2: .PARAM_ID_GFP_2048_256,
        
        // MARK: Elliptic Curve Standardized Domain Parameters
        
        8: .PARAM_ID_ECP_NIST_P192_R1,
        9: .PARAM_ID_ECP_BRAINPOOL_P192_R1,
        10: .PARAM_ID_ECP_NIST_P224_R1,
        11: .PARAM_ID_ECP_BRAINPOOL_P224_R1,
        12: .PARAM_ID_ECP_NIST_P256_R1,
        13: .PARAM_ID_ECP_BRAINPOOL_P256_R1,
        14: .PARAM_ID_ECP_BRAINPOOL_P320_R1,
        15: .PARAM_ID_ECP_NIST_P384_R1,
        16: .PARAM_ID_ECP_BRAINPOOL_P384_R1,
        17: .PARAM_ID_ECP_BRAINPOOL_P512_R1,
        18: .PARAM_ID_ECP_NIST_P521_R1
    ]
    
    /// Decodes PACE parameters based on their identifier and returns
    /// the corresponding ``StandardizedDomainParameters``.
    ///
    /// - Parameter parametersId: The identifier of PACE parameters.
    ///
    /// - Returns: The corresponding ``StandardizedDomainParameters`` or `nil` if not found.
    
    internal static func decode(parametersId: ParametersIdentifier) -> StandardizedDomainParameters? {
        parameters[parametersId]
    }
    
    /// Get the PACE parameters identifier from the corresponding ``StandardizedDomainParameters``.
    ///
    /// - Parameter parameters: The ``StandardizedDomainParameters``.
    ///
    /// - Returns: The corresponding PACE parameters identifier or `nil` if not found.
    
    internal static func getParametersId(from parameters: StandardizedDomainParameters) -> ParametersIdentifier? {
        Self.parameters.first { $0.value == parameters }?.key
    }
}
