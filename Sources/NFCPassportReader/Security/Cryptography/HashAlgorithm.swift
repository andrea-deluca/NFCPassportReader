//
//  HashAlgorithm.swift
//  
//
//  Created by Andrea Deluca on 11/09/23.
//

import Foundation
import CommonCrypto
import CryptoKit

/// The `HashAlgorithm` enum represents various hash algorithms that can be used to calculate the hash of data.
/// Supported hash algorithms include SHA1, SHA224, SHA256, SHA384, and SHA512.
///
/// - SeeAlso: ``EncryptionAlgorithm`` and ``KeyAgreementAlgorithm``

internal enum HashAlgorithm: ObjectIdentifier {
    case SHA1 = "2.26"
    case SHA224 = "101.3.4.2.4"
    case SHA256 = "101.3.4.2.1"
    case SHA384 = "101.3.4.2.2"
    case SHA512 = "101.3.4.2.3"
    
    /// Calculate the hash of the provided data using the specified hash algorithm.
    ///
    /// - Parameters:
    ///   - data: An array of bytes representing the data to be hashed.
    ///   - algorithm: The hash algorithm to be used for the calculation.
    ///
    /// - Throws: An error if something went wrong.
    ///
    /// - Returns: An array of bytes representing the hash value.
    
    internal static func hash(_ data: [UInt8], with algorithm: HashAlgorithm) throws -> [UInt8] {
        try algorithm.hash(data)
    }
    
    /// Calculate the hash of the provided data using the hash algorithm.
    ///
    /// - Parameter data: An array of bytes representing the data to be hashed.
    ///
    /// - Throws: An error if something went wrong.
    ///
    /// - Returns: An array of bytes representing the hash value.
    
    internal func hash(_ data: [UInt8]) throws -> [UInt8] {
        if self == .SHA224 {
            return self.calcSHA224Hash(data)
        }
        
        var hashFunction = try self.getHashFunction()
        
        hashFunction.update(data: data)
        let digest = hashFunction.finalize()
        return Array(digest)
    }
    
    /// Calculate the hash of the provided data using the specified hash algorithm.
    ///
    /// - Parameters:
    ///   - data: An array of `Data` representing the data to be hashed.
    ///   - algorithm: The hash algorithm to be used for the calculation.
    ///
    /// - Throws: An error if the chosen hash algorithm is not supported for `Data`.
    ///
    /// - Returns: An array of `UInt8` representing the hash value.
    
    internal static func hash(_ data: [Data], with algorithm: HashAlgorithm) throws -> [UInt8] {
        try algorithm.hash(data)
    }
    
    /// Calculate the hash of the provided data using the hash algorithm.
    ///
    /// - Parameter data: An array of `Data` representing the data to be hashed.
    ///
    /// - Throws: An error if the chosen hash algorithm is not supported for `Data`.
    ///
    /// - Returns: An array of `UInt8` representing the hash value.
    
    internal func hash(_ data: [Data]) throws -> [UInt8] {
        if self == .SHA224 {
            throw HashAlgorithmError.NotImplemented
        }
        
        var hashFunction = try self.getHashFunction()
        
        data.forEach { hashFunction.update(data: $0) }
        let digest = hashFunction.finalize()
        return Array(digest)
    }
}

private extension HashAlgorithm {
    
    /// Calculate the SHA224 hash of the provided `UInt8` data.
    ///
    /// - Parameter data: An array of `UInt8` representing the data to be hashed.
    /// - Returns: An array of `UInt8` representing the SHA224 hash.
    
    private func calcSHA224Hash(_ data: [UInt8]) -> [UInt8] {
        var digest = [UInt8](repeating: 0x00, count: Int(CC_SHA224_DIGEST_LENGTH))
        
        data.withUnsafeBytes {
            _ = CC_SHA224($0.baseAddress, CC_LONG(data.count), &digest)
        }
        
        return digest
    }
    
    /// Get the appropriate hash function based on the selected `HashAlgorithm`.
    ///
    /// - Throws: An error if an invalid hash function is found.
    ///
    /// - Returns: An instance of the selected hash function.
    
    private func getHashFunction() throws -> any HashFunction {
        return switch self {
        case .SHA1: Insecure.SHA1()
        case .SHA256: CryptoKit.SHA256()
        case .SHA384: CryptoKit.SHA384()
        case .SHA512: CryptoKit.SHA512()
        default: throw HashAlgorithmError.UnexpectedHashFunctionFound
        }
    }
}

private enum HashAlgorithmError: Error {
    case UnexpectedHashFunctionFound
    case NotImplemented
}
