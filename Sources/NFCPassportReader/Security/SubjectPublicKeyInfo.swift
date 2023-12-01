//
//  SubjectPublicKeyInfo.swift
//  
//
//  Created by Andrea Deluca on 18/09/23.
//

import Foundation
import OpenSSL

/// The `SubjectPublicKeyInfo` class represents a data structure defined by the ASN.1 notation.
/// It is used to encapsulate information related to a public key.
///
/// According to the ASN.1 definition, a `SubjectPublicKeyInfo` consists of two components: an `AlgorithmIdentifier`
/// and a `subjectPublicKey` of type `BIT STRING`.
///
/// The data structures `SubjectPublicKeyInfo` and `AlgorithmIdentifier` are defined as follows:
///
///  ```
///  SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm  AlgorithmIdentifier,
///     subjectPublicKey    BIT STRING
///  }
///
///  AlgorithmIdentifier ::= SEQUENCE {
///     algorithm OBJECT IDENTIFIER,
///     parameters ANY DEFINED BY algorithm OPTIONAL
///  }
///  ```
///
///  - Note: This class encapsulate just the public key. The algorithm data structure is not included here.

internal final class SubjectPublicKeyInfo {
    private(set) var publicKey: OpaquePointer
    private(set) var subjectPublicKeyBytes: [UInt8]
    
    /// Initializes a ``SubjectPublicKeyInfo`` object from an ``ASN1Node``.
    ///
    /// - Parameter node: An ``ASN1Node`` containing the encoded public key information.
    ///
    /// - Throws: An error if there is an issue with decoding the provided ASN.1 node
    ///           into a public key.
    
    internal init(from node: ASN1Node) throws {
        
        var bytes: [UInt8]?
        
        try node.children?.forEach { child in
            if child.tag == ASN1UniversalTag.BIT_STRING {
                
                guard case .primitive(let subjectPublicKey) = child.content else {
                    throw NFCPassportReaderError.UnexpectedResponseStructure
                }
                
                let parsedSubjectPublicKey = try ASN1Parser.parse(subjectPublicKey.dropFirst())
                
                guard case .primitive(let keyBytes) = parsedSubjectPublicKey.content else {
                    throw NFCPassportReaderError.UnexpectedResponseStructure
                }
                
                bytes = [UInt8](keyBytes)
            }
        }
        
        guard let bytes = bytes else { throw NFCPassportReaderError.UnexpectedError }
        self.subjectPublicKeyBytes = bytes
        
        self.publicKey = try node.encodedBytes.withUnsafeBytes { bytes in
            var newPtr = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self)
            guard let key = d2i_PUBKEY(nil, &newPtr, node.encodedBytes.count) else {
                throw NFCPassportReaderError.InvalidDataPassed("Unable to read public key")
            }
            return key
        }
    }
    
    deinit { EVP_PKEY_free(publicKey) }
}
