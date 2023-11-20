//
//  SOD.swift
//  
//
//  Created by Andrea Deluca on 17/10/23.
//

import Foundation

/// `SOD` (Security Object Document) is a class representing the Security Object data group within an eMRTD.
/// It contains information related to digital signatures and security attributes.
///
/// - Tip: Retrieving data group hashes and perform Passive Autentication is possible by decoding `SOD`.
///
/// - SeeAlso: ``DataGroup``, ``SignedData``, ``PKCS7``,
/// ``X509Certificate`` and ``PassiveAuthenticationHandler``

internal final class SOD: DataGroup {
    private(set) var pkcs7: PKCS7!
    private(set) var signedData: SignedData!
    
    /// An array of X.509 certificates associated with the Security Object Document.
    
    internal var certs: [X509Certificate] { pkcs7.certs }
    
    /// Initialize a ``SOD`` instance with ASN.1 data.
    ///
    /// - Parameter data: The ASN.1 data representing the Security Object Document.
    ///
    /// - Throws: An error if there are issues with the provided data or during initialization.
    
    internal required init(_ data: ASN1Node, identifier: DGTag) throws {
        try super.init(data, identifier: identifier)
    }
    
    /// Decode the ASN.1 data to extract the ``PKCS7Message`` and ``SignedData``.
    ///
    /// - Parameter data: The ASN.1 data representing the Security Object Document content.
    ///
    /// - Throws: An error if there are issues with the provided data or during decoding.
    
    override internal func decode(_ data: ASN1Node) throws {
        guard case .constructed(let sodContent) = data.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        // Initialize PKCS7Message and SignedData from the provided ASN.1 data.
        
        self.pkcs7 = try PKCS7(data: sodContent.contentBytes)
        self.signedData = try SignedData(data: sodContent)
    }
}
