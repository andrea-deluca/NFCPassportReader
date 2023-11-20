//
//  PassiveAuthenticationHandler.swift
//  
//
//  Created by Andrea Deluca on 19/10/23.
//

import Foundation

/// `PassiveAuthenticationHandler` is responsible for performing passive authentication
/// on data groups of an eMRTD.
///
/// Passive Authentication proves that the contents of the Document Security Object (``SOD``) and LDS are authentic and not changed.
///
/// - Note: This verification mechanism does not require processing capabilities of the contactless IC in the
/// Therefore it is called “Passive Authentication” of the contactless IC’s contents.
///
/// - Important: It does not prevent exact copying of the contactless IC’s content or chip substitution.
/// See ``ChipAuthenticationHandler`` for more about that.
///
/// - SeeAlso: ``SOD`` and ``HashAlgorithm``

internal final class PassiveAuthenticationHandler {
    private var sod: SOD
    
    /// Initialize the ``PassiveAuthenticationHandler`` with a ``SOD`` (Security Object Document) object.
    ///
    /// - Parameter sod: The ``SOD`` object containing security-related data.
    
    internal init(sod: SOD) {
        self.sod = sod
    }
    
    /// Perform passive authentication on specified data groups of the eMRTD document.
    ///
    /// Passive authentication checks the integrity of data groups and ensures that the Security Object Document (SOD) is correctly signed.
    ///
    /// - Parameter dataGroups: An array of data groups to be authenticated.
    ///
    /// - Throws: An error if the authentication process fails or if there are issues with the provided data.
    
    internal func performPassiveAuthentication(on dataGroups: [DataGroup]) throws {
        // Get SOD Content and verify that its correctly signed by the Document Signing Certificate
        if !sod.signedData.isSignedDataValid {
            throw NFCPassportReaderError.PassiveAuthenticationFailed("Signed data is not valid")
        }
        
        // verify passport data by comparing Hashes in SOD against
        // computed hashes to ensure data not been tampered with
        
        try dataGroups.filter {
            $0.identifier != .COM && $0.identifier != .SOD
        }.forEach { dataGroup in
            guard let currentSodHash = sod.signedData.encapContentInfo[dataGroup.identifier] else {
                throw NFCPassportReaderError.PassiveAuthenticationFailed("Data group hash not found in SOD")
            }
            
            let computedHash = try HashAlgorithm.hash([UInt8](dataGroup.data.encodedBytes), with: sod.signedData.digestAlgorithm)
            
            if computedHash != currentSodHash {
                throw NFCPassportReaderError.PassiveAuthenticationFailed("\(String(describing: dataGroup.identifier)) hash not match")
            }
        }
    }
}
