//
//  PKCS7.swift
//  
//
//  Created by Andrea Deluca on 19/10/23.
//

import Foundation
import OpenSSL

/// `PKCS7` is a class for handling PKCS#7 messages, extracting X.509 certificates.
///
/// - SeeAlso: ``X509Certificate``

internal final class PKCS7 {
    private(set) var certs: [X509Certificate]
    
    /// Initialize the PKCS7 instance with PKCS#7 message data.
    ///
    /// - Parameter data: The PKCS#7 message data in the form of an array of bytes.
    ///
    /// - Throws: An error if there is an issue parsing the PKCS#7 data or certificates.
    
    internal init(data: [UInt8]) throws {
        // Create a memory-based BIO to hold the input data.
        let inputBuffer = BIO_new(BIO_s_mem())
        defer { BIO_free(inputBuffer) }
        
        // Write the input data to the BIO.
        let _ = data.withUnsafeBytes { (ptr) in
            BIO_write(inputBuffer, ptr.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(data.count))
        }
        
        // Parse the PKCS#7 data using d2i_PKCS7_bio.
        guard let pkcs7Data = d2i_PKCS7_bio(inputBuffer, nil) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to read PKCS#7")
        }
        defer { PKCS7_free(pkcs7Data) }
        
        // Extract the certificates from the PKCS#7 data based on the PKCS7 type.
        var certs : OpaquePointer? = nil
        let pkcs7Type = OBJ_obj2nid(pkcs7Data.pointee.type)
        
        if pkcs7Type == NID_pkcs7_signed,
           let sign = pkcs7Data.pointee.d.sign {
            certs = sign.pointee.cert
        } else if pkcs7Type == NID_pkcs7_signedAndEnveloped,
                  let signed_and_enveloped = pkcs7Data.pointee.d.signed_and_enveloped {
            certs = signed_and_enveloped.pointee.cert
        }
        
        // Decode the certificates and store them in the X509Certificate array.
        var decodedCerts: [X509Certificate] = []
        if let certs = certs  {
            let certCount = sk_X509_num(certs)
            for i in 0 ..< certCount {
                let encodedCert = sk_X509_value(certs, i);
                if let decodedCert = try X509Certificate(with: encodedCert) {
                    decodedCerts.append(decodedCert)
                }
            }
        }
        
        self.certs = decodedCerts
    }
}
