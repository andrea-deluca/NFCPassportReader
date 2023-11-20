//
//  X509Certificate.swift
//
//
//  Created by Andrea Deluca on 17/10/23.
//

import Foundation
import OpenSSL

/// `X509Certificate` is a class representing an X.509 certificate.
///
/// - SeeAlso: ``PKCS7Message`` and ``X509CertificateDetails``

internal final class X509Certificate {
    
    /// The OpenSSL `X509` certificate object.
    private var cert: OpaquePointer
    
    /// Details of the X.509 certificate, such as subject, issuer, and validity information.
    private(set) var details: X509CertificateDetails?
    
    /// Retrieve the certificate in PEM (Privacy-Enhanced Mail) format.
    internal var pem: String {
        
        // Create a memory-based BIO to hold the output.
        guard let output = BIO_new(BIO_s_mem()) else {
            return "Unable to convert certificate to PEM"
        }
        
        defer { BIO_free(output) }
        
        // Write the X.509 certificate to the memory-based BIO in PEM format.
        PEM_write_bio_X509(output, self.cert)
        
        // Convert the BIO to a string and return the PEM representation.
        return String(bio: output)
    }
    
    /// Initialize an ``X509Certificate`` instance with an OpenSSL `X509` certificate object.
    ///
    /// - Parameter cert: The OpenSSL `X509` certificate object.
    ///
    /// - Throws: An error if there is an issue initializing the certificate.
    
    internal init?(with cert: OpaquePointer?) throws {
        guard let cert = cert else { return nil }
        
        self.cert = X509_dup(cert)
        self.details = try? X509CertificateDetails(cert: cert)
    }
    
    /// Deinitialize the ``X509Certificate`` instance and
    /// free the associated OpenSSL certificate object.
    
    deinit { X509_free(self.cert) }
}
