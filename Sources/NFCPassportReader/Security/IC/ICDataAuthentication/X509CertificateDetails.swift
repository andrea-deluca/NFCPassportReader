//
//  X509CertificateDetails.swift
//  
//
//  Created by Andrea Deluca on 19/10/23.
//

import Foundation
import OpenSSL

/// `X509CertificateDetails` is a structure representing the details of an X.509 certificate.
///
/// - SeeAlso: ``X509Certificate``

public struct X509CertificateDetails {
    
    /// The fingerprint of the certificate.
    public private(set) var fingerprint: String?
    
    /// The issuer of the certificate.
    public private(set) var iusser: CertificateEntity?
    
    /// The subject (soggetto) of the certificate.
    public private(set) var subject: CertificateEntity?
    
    /// The serial number of the certificate.
    public private(set) var serialNumber: String?
    
    /// The name of the signature algorithm used in the certificate.
    public private(set) var signatureAlgorithmName: String?
    
    /// The name of the public key algorithm used in the certificate.
    public private(set) var publicKeyAlgorithmName: String?
    
    /// The date of issue (validity start) of the certificate.
    public private(set) var dateOfIssue: String?
    
    /// The date of expiry (validity end) of the certificate.
    public private(set) var dateOfExpiry: String?
    
    /// Initialize the ``X509CertificateDetails`` structure with an OpenSSL `X509` certificate.
    ///
    /// - Parameter cert: The OpenSSL `X509` certificate.
    ///
    /// - Throws: An error if there is an issue extracting certificate details.
    
    internal init(cert: OpaquePointer) throws {
        self.fingerprint = Self.getFingerprint(from: cert)
        self.iusser = try .init(entity: X509_get_issuer_name(cert))
        self.subject = try .init(entity: X509_get_subject_name(cert))
        self.serialNumber = Self.getSerialNumber(from: cert)
        self.signatureAlgorithmName = Self.getSignatureAlgorithmName(from: cert)
        self.publicKeyAlgorithmName = Self.getPublicKeyAlgorithmName(from: cert)
        self.dateOfExpiry = Self.getDateOfExpiry(from: cert)
        self.dateOfIssue = Self.getDateOfIssue(from: cert)
    }
    
    private static func ASN1TimeToString( _ date: UnsafePointer<ASN1_TIME> ) -> String? {
        guard let b = BIO_new(BIO_s_mem()) else { return nil }
        defer { BIO_free(b) }
        
        ASN1_TIME_print(b, date)
        return String(bio: b)
    }
    
    private static func getAlgorithm( _ algo:  OpaquePointer? ) -> String? {
        guard let algo = algo else { return nil }
        let len = OBJ_obj2nid(algo)
        var algoString : String? = nil
        if let sa = OBJ_nid2ln(len) {
            algoString = String(cString: sa)
        }
        return algoString
    }
}

/// Extension for `X509CertificateDetails` to include methods for extracting specific details.

private extension X509CertificateDetails {
    private static func getFingerprint(from cert: OpaquePointer) -> String {
        let fdig = EVP_sha1()
        
        var n : UInt32 = 0
        
        let md = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(EVP_MAX_MD_SIZE))
        
        defer {
            md.deinitialize(count: Int(EVP_MAX_MD_SIZE))
            md.deallocate()
        }
        
        X509_digest(cert, fdig, md, &n)
        
        return UnsafeMutableBufferPointer(start: md, count: Int(n))
            .map({ BytesRepresentationConverter
                .convertToHexRepresentation(from: $0) })
            .joined(separator: ":")
    }
    
    private static func getSerialNumber(from cert: OpaquePointer) -> String {
        String(ASN1_INTEGER_get(X509_get_serialNumber(cert)), radix: 16, uppercase: true)
    }
    
    private static func getSignatureAlgorithmName(from cert: OpaquePointer) -> String? {
        let algor = X509_get0_tbs_sigalg(cert)
        let algo = getAlgorithm( algor?.pointee.algorithm)
        return algo
    }
    
    private static func getPublicKeyAlgorithmName(from cert: OpaquePointer) -> String? {
        let pubKey = X509_get_X509_PUBKEY(cert)
        var ptr : OpaquePointer?
        X509_PUBKEY_get0_param(&ptr, nil, nil, nil, pubKey)
        let algo = getAlgorithm(ptr)
        return algo
    }
    
    private static func getDateOfIssue(from cert: OpaquePointer) -> String? {
        var notBefore : String?
        if let val = X509_get0_notBefore(cert) {
            notBefore = ASN1TimeToString(val)
        }
        return notBefore
        
    }
    
    private static func getDateOfExpiry(from cert: OpaquePointer) -> String? {
        var notAfter : String?
        if let val = X509_get0_notAfter(cert) {
            notAfter = ASN1TimeToString(val)
        }
        return notAfter
    }
}

/// ``CertificateEntity`` is a structure representing the entity (issuer or subject) of an X.509 certificate.

public extension X509CertificateDetails {
    struct CertificateEntity {
        
        /// The country associated with the entity.
        public private(set) var country: String?
        
        /// The organization associated with the entity.
        public private(set) var organization: String?
        
        /// The organizational unit associated with the entity.
        public private(set) var organizationUnit: String?
        
        /// The common name associated with the entity.
        public private(set) var commonName: String?
        
        /// The serial number associated with the entity.
        public private(set) var serialNumber: String?
        
        /// Initialize the ``CertificateEntity`` with a description string.
        ///
        /// - Parameter description: The description string containing entity details.
        
        internal init(description: String) {
            description.split(separator: ",").map { inner in
                inner.split(separator: "=")
            }.forEach { pair in
                if let key = pair.first, let value = pair.last {
                    switch key {
                    case "C": self.country = String(value)
                    case "O": self.organization = String(value)
                    case "OU": self.organizationUnit = String(value)
                    case "CN": self.commonName = String(value)
                    case "serialNumber": self.serialNumber = String(value)
                    default: return
                    }
                }
            }
        }
        
        /// Initialize a ``CertificateEntity`` with details extracted from an OpenSSL `X509_NAME` entity.
        ///
        /// - Parameter entity: An OpenSSL `X509_NAME` entity containing entity details.
        ///
        /// - Throws: An error if there is an issue extracting entity details.
        
        internal init(entity: OpaquePointer) throws {
            let description: String
            
            // Create a memory-based BIO to handle the output.
            guard let output = BIO_new( BIO_s_mem()) else {
                throw NFCPassportReaderError.UnexpectedError
            }
            
            defer { BIO_free(output) }
            
            // Define flags to control the formatting of the string representation.
            let flags = UInt(
                ASN1_STRFLGS_ESC_2253 |
                ASN1_STRFLGS_ESC_CTRL |
                ASN1_STRFLGS_ESC_MSB |
                ASN1_STRFLGS_UTF8_CONVERT |
                ASN1_STRFLGS_DUMP_UNKNOWN |
                ASN1_STRFLGS_DUMP_DER | XN_FLAG_SEP_COMMA_PLUS |
                XN_FLAG_DN_REV |
                XN_FLAG_FN_SN |
                XN_FLAG_DUMP_UNKNOWN_FIELDS)
            
            // Generate the string representation of the entity details.
            X509_NAME_print_ex(output, entity, 0, flags)
            
            // Convert the BIO to a string and initialize the entity with the description.
            description = String(bio: output)
            self.init(description: description)
        }
    }
}
