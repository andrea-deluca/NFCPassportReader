//
//  SignedData.swift
//  
//
//  Created by Andrea Deluca on 19/10/23.
//

import Foundation
import OpenSSL

/// `SignedData` is a class representing data contained in a signed data structure
/// found in eMRTD ``SOD`` data group.
///
/// The ASN.1 data structure `SignedData` is defined as follows:
///
/// ```
/// SignedData ::= SEQUENCE {
///     INTEGER version CMSVersion,
///     SET digestAlgorithms DigestAlgorithmIdentifiers,
///     SEQUENCE encapContentInfo EncapsulatedContentInfo,
///     certificates [0] IMPLICIT CertificateSet OPTIONAL,
///     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///     SET signerInfos SignerInfos
/// }
///
/// DigestAlgorithmIdentifiers ::= AlgorithmIdentifier
///
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm OBJECT IDENTIFIER,
///     parameters ANY OPTIONAL
/// }
///
/// EncapsulatedContentInfo ::= SEQUENCE {
///     eContentType ContentType,
///     eContent [0] EXPLICIT OCTET STRING OPTIONAL
/// }
///
/// ContentType ::= OBJECT IDENTIFIER
///
/// SignerInfos ::= SET OF SignerInfo
///
/// SignerInfo ::= SEQUENCE {
///     version CMSVersion,
///     sid SignerIdentifier,
///     digestAlgorithm DigestAlgorithmIdentifier,
///     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///     signatureAlgorithm SignatureAlgorithmIdentifier,
///     signature SignatureValue,
///     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
/// }
///
/// SignerIdentifier ::= CHOICE {
///     issuerAndSerialNumber IssuerAndSerialNumber,
///     subjectKeyIdentifier [0] SubjectKeyIdentifier
/// }
///
/// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
///
/// Attribute ::= SEQUENCE {
///     attrType OBJECT IDENTIFIER,
///     attrValues SET OF AttributeValue
/// }
///
/// AttributeValue ::= ANY
/// SignatureValue ::= OCTET STRING
/// ```
///
/// In addition, the class allows to verify the signed data against the stored certificate.
///
/// - SeeAlso: ``SOD`` and ``PassiveAuthenticationHandler``

internal final class SignedData {
    typealias DataGroupHash = [UInt8]
    
    /// The ASN.1 node collection containing the data.
    private var data: ASN1NodeCollection
    
    /// The hash algorithm used for signing.
    private(set) var digestAlgorithm: HashAlgorithm!
    
    /// A dictionary representing encapsulated content information,
    /// where the key is the ``DGTag`` and the value is the data group hash.
    private(set) var encapContentInfo: [DGTag: DataGroupHash] = [:]
    
    internal lazy var isSignedDataValid: Bool = {
        do {
            try self.verify()
            return true
        } catch { return false }
    }()
    
    /// Initialize a ``SignedData`` instance with an ASN.1 node collection.
    ///
    /// - Parameter content: The ASN.1 node collection containing the signed data.
    ///
    /// - Throws: An error if there is an issue decoding the signed data.
    
    internal init(data: ASN1NodeCollection) throws {
        self.data = data
        
        guard case .constructed(let sodSequenceContent) = data.firstChild?.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        try sodSequenceContent.forEach { sodSequenceNode in
            if sodSequenceNode.tag == ASN1UniversalTag.OBJECT_IDENTIFIER { return }
            
            guard case .constructed(let signedDataNodeCollection) = sodSequenceNode.content else {
                throw NFCPassportReaderError.UnexpectedResponseStructure
            }
            
            try self.decode(data: signedDataNodeCollection)
        }
    }
    
    /// Decode the signed data from the ASN.1 node collection.
    ///
    /// - Parameter data: The ASN.1 node collection containing decodable signed data.
    ///
    /// - Throws: An error if there is an issue decoding the data.
    
    internal func decode(data: ASN1NodeCollection) throws {
        guard case .constructed(let signedDataSequence) = data.firstChild?.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        try self.decodeDigestAlgorithm(sequence: signedDataSequence)
        try self.decodeEncapsulatedContentInfo(sequence: signedDataSequence)
    }
    
    /// Verify the integrity and authenticity of the signed data.
    ///
    /// This method verifies whether the signed data is valid and has not been tampered with.
    /// It also checks the authenticity of the signature using the CMS (Cryptographic Message Syntax) standard.
    ///
    /// - Throws: An error if the verification fails or if there are issues during the verification process.
    
    internal func verify() throws {
        guard let inf = BIO_new(BIO_s_mem()) else {
            throw NFCPassportReaderError.CMSCertificateVerificationFailed("Unable to allocate input buffer")
        }
        defer { BIO_free(inf) }
        
        guard let out = BIO_new(BIO_s_mem()) else {
            throw NFCPassportReaderError.CMSCertificateVerificationFailed("Unable to allocate output buffer")
        }
        defer { BIO_free(out) }
        
        let _ = data.contentBytes.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(data.contentBytes.count))
        }
        
        guard let cms = d2i_CMS_bio(inf, nil) else {
            throw NFCPassportReaderError.CMSCertificateVerificationFailed("Verification of PKCS#7 failed. Unable to create CMS.")
        }
        defer { CMS_ContentInfo_free(cms) }
        
        let flags : UInt32 = UInt32(CMS_NO_SIGNER_CERT_VERIFY)
        
        if CMS_verify(cms, nil, nil, nil, out, flags) == 0 {
            throw NFCPassportReaderError.CMSCertificateVerificationFailed("Verification of PKCS#7 failed. Unable to verify signature.")
        }
    }
}

private extension SignedData {
    
    /// Decode the digest algorithm from the provided sequence.
    ///
    /// - Parameter sequence: The ASN.1 node collection containing the signed data content.
    ///
    /// - Throws: An error if there is an issue decoding the data.
    
    private func decodeDigestAlgorithm(sequence: ASN1NodeCollection) throws {
        guard case .constructed(let digestAlgorithmSequence) = try sequence
            .first(where: { $0.tag == ASN1UniversalTag.SET })?
            .children?
            .firstChild?
            .content
        else { throw NFCPassportReaderError.UnexpectedResponseStructure }
        
        try digestAlgorithmSequence.forEach { digestAlgorithmSequenceNode in
            if digestAlgorithmSequenceNode.tag == ASN1UniversalTag.OBJECT_IDENTIFIER {
                var oid = try ObjectIdentifier(node: digestAlgorithmSequenceNode)
                oid.removeFirst(4)
                self.digestAlgorithm = .init(rawValue: oid)
            }
        }
    }
    
    /// Decode the encapsulated content information from the provided sequence.
    ///
    /// Within the `encapContentInfo` data structure, an octect string is found. If it is
    /// considered as an ASN.1 data structure, its parsing is possible and the ASN.1 data structure with
    /// the following definition is found:
    ///
    /// ```
    /// ParsedContent ::= SEQUENCE {
    ///     ...
    ///     hashes SEQUENCE OF DataGroupHash
    ///     ...
    /// }
    ///
    /// DataGroupHash ::= SEQUENCE {
    ///     dataGroupTag DGFileShortIdentifier,
    ///     hash OCTECT STRING
    /// }
    ///
    /// DGFileShortIdentifier :== INTEGER (
    ///     1 | -- DG1
    ///     2 | -- DG2
    ///     3 | -- DG3
    ///     ... |
    ///     15 | -- DG15
    ///     16 -- DH16
    /// )
    /// ```
    ///
    /// According to this data structure, decoding data group hashes is possible here.
    ///
    /// - Parameter sequence: The ASN.1 node collection containing the signed data content.
    ///
    /// - Throws: An error if there is an issue decoding the data.
    
    private func decodeEncapsulatedContentInfo(sequence: ASN1NodeCollection) throws {
        guard let encapContentInfo = try sequence
            .first(where: { $0.tag == ASN1UniversalTag.SEQUENCE })?
            .children?
            .first(where: { $0.tag == 0xA0 })?
            .children?
            .firstChild
        else { throw NFCPassportReaderError.UnexpectedResponseStructure }
        
        guard case .primitive(let contentBytes) = encapContentInfo.content else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        let parsedContent = try ASN1Parser.parse([UInt8](contentBytes))
        
        parsedContent.children?.forEach { node in
            if node.tag == ASN1UniversalTag.SEQUENCE {
                if let firstChild = node.children?.firstChild,
                   firstChild.tag == ASN1UniversalTag.SEQUENCE {
                    node.children?.forEach { dataGroupHashes in
                        var dataGroup: DGTag?
                        var dataGroupHash: DataGroupHash = []
                        
                        dataGroupHashes.children?.forEach { dataGroupHashNode in
                            if dataGroupHashNode.tag == ASN1UniversalTag.INTEGER,
                               case .primitive(let tag) = dataGroupHashNode.content {
                                let dgTag = BytesRepresentationConverter.convertToHexNumber(from: tag)
                                dataGroup = DGTag.from(shortIdentifier: UInt8(dgTag))
                            } else if case .primitive(let hash) = dataGroupHashNode.content {
                                dataGroupHash = [UInt8](hash)
                            }
                        }
                        
                        if let dataGroup = dataGroup, !dataGroupHash.isEmpty {
                            self.encapContentInfo.updateValue(dataGroupHash, forKey: dataGroup)
                        }
                    }
                }
            }
        }
    }
}
