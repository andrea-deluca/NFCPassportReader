//
//  NFCPassportModel.swift
//  
//
//  Created by Andrea Deluca on 11/09/23.
//

import Foundation
import UIKit

public enum PassportAuthenticationStatus {
    case notDone
    case success
    case failed
    case notSupported
    case notImplemented
}

public struct NFCPassportModel {
    public var BACStatus: PassportAuthenticationStatus = .notDone
    public var CAStatus: PassportAuthenticationStatus = .notDone
    public var PACEStatus: PassportAuthenticationStatus = .notDone
    public var PAStatus: PassportAuthenticationStatus = .notDone
    
    public var AAStatus: PassportAuthenticationStatus = .notImplemented
    public var TAStatus: PassportAuthenticationStatus = .notImplemented
    
    internal var cardAccess: CardAccess?
    private(set) var dataGroupsRead: [DGTag: DataGroup] = [:]
    
    internal mutating func addDataGroup(_ id: DGTag, dataGroup: DataGroup) {
        self.dataGroupsRead[id] = dataGroup
    }
    
    public var travelDocument: TravelDocument? {
        (self.dataGroupsRead[.DG1] as? DataGroup1)?.travelDocument
    }
    
    public var faceBiometricDataEncoding: FaceBiometricDataEncoding? {
        (self.dataGroupsRead[.DG2] as? DataGroup2)?.faceBiometricDataEncoding
    }
    
    public var personalDetails: PersonalDetails? {
        (self.dataGroupsRead[.DG11] as? DataGroup11)?.personalDetails
    }
    
    public var documentDetails: DocumentDetails? {
        (self.dataGroupsRead[.DG12] as? DataGroup12)?.documentDetails
    }
    
    public var certificateDetails: X509CertificateDetails? {
        (self.dataGroupsRead[.SOD] as? SOD)?.certs.first?.details
    }
    
    public var lastName: String? {
        personalDetails?.surname ??
        travelDocument?.mrz.surname
    }
    
    public var firstName: String? {
        personalDetails?.name ??
        travelDocument?.mrz.name
    }
    
    public var holderPicture: UIImage? {
        self.faceBiometricDataEncoding?.image
    }
    
    public var availableDataGroups: [String]? {
        (self.dataGroupsRead[.COM] as? COM)?.availableDataGroups.map { $0.name }
    }
    
    public var dataGroupsReadNames: [String] {
        self.dataGroupsRead.map { $0.key.name }
    }
    
    public var paceSecurityProtocol: String? {
        if let paceInfo = (self.dataGroupsRead[.DG14] as? DataGroup14)?
            .securityInfos
            .first(where: { $0 is PACEInfo }) as? PACEInfo {
            return "\(paceInfo.securityProtocol)"
        } else { return nil }
    }
    
    public var chipAuthenticationSecurityProtocol: String? {
        if let caInfo = (self.dataGroupsRead[.DG14] as? DataGroup14)?
            .securityInfos
            .first(where: { $0 is ChipAuthenticationInfo }) as? ChipAuthenticationInfo {
            return "\(caInfo.securityProtocol)"
        } else if let caPubKeyInfo = (self.dataGroupsRead[.DG14] as? DataGroup14)?
            .securityInfos
            .first(where: { $0 is ChipAuthenticationPublicKeyInfo }) as? ChipAuthenticationPublicKeyInfo {
            return "\(caPubKeyInfo.securityProtocol.defaultChipAuthenticationSecurityProtocol)"
        } else { return nil }
    }
    
    public var chipAuthenticationPublicKeySecurityProtocol: String? {
        if let caPubKeyInfo = (self.dataGroupsRead[.DG14] as? DataGroup14)?
            .securityInfos
            .first(where: { $0 is ChipAuthenticationPublicKeyInfo }) as? ChipAuthenticationPublicKeyInfo {
            return "\(caPubKeyInfo.securityProtocol)"
        } else { return nil }
    }
    
    public var sodHashes: [String: String] {
        if let sod = (self.dataGroupsRead[.SOD] as? SOD) {
            var hashes: [String: String] = [:]
            sod.signedData.encapContentInfo.forEach {
                hashes.updateValue(
                    BytesRepresentationConverter.convertToHexRepresentation(from: $1),
                    forKey: $0.name
                )}
            return hashes
        } else { return [:] }
    }
    
    public var sodPemCertificate: String? {
        (self.dataGroupsRead[.SOD] as? SOD)?.certs.first?.pem
    }
}
