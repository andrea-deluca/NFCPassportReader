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
    
    public var firstName: String {
        personalDetails?.fullName?.components(separatedBy: "<<")[0] ??
        travelDocument?.mrz.holderName?.components(separatedBy: "<<")[0] ?? "Unkown"
    }
    
    public var lastName: String {
        personalDetails?.fullName?.components(separatedBy: "<<")[1] ??
        travelDocument?.mrz.holderName?.components(separatedBy: "<<")[1] ?? "Unkown"
    }
    
    public var holderPicture: UIImage? {
        self.faceBiometricDataEncoding?.image
    }
}
