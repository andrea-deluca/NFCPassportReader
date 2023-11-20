//
//  NFCPassportReader.swift
//
//
//  Created by Andrea Deluca on 07/09/23.
//

import Foundation
import CoreNFC

/// A class responsible for reading and authenticating NFC passport data.
///
/// This class represent the entrypoint for the NFCPassportReader package and
/// if reading is performed successfully, it returns data as ``NFCPassportModel``
/// that allows the access to the info read smartly.
///
/// - SeeAlso: ``NFCPassportModel``

public final class NFCPassportReader: NSObject {
    private typealias NFCCheckContinuation = CheckedContinuation<NFCPassportModel, Error>
    
    private var mrzKey: String?
    private var readerSession: NFCTagReaderSession?
    
    private var continuation: NFCCheckContinuation?
    private var passport: NFCPassportModel?
    
    private var scanCompletedHandler: ((NFCPassportModel?, NFCPassportReaderError?) -> Void)!
    private var shouldNotReportNextReaderSessionInvalidationErrorUserCanceled: Bool = false
    
    private var currentlyReadingDataGroup: DGTag?
    
    /// Reads passport data using the provided passport number, date of birth and date of expiry.
    ///
    /// The function uses ``MRZKeyGenerator`` to generate the MRZ (Machine-Readable Zone) key from
    /// the provided info.
    ///
    /// - Parameters:
    ///   - passportNumber: The passport number reported on the document.
    ///   - dateOfBirth: The holder date of birth, also reported on the document.
    ///   - dateOfExpiry: The document date of expiry reported on it.
    ///
    /// - Throws: An error if there's an issue with the NFC session,
    /// the authentication or data reading.
    ///
    /// - Returns: An ``NFCPassportModel`` containing passport data.
    
    public func readPassport(passportNumber: String, dateOfBirth: String, dateOfExpiry: String) async throws -> NFCPassportModel {
        try await readPassport(
            mrzKey: MRZKeyGenerator
                .generate(
                    passportNumber: passportNumber,
                    dateOfBirth: dateOfBirth,
                    dateOfExpiry: dateOfExpiry
                )
        )
    }
    
    /// Reads passport data using the provided MRZ (Machine-Readable Zone) key.
    ///
    /// - Parameter mrzKey: The MRZ key used for authentication.
    ///
    /// - Throws: An error if there's an issue with the NFC session,
    /// the authentication or data reading.
    ///
    /// - Returns: An ``NFCPassportModel`` containing passport data.
    
    
    public func readPassport(mrzKey: String) async throws -> NFCPassportModel {
        self.passport = NFCPassportModel()
        self.mrzKey = mrzKey
        
        guard NFCNDEFReaderSession.readingAvailable else {
            throw NFCPassportReaderError.NFCNotSupported
        }
        
        readerSession = NFCTagReaderSession(pollingOption: .iso14443, delegate: self, queue: nil)
        self.updateReaderSessionMessage(alertMessage: .requestPresentPassport)
        readerSession?.begin()
        
        return try await withCheckedThrowingContinuation { (continuation: NFCCheckContinuation) in
            self.continuation = continuation
        }
    }
}

extension NFCPassportReader: NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        self.readerSession?.invalidate()
        self.readerSession = nil
        
        if let readerError = error as? NFCReaderError,
           readerError.code == .readerSessionInvalidationErrorUserCanceled
            && self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled {
            self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = false
        } else {
            var userError: NFCPassportReaderError = .UnexpectedError
            if let readerError = error as? NFCReaderError {
                switch readerError.code {
                case .readerSessionInvalidationErrorUserCanceled: userError = .UserCanceled
                default: userError = .UnexpectedError
                }
            }
            self.continuation?.resume(throwing: userError)
            self.continuation = nil
        }
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        if tags.count > 1 {
            self.invalidateSession(error: .MoreThanOneTagFound)
            return
        }
        
        let passportTag: NFCISO7816Tag
        if case .iso7816(let nFCISO7816Tag) = tags.first {
            passportTag = nFCISO7816Tag
        } else {
            self.invalidateSession(error: .TagNotValid)
            return
        }
        
        Task { [passportTag] in
            do {
                try await session.connect(to: tags.first!)
                self.updateReaderSessionMessage(alertMessage: .authenticatingWithPassport)
                let tagReader = TagReader(tag: passportTag)
                
                tagReader.progress = { [unowned self] (progress) in
                    if let dgId = self.currentlyReadingDataGroup {
                        self.updateReaderSessionMessage( alertMessage: .readingDataGroupProgress(dgId, progress) )
                    }
                }
                
                let passportModel = try await self.startReading(tagReader: tagReader)
                continuation?.resume(returning: passportModel!)
                continuation = nil
            } catch let error as NFCPassportReaderError {
                self.invalidateSession(error: error)
            } catch let error {
                self.invalidateSession(error: .ConnectionError)
                continuation?.resume(throwing: error)
                continuation = nil
            }
        }
    }
    
    private func updateReaderSessionMessage(alertMessage: DisplayedMessage) {
        self.readerSession?.alertMessage = alertMessage.description
    }
}



private extension NFCPassportReader {
    private func startReading(tagReader: TagReader) async throws -> NFCPassportModel? {
        let cardAccessData = try await tagReader.readCardAccess()
        let cardAccess = try CardAccess(ASN1Parser.parse(cardAccessData))
        passport?.cardAccess = cardAccess
        
        
        try await self.doPACEAuthentication(tagReader: tagReader)
        try await tagReader.selectPassportApplication().discardResponse()
        if passport?.PACEStatus != .success {
            try await doBACAuthentication(tagReader: tagReader)
        }
        
        try await readDataGroups(tagReader: tagReader)
        self.updateReaderSessionMessage(alertMessage: .successfulRead)
        
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        readerSession?.invalidate()
        
        return self.passport
    }
    
    private func readDataGroups(tagReader: TagReader) async throws {
        
        // Read COM DataGroup for Available DataGroups
        
        if let com = try await readDataGroup(tagReader: tagReader, dgTag: .COM) as? COM {
            self.passport?.addDataGroup(.COM, dataGroup: com)
            
            // Read DG14 for Security Infos and Chip Authentication
            
            if com.availableDataGroups.contains(.DG14),
               let dg14 = try await readDataGroup(tagReader: tagReader, dgTag: .DG14) as? DataGroup14 {
                self.passport?.addDataGroup(.DG14, dataGroup: dg14)
                
                self.updateReaderSessionMessage(alertMessage: .authenticatingWithPassport)
                try await doChipAuthentication(tagReader: tagReader, dg14: dg14)
            } else { self.passport?.CAStatus = .notSupported }
            
            // Read remaining available DataGroups
            
            for dgTag in com.availableDataGroups.filter({ $0 != .DG14 }) {
                if let dataGroup = try await readDataGroup(tagReader: tagReader, dgTag: dgTag) {
                    self.passport?.addDataGroup(dgTag, dataGroup: dataGroup)
                }
            }
            
            // Read SOD DataGroup for Passive Authentication
            
            if let sod = try await readDataGroup(tagReader: tagReader, dgTag: .SOD) as? SOD {
                self.passport?.addDataGroup(.SOD, dataGroup: sod)
                try doPassiveAuthentication(sod: sod)
            }
        }
    }
    
    private func readDataGroup(tagReader: TagReader, dgTag: DGTag) async throws -> DataGroup? {
        var passportReaderError: NFCPassportReaderError
        var readAttemps = 0
        
        self.currentlyReadingDataGroup = dgTag
        self.updateReaderSessionMessage(alertMessage: .readingDataGroupProgress(dgTag, 0))
        
        repeat {
            do {
                let response = try await tagReader.readDataGroup(dgTag)
                return try DGDecoder.decode(data: response)
            } catch let error as NFCPassportReaderError {
                var skipElement = false
                var redoBAC = false
                
                passportReaderError = error
                
                if case .ResponseError(let error, _, _, _) = error {
                    switch error {
                    case .ClassNotSupported:
                        if self.passport?.CAStatus != .notDone {
                            redoBAC = true
                        } else {throw error}
                    case .SecurityStatusNotSatisfied, .FileNotFound:
                        skipElement = true
                    case .IncorrectSMDataObject: redoBAC = true
                    case .WrongLength, .EndReachedBeforeReadingLeBytes:
                        tagReader.reduceDataAmountToRead()
                        redoBAC = true
                    default: break
                    }
                }
                
                if redoBAC { try await doBACAuthentication(tagReader: tagReader) }
                if skipElement { return nil }
                readAttemps += 1
            }
        } while readAttemps < 2
        
        throw passportReaderError
    }
    
    private func invalidateSession(error: NFCPassportReaderError) {
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate(errorMessage: DisplayedMessage.error(error).description)
        self.continuation?.resume(throwing: error)
        self.continuation = nil
    }
    
}

private extension NFCPassportReader {
    private func doPACEAuthentication(tagReader: TagReader) async throws {
        self.currentlyReadingDataGroup = nil
        let paceHandler = try PACEHandler(tagReader: tagReader, cardAccess: passport!.cardAccess!)
        do {
            try await paceHandler.performPACE(mrzKey: self.mrzKey!)
            passport?.PACEStatus = .success
        } catch {
            passport?.PACEStatus = .failed
        }
    }
    
    private func doBACAuthentication(tagReader: TagReader) async throws {
        self.currentlyReadingDataGroup = nil
        let bacHandler = BACHandler(tagReader: tagReader)
        do {
            try await bacHandler.performBAC(mrzKey: self.mrzKey!)
            self.passport?.BACStatus = .success
        } catch {
            self.passport?.BACStatus = .failed
            throw error
        }
    }
    
    private func doChipAuthentication(tagReader: TagReader, dg14: DataGroup14) async throws {
        self.currentlyReadingDataGroup = nil
        let caHandler = ChipAuthenticationHandler(tagReader: tagReader, dg14: dg14)
        if caHandler.isChipAuthenticationSupported {
            do {
                try await caHandler.performCA()
                self.passport?.CAStatus = .success
            } catch {
                self.passport?.CAStatus = .failed
                try await doBACAuthentication(tagReader: tagReader)
            }
        }
    }
    
    private func doPassiveAuthentication(sod: SOD) throws {
        self.currentlyReadingDataGroup = nil
        do {
            let paHandler = PassiveAuthenticationHandler(sod: sod)
            try paHandler.performPassiveAuthentication(on: [DataGroup](passport!.dataGroupsRead.values))
            self.passport?.PAStatus = .success
        } catch {
            self.passport?.PAStatus = .failed
        }
    }
}
