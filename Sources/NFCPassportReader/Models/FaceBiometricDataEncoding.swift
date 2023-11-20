//
//  FaceBiometricDataEncoding.swift
//  
//
//  Created by Andrea Deluca on 14/09/23.
//

import Foundation
import UIKit

/// Represents biometric face data conforming to the ISO/IEC 19794-5 standard.

public struct FaceBiometricDataEncoding {
    
    /// Version of the biometric data format.
    public private(set) var version: Int?
    
    /// Length of the biometric record.
    public private(set) var lengthOfRecord: Int?
    
    /// Number of biometric images present.
    public private(set) var numberOfImages: Int?
    
    /// Overall length of the record data.
    public private(set) var recordDataLength: Int?
    
    /// Number of facial feature points.
    public private(set) var featurePoints: Int?
    
    /// Gender of the biometric subject.
    public private(set) var gender: Int?
    
    /// Eye color of the subject.
    public private(set) var eyeColor: Int?
    
    /// Hair color of the subject.
    public private(set) var hairColor: Int?
    
    /// Feature characteristics mask.
    public private(set) var featureMask: Int?
    
    /// Detected facial expression.
    public private(set) var expression: Int?
    
    /// Pose angle of the subject.
    public private(set) var poseAngle: Int?
    
    /// Uncertainty of the pose angle.
    public private(set) var poseAngleUncertainty: Int?
    
    /// Type of face image.
    public private(set) var imageType: Int?
    
    /// Image data type.
    public private(set) var imageDataType: Int?
    
    /// Width of the face image.
    public private(set) var imageWidth: Int?
    
    /// Height of the face image.
    public private(set) var imageHeight: Int?
    
    /// Image color space.
    public private(set) var imageColorSpace: Int?
    
    /// Image source type.
    public private(set) var sourceType: Int?
    
    /// Device type used for acquisition.
    public private(set) var deviceType: Int?
    
    /// Quality of the face image.
    public private(set) var quality: Int?
    
    /// Face image data.
    internal private(set) var imageData: [UInt8]?
    
    
    /// Representation of the face image as a UIImage object.
    
    public var image: UIImage? {
        if let imageData = imageData, !imageData.isEmpty {
            return UIImage(data: Data(imageData))
        } else { return nil }
    }
    
    /// Parses data conforming to the ISO/IEC 19794-5 standard and returns a ``FaceBiometricDataEncoding`` structure.
    ///
    /// - Parameter data: Data conforming to ISO/IEC 19794-5.
    ///
    /// - Throws: An error if the data format is invalid or if parsing errors occur.
    ///
    /// - Returns: A ``FaceBiometricDataEncoding`` structure with parsed data.
    
    internal static func parseISO19794_5(data: [UInt8]) throws -> FaceBiometricDataEncoding {
        if data[0] != 0x46 && data[1] != 0x41 && data[2] != 0x43 && data[3] != 0x00 {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        var faceBiometricDataEncoding = FaceBiometricDataEncoding()
        
        var offset = 4
        
        faceBiometricDataEncoding.version = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 4]))
        
        offset += 4
        
        faceBiometricDataEncoding.lengthOfRecord = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 4]))
        
        offset += 4
        
        faceBiometricDataEncoding.numberOfImages = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 2]))
        
        offset += 2
        
        faceBiometricDataEncoding.recordDataLength = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 4]))
        
        offset += 4
        
        faceBiometricDataEncoding.featurePoints = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 2]))
        
        offset += 2
        
        faceBiometricDataEncoding.gender = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 1]))
        
        offset += 1
        
        faceBiometricDataEncoding.eyeColor = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 1]))
        
        offset += 1
        
        faceBiometricDataEncoding.hairColor = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 1]))
        
        offset += 1
        
        faceBiometricDataEncoding.featureMask = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 3]))
        
        offset += 3
        
        faceBiometricDataEncoding.expression = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 2]))
        
        offset += 2
        
        faceBiometricDataEncoding.poseAngle = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 3]))
        
        offset += 3
        
        faceBiometricDataEncoding.poseAngleUncertainty = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 3]))
        
        offset += 3
        
        // Features not handled.
        // The feature block is 8 bytes long.
        
        guard let featurePoints = faceBiometricDataEncoding.featurePoints else {
            throw NFCPassportReaderError.UnexpectedResponseStructure
        }
        
        offset += featurePoints * 8
        
        faceBiometricDataEncoding.imageType = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 1]))
        
        offset += 1
        
        faceBiometricDataEncoding.imageDataType = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 1]))
        
        offset += 1
        
        faceBiometricDataEncoding.imageWidth = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 2]))
        
        offset += 2
        
        faceBiometricDataEncoding.imageHeight = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 2]))
        
        offset += 2
        
        faceBiometricDataEncoding.imageColorSpace = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 1]))
        
        offset += 1
        
        faceBiometricDataEncoding.sourceType = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 1]))
        
        offset += 1
        
        faceBiometricDataEncoding.deviceType = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 2]))
        
        offset += 2
        
        faceBiometricDataEncoding.quality = Int(BytesRepresentationConverter
            .convertToHexNumber(from: data[offset..<offset + 2]))
        
        offset += 2
        
        if data.count < offset + ImageFormat.JPEG2000CodestreamBitmap.header.count {
            throw NFCPassportReaderError.UnknownImageFormat
        }
        
        if [UInt8](data[offset..<offset + ImageFormat.JPEG.header.count]) != ImageFormat.JPEG.header &&
            [UInt8](data[offset..<offset + ImageFormat.JPEG2000Bitmap.header.count]) != ImageFormat.JPEG2000Bitmap.header &&
            [UInt8](data[offset..<offset + ImageFormat.JPEG2000CodestreamBitmap.header.count]) != ImageFormat.JPEG2000CodestreamBitmap.header {
            throw NFCPassportReaderError.UnknownImageFormat
        }
        
        faceBiometricDataEncoding.imageData = [UInt8](data[offset...])
        
        return faceBiometricDataEncoding
    }
    
    /// Enumeration of supported image formats.
    ///
    /// - SeeAlso: ``FaceBiometricDataEncoding``
    
    private enum ImageFormat {
        case JPEG
        case JPEG2000Bitmap
        case JPEG2000CodestreamBitmap
        
        /// Image format header.
        
        internal var header: [UInt8] {
            switch self {
            case .JPEG: [0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46]
            case .JPEG2000Bitmap: [0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a]
            case .JPEG2000CodestreamBitmap: [0xff, 0x4f, 0xff, 0x51]
            }
        }
    }
}
