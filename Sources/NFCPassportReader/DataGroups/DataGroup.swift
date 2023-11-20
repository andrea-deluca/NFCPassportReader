//
//  DataGroup.swift
//  
//
//  Created by Andrea Deluca on 04/09/23.
//

import Foundation

/// `DataGroup` is an abstract class that represents a data group,
/// which is a container for structured data stored in ASN.1 format.
///
/// Within the LDS (Logical Data Structure), logical groupings of related Data Elements
/// have been established. These logical groupings are referred to as Data Groups.
///
/// - Note: This class is extended and the ``decode(_:)`` function is overrided
/// to retrieve needed data for the specific Data Group.
///
/// - SeeAlso: ``COM``, ``DataGroup1``, ``DataGroup2``, ``DataGroup7``, ``DataGroup11``
/// ``DataGroup12``, ``DataGroup14`` and ``SOD``

internal class DataGroup {
    
    /// The identifier of the data group.
    
    internal var identifier: DGTag!
    
    /// The structured data stored in ASN.1 format.
    ///
    /// Data follows the ASN.1 (Abstract Syntax Notation One) notation so data is divided into
    /// the TLV (Tag/Type - Length - Value) format, where:
    /// - Tag/Type identifies the type of encoded data
    /// - Length specifies the length in bytes of the value
    /// - Value is the actual data
    ///
    /// - Note: It contains the whole Data Group data and that is what
    /// the hash for ``PassiveAuthenticationHandler`` is calculated from.
    
    private(set) var data: ASN1Node!
    
    /// Initializes a new instance of a data group.
    ///
    /// - Parameters:
    ///   - data: The ASN.1 encoded data for the data group.
    ///   - identifier: The identifier specifying the type of the data group.
    ///
    /// - Throws: An error if decoding the data group fails.
    
    internal required init (_ data: ASN1Node, identifier: DGTag) throws {
        self.identifier = identifier
        self.data = data
        
        try decode(data)
    }
    
    /// Decodes the data within the data group. Subclasses should override this method to perform specific decoding.
    ///
    /// - Parameter data: The ASN.1 encoded data for the data group.
    ///
    /// - Throws: An error if decoding the data fails.
    
    internal func decode(_ data: ASN1Node) throws { }
}
