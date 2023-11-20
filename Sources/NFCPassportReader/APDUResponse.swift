//
//  APDUResponse.swift
//  
//
//  Created by Andrea Deluca on 07/09/23.
//

import Foundation

/// Represents the response from an APDU (Application Protocol Data Unit) command.

internal struct APDUResponse {
    
    /// The data received as a response to the command.
    
    private(set) var data: [UInt8]
    
    /// The first status byte (SW1) of the response.
    
    private(set) var sw1: UInt8
    
    /// The second status byte (SW2) of the response.
    
    private(set) var sw2: UInt8
    
    /// Indicates whether the response is a success based on
    /// SW1 and SW2 values (0x90, 0x00).
    
    internal var isSuccess: Bool { [sw1, sw2] == [0x90, 0x00] }
    
    /// Indicates whether the response represents an error.
    
    internal var isError: Bool { !self.isSuccess }
    
    /// If the response is an error, provides details about the error.

    internal var error: APDUResponseError? {
        if self.isError {
            return APDUResponseErrorDecoder.decode(response: self)
        } else { return nil }
    }
    
    /// Discards the response, useful in cases where you don't need
    /// to process the response further.

    internal func discardResponse() {}
}
