# NFCPassportReader

Simplify eMRTD data extraction with NFCPassportReader – a Swift package for reading and decoding electronic travel documents via NFC. 
Access personal details, biometrics, and security elements effortlessly.

> This project is part of a research thesis about interactive experiences through NFC carried out by Andrea Deluca during
master's degree in computer engineering at PoliTO in collaboration with Iriscube Reply.

NFCPassportReader allows you to read ISO/IEC 7816-4 smart cards following the ICAO Doc 9303 specifications. All the travel documents
enabled to be read via NFC have an integrated circuit and the corresponding "Chip Inside" symbol is reported on them.

As ICAO Doc 9303 reports, an host of security mechanisms should be performed. At the moment, the NFCPassportReader package supports 
both BAC and PACE (just with general mapping) protocols to access the IC, Chip Authentication to authenticate the IC and 
Passive Authentication to authenticate data stored in the IC.

> No automated tests have been implemented and the package has been tested on the italian eID (CIE). 
However, I would like to point out that CIE implements DESEDE2 and DH cryptography algorithms. The other variants have been
implemented following the same rules as the previous ones but their correct functioning is not guaranteed.

Please, take note of the following:

 - PACE is supported just with general mapping. PACE integrated mapping and PACE chip authentication mapping are not supported.
 - Validation of the certification path from a Trust Anchor to the Document Signer Certificate used to sign the SOD 
during Passive Authentication is not supported.
 - Active Authentication and Terminal Authentication are not supported.

See more about eMRTD data reading through NFC from the [ICAO Doc 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303).
See more about the package implementation from the source code and see also the [documentation](https://andrea-deluca.github.io/NFCPassportReader/).

## Table of Contents

- [Installation](#installation)
- [Getting Started](#getting-started)
- [Documentation](#documentation)
- [Demo](#demo)
- [Get In Touch](#get-in-touch)
- [Credits](#credits)
- [What's Next](#whats-next)

## Installation

### Swift Package Manager

You can install NFCPassportReader via [Swift Package Manager](https://swift.org/package-manager/) by adding 
the following line to your `Package.swift`:

```swift
import PackageDescription

let package = Package(
    [...]
    dependencies: [
        .package(url: "https://github.com/andrea-deluca/NFCPassportReader.git", from: "0.1.0"),
    ]
)
```

## Getting Started

Once you have installed the package, you can import it and calliing one of the `readPassport(:)` functions available in `NFCPassportReader` class is enaugh
to start an NFC read of the travel document.

You can pass the document number, the date of birth of the holder and the document date of expiry as `String` args and the package
will generate the correct MRZ key for you or you can pass directly the MRZ key. Your app will automatically show the NFC request to read
an enabled document. When reading ends, an `NFCPassportModel` will be returned from the called method and you will be able to read all the extracted info
and the security protcols results.

The extracted info are coded into some structs, such as `TravelDocument` and `MRZ`, `FaceBiometricDataEncoding`, `PersonalDetails` and `DocumentDetails`.
Some shortcuts are also defined, e.g. to read firstname or lastname without moving through `TravelDocument` or `PersonalDetails` models, and the facial image
is also exported as `UIImage` to show it easily.

See also [Demo](#demo) to discover a practical example.

## Documentation

Once you have installed the NFCPassportReader package, a documentation built with DocC is provided for public APIs.

See more about eMRTD data reading through NFC from the [ICAO Doc 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303).
See more about the package implementation from the source code and see also the [internal documentation](https://andrea-deluca.github.io/NFCPassportReader/).

## Demo

A full working demo is provided by [NFCTouchpoint](https://github.com/andrea-deluca/NFC-Touchpoint) iOS application. It has been developed 
as part of the research to study some useful use cases on how NFC may be used within a mobile banking app smartly.

## Get In Touch

I'm curious to know if you appreciate the work done and I would be very happy to hear your opinions or answer your questions. 
For anything you can find me also on [X](https://twitter.com/deeelux_) and [LinkedIn](https://www.linkedin.com/in/andrea-deluca-022b1820b/).

## Credits

I would like to point out that the [OpenSSL Swift Package](https://github.com/krzyzanowskim/OpenSSL) 
developed by [@krzyzanowskim](https://github.com/krzyzanowskim) has been used to carry out some more complex security operations.

In addition, I would like to mention the [NFCPassportReader](https://github.com/AndyQ/NFCPassportReader) repo 
developed by [@AndyQ](https://github.com/AndyQ). I studied it as well as the ICAO Doc 9303 to be able to develop the NFCPassportReader package.

Lastly, I would like to say that the ASN.1 module has been extracted and manipulated as needed 
from [swift-asn1](https://github.com/apple/swift-asn1) developed by [@apple](https://github.com/apple). 

## What's Next

The following are some notes of what should definitely be done:

- [ ] Implement automated tests also providing a functioning guarantee for all cryptographic possibilities that may be used by eMRTD
- [ ] Implement integrated mapping and chip authentication mapping for PACE access mechanism
- [ ] Implement full Passive Autentication
- [ ] Implement Active Authentication, also providing decoding of secured elements such as DG3, and Terminal Authentication, if needed 
- [ ] Implement data decoding for missing data groups
- [ ] Implement `GET RESPONSE` APDU to try to handle extra bytes reading
- [ ] Fully integrate [swift-asn1](https://github.com/apple/swift-asn1) package developed by [@apple](https://github.com/apple)
