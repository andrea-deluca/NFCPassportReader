# Getting Started

## Overview

Once you have installed the package, you can import it and calliing one of the `readPassport(:)` functions available in `NFCPassportReader` class is enaugh
to start an NFC read of the travel document.

You can pass the document number, the date of birth of the holder and the document date of expiry as `String` args and the package
will generate the correct MRZ key for you or you can pass directly the MRZ key. Your app will automatically show the NFC request to read
an enabled document. When reading ends, an `NFCPassportModel` will be returned from the called method and you will be able to read all the extracted info
and the security protcols results.

The extracted info are coded into some structs, such as `TravelDocument` and `MRZ`, `FaceBiometricDataEncoding`, `PersonalDetails` and `DocumentDetails`.
Some shortcuts are also defined, e.g. to read firstname or lastname without moving through `TravelDocument` or `PersonalDetails` models, and the facial image
is also exported as `UIImage` to show it easily.

A full working demo is provided by [NFCTouchpoint](https://github.com/andrea-deluca/NFC-Touchpoint) iOS application. It has been developed 
as part of the research to study some useful use cases on how NFC may be used within a mobile banking app smartly.
