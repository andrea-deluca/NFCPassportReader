# ``NFCPassportReader``

Simplify eMRTD data extraction with NFCPassportReader – a Swift package for reading and decoding electronic travel documents via NFC. 
Access personal details, biometrics, and security elements effortlessly.

NFCPassportReader allows you to read ISO/IEC 7816-4 smart cards following the ICAO Doc 9303 specifications. All the travel documents
enabled to be read via NFC have an integrated circuit and the corresponding "Chip Inside" symbol is reported on them.

As ICAO Doc 9303 reports, an host of security mechanisms should be performed. At the moment, the NFCPassportReader package supports 
both BAC and PACE (just with general mapping) protocols to access the IC, Chip Authentication to authenticate the IC and 
Passive Authentication to authenticate data stored in the IC.

Please, take note of the following:

 - PACE is supported just with general mapping. PACE integrated mapping and PACE chip authentication mapping are not supported.
 - Validation of the certification path from a Trust Anchor to the Document Signer Certificate used to sign the SOD 
during Passive Authentication is not supported.
 - Active Authentication and Terminal Authentication are not supported.


See more about eMRTD data reading through NFC from the [ICAO Doc 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303).
See more about the package implementation from the source code and see also the [documentation]().
