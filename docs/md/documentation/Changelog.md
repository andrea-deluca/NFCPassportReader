# 0.1.1

*Released: 2023/12/01*

**What's changed:**

This patch resolves some problems detected during demo development and testing. In particular,
a bug has been found during Subject Public Key parsing: the first public key byte was removed and therefore 
parsed key was invalid. Moreover, a bug that was causing a fatal error during PassiveAuthentication has been fixed.

In addition, more info are now exported from the NFCPassportModel, such as security protocols, 
data groups available and read, hashes and X509 certificate details stored within the SOD. 

**Other:**

- Exported dates are now formatted
- Fixed exported name and surname that they were exchanged
- Filler chars removed from exported strings
- Fixed MRZ properties that are now public and exported

# 0.1.0

*Released: 2023/11/20*

**What's changed:**

The first version of the package includes IC access, IC authentication and IC data authentication mechanisms,
data decoding for some groups and public interfaces to read eMRTD smartly.

> No automated tests have been implemented and the package has been tested on the italian eID (CIE). 
However, I would like to point out that CIE implements DESEDE2 and DH cryptography algorithms. The other variants have been
implemented following the same rules as the previous ones but their correct functioning is not guaranteed.

- Security mechanisms implemented:
   - CardAccess group reading has been implemented
   - BAC and PACE (with general mapping) to access the IC have been implemented
   - Chip Authentication mechanism has been implemented
   - SOD group reading has been implemented
   - Passive Authentication (without validation of the certification path from a 
   Trust Anchor to the Document Signer Certificate used to sign the SOD) to authenticate data groups has been implemented
- COM, DG1, DG2, DG7, DG11, DG12 and DG14 decoding have been implemented
 
**Public APIs:**
- NFCPassportReader class allows you to read eMRTD passing the mrz key or info to generate it 
(document number, date of birth of the document holder and doucment date of expiry) as args
- NFCPassportModel is returned as reading result and it contains extracted info
- Holder facial image is returned also as UIImage to easily show it on your iOS application 

**Other:**

- ASN.1 utils have been implemented
- Security utils, such as encryption algorithms, hash algorithms and key agreement algorithms, have been implemented
- DocC for public APIs has been generated
- Full implementation doc, containing also code protected as internal level, has been generated with jazzy
