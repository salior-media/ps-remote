# Certificates shipped with psr-psn

`comodo-rsa-domain-validation-secure-server-ca.der` is the public intermediate CA
*COMODO RSA Domain Validation Secure Server CA* (DER), issued by *COMODO RSA Certification Authority*,
valid 2014-02-12 to 2029-02-11, SHA-256 `02:AB:57:E4:E6:7A:0C:B4:8D:D2:FF:34:83:0E:8A:C4:0F:44:76:FB:08:CA:6B:E3:F5:CD:84:6F:64:68:40:F0`.
It was downloaded on 2026-11-25 from the address in the push server certificate's Authority Information
Access field, `http://crt.comodoca.com/COMODORSADomainValidationSecureServerCA.crt`.

Sony's push-notification server (`*.np.communication.playstation.net`) sends only its own certificate,
without this intermediate. Browsers and chiaki-ng fetch it through AIA; rustls does not. `push.rs` offers
it to rustls's own verifier beside the server's chain. It is not trusted by itself: rustls still checks it
up to the public root in `webpki-roots`, and checks the signatures, dates and host name, so a wrong or
altered file fails verification just as a missing one does. `tests/push.rs` pins its fingerprint.

**It expires on 2029-02-11.** After that the push connection fails closed (rustls refuses the chain), and
this file needs replacing with the intermediate the server's certificate then names. Like chiaki-ng, and like
rustls by default, nothing checks revocation (CRL or OCSP).
