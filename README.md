PHP X.509 certificate (SSL) validate
====================================

Validate X.509 (SSL) certificates, implemented PHP only.

Licensed under [The MIT license](http://www.opensource.org/licenses/mit-license.php).


### Main Purpose

iTune Store Receipt have Certificate(DER).  
But PHP's openssl doesn't support Certificate Path Validation(Certificate Chain).
 
This Library support Certificate Path Validation.

e.g.
> Root CA: /C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple Root CA  
> Intermidiate CA: /C=US/O=Apple Inc./OU=Apple Certification Authority/CN=Apple iTunes Store Certification Authority  
> Leaf CA: /CN=PurchaseReceiptCertificate/OU=Apple iTunes Store/O=Apple Inc./C=US  

But This Library doesn't support full validation.


