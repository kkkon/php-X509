<?php

//http://curl.haxx.se/docs/caextract.html
define( 'CACERT_URL', 'http://curl.haxx.se/ca/cacert.pem' );
define( 'CACERT_FILEPATH', dirname(__FILE__) . '/cert/cacert.pem' );



// http://www.apple.com/certificateauthority/
// https://www.apple.com/appleca/AppleIncRootCertificate.cer
define( 'APPLE_CACERT_URL', 'https://www.apple.com/appleca/AppleIncRootCertificate.cer' );
define( 'APPLE_CACERT_FILEPATH', dirname(__FILE__) . '/cert/AppleIncRootCertificate.pem' );


define( 'ITS_INTERMEDIATE_FILEPATH', dirname(__FILE__) . '/cert/itunes_intermediate.pem');

?>

