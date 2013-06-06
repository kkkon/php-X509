<?php
/*
 * The MIT License
 * 
 * Copyright (C) 2013 Kiyofumi Kondoh
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

//http://curl.haxx.se/docs/caextract.html
define( 'CACERT_URL', 'http://curl.haxx.se/ca/cacert.pem' );
define( 'CACERT_FILEPATH', dirname(__FILE__) . '/cert/cacert.pem' );



// http://www.apple.com/certificateauthority/
// https://www.apple.com/appleca/AppleIncRootCertificate.cer
define( 'APPLE_CACERT_URL', 'https://www.apple.com/appleca/AppleIncRootCertificate.cer' );
define( 'APPLE_CACERT_FILEPATH', dirname(__FILE__) . '/cert/AppleIncRootCertificate.pem' );


define( 'ITS_INTERMEDIATE_FILEPATH', dirname(__FILE__) . '/cert/itunes_intermediate.pem');

define( 'ITS_PURCHASERECEIPT_FILEPATH', dirname(__FILE__) . '/cert/itunes_PurchaseReceiptCertificate.pem');

?>

