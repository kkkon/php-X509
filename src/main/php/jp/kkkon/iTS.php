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

require_once 'jp/kkkon/X509.php';

function iTSparseNSDic($data)
{
    $dic = base64_decode( $data );
    if ( FALSE === $dic )
    {
        return FALSE;
    }

    $lines = explode( "\n", $dic );
    //var_dump( $lines );
    $count = count($lines);

    $result = array();

    for ( $index = 0; $index < $count; ++$index )
    {
        $ret = preg_match( '#"([A-Za-z-]+)"\s*=\s*"([0-9A-Za-z=/+]*)";#', $lines[$index], $matches );
        if ( $ret )
        {
            //var_dump( $matches );
            $result[$matches[1]] = $matches[2];
        }
    }

    return $result;
}

function iTSdecodeSignature($signature)
{
    $signature_decoded = base64_decode( $signature, TRUE );
    if ( FALSE === $signature_decoded )
    {
        return FALSE;
    }

    $array = array();

    $array['version'] = substr($signature_decoded, 0, 1);
    $array['signature'] = substr($signature_decoded, 1, 128);
    $array['cert_len'] = unpack('N',substr($signature_decoded, 129, 4));
    $array['cert'] = substr($signature_decoded, 133);
    
    return $array;
}

function iTSisPurchaseCert($certdata)
{
    $subject = $certdata['subject'];
    $issuer = $certdata['issuer'];
    $extensions = $certdata['extensions'];
    //var_dump( $certdata['extensions'] );
    if (
        'Apple Inc.' === $subject['O']
        && 'Apple Inc.' === $issuer['O']
        && 'US' === $subject['C']
        && 'US' === $issuer['C']
    )
    {
        if ( isset($extensions['1.2.840.113635.100.6.5.1']) )
        {
            return true;
        }
    }
    
    return false;
}


function iTSverifySignature($receipt_decoded)
{
    $checkResult = true;

    $signature_decoded = iTSdecodeSignature( $receipt_decoded['signature'] );
    $purchase_decoded = base64_decode($receipt_decoded['purchase-info'], TRUE);

    $data = $signature_decoded['version'].$purchase_decoded;
    
    $pem = X509der2pem( $signature_decoded['cert'] );

    {
        $cert = openssl_x509_read( $pem );

        $certdata = openssl_x509_parse( $cert );
        $validCert = iTSisPurchaseCert( $certdata );
        if ( $validCert )
        {
            $keyId= openssl_get_publickey($cert);

            $verifyResult = openssl_verify( $data, $signature_decoded['signature'], $keyId, OPENSSL_ALGO_SHA1 );
            if ( 1 === $verifyResult )
            {
                //echo 'verify: OK' . PHP_EOL;
            }
            else if ( 0 === $verifyResult )
            {
                $checkResult = false;
                //die('verify: NG');
            }
            else
            {
                $checkResult = false;
                //die( openssl_error_string() );
            }
            openssl_free_key( $keyId );
        }
        openssl_x509_free( $cert );
    }

    return $checkResult;
}

?>
