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


/**
 * 
 * @param string $pem
 * @return binary
 */
function X509pem2der($pem)
{
    $cert_split = preg_split('/(-----((BEGIN)|(END)) CERTIFICATE-----)/', $pem );
    $der = base64_decode( $cert_split[1] );
    
    return $der;
}

/**
 * 
 * @param binary $der
 * @return string
 */
function X509der2pem($der)
{
    $pem = chunk_split(base64_encode($der), 64, "\n");
    $pem = '-----BEGIN CERTIFICATE-----' . "\n" . $pem . '-----END CERTIFICATE-----' . "\n";
    
    return $pem;
}

function X509checkSignature( $decodedCert, $certPEM )
{
    $checkResult = false;

    $certRaw = $decodedCert['cert'];
    $signatureOID = $decodedCert['sigOID'];
    $encryptedSignature = $decodedCert['signature'];
    
    $decrypted = null;
    {
        $cert = openssl_x509_read( $certPEM );
        $keyId = openssl_get_publickey( $cert );
        $ret = openssl_public_decrypt($encryptedSignature, $decrypted, $keyId );
        if ( FALSE === $ret )
        {
            error_log( openssl_error_string() );
            $checkResult = false;
        }
        openssl_free_key( $keyId );
        openssl_x509_free($cert);
        //echo 'PEM signature decrypted' . var_export( unpack('H*', $decrypted), true ) . PHP_EOL;
    }
    if ( null == $decrypted )
    {
        return false;
    }
    
    {
        $decodedSignature = null;
        {
            $ret = X509extractSignatureValue($decrypted);
            if ( FALSE === $ret )
            {
                //echo 'signature value parse fail' . PHP_EOL;
                return false;
            }
            else
            {
                $decodedSignature = $ret;
                //echo 'PEM signature OID' . var_export( $ret['sigOID'], true ) . PHP_EOL;
                //echo 'PEM signature' . var_export( unpack('H*', $ret['signature']), true ) . PHP_EOL;
            }
        }

        $algo = null;
        $algo = getHashAlgorithmFromOID( $decodedSignature['sigOID'] );
        switch( $algo )
        {
        case 'md2':
        case 'md4':
        case 'md5':
            error_log( 'hash algorithm not allow' . PHP_EOL );
            $algo = null;
            break;
        default:
            // nothing
            break;
        }

        if ( null == $algo )
        {
            return false;
        }

        $verifyResult = FALSE;
        {
            $calced_hash = hash($algo, $certRaw, true );
            //echo 'calced_hash: ' . var_export( unpack('H*',$calced_hash), TRUE ) . PHP_EOL;
            if ( $calced_hash === $decodedSignature['signature'] )
            {
                $verifyResult = TRUE;
            }
        }
        if ( TRUE === $verifyResult )
        {
            $checkResult = true;
            //echo 'verify: OK' . PHP_EOL;
        }
        else
        {
            $checkResult = false;
            error_log('verify: NG' . __FILE__ . __LINE__ );
        }
    }

    return $checkResult;
}

function X509certPathValidate( $certLeafPEM=null, $certAnchorPEM=null, $certRootPEM=null )
{
    $result = true;

    $certLeaf = null;
    if ( null != $certLeafPEM )
    {
        $certLeafDER = X509pem2der($certLeafPEM);
        //echo 'certLeafDER' . var_export( unpack('H*', $certLeafDER ), true ) . PHP_EOL;
        $ret = X509extractSignature($certLeafDER);
        if ( FALSE === $ret )
        {
            //echo 'X509extractSignature fail' . __FILE__ . __LINE__ . PHP_EOL;
            return false;
        }
        else
        {
            $certLeaf = $ret;
            //echo 'LEAF_PEM cert(DER)' . var_export( unpack('H*', $ret['cert']), true ) . PHP_EOL;
            //echo 'LEAF_PEM signature OID' . var_export( $ret['sigOID'], true ) . PHP_EOL;
            //echo 'LEAF_PEM signature(encrypted)' . var_export( unpack('H*', $ret['signature']), true ) . PHP_EOL;
        }
    }
    
    $certAnchor = null;
    if ( null != $certAnchorPEM )
    {
        $certAnchorDER = X509pem2der($certAnchorPEM);
        //echo 'certAnchorDER' . var_export( unpack('H*', $certAnchorDER ), true ) . PHP_EOL;
        $ret = X509extractSignature($certAnchorDER);
        if ( FALSE === $ret )
        {
            //echo 'X509extractSignature fail' . __FILE__ . __LINE__ . PHP_EOL;
            return false;
        }
        else
        {
            $certAnchor = $ret;
            //echo 'ANCHOR_PEM cert(DER)' . var_export( unpack('H*', $ret['cert']), true ) . PHP_EOL;
            //echo 'ANCHOR_PEM signature OID' . var_export( $ret['sigOID'], true ) . PHP_EOL;
            //echo 'ANCHOR_PEM signature(encrypted)' . var_export( unpack('H*', $ret['signature']), true ) . PHP_EOL;
        }
    }

    $certRoot = null;
    if ( null != $certRootPEM )
    {
        $certRootDER = X509pem2der($certRootPEM);
        //echo 'certRootDER' . var_export( unpack('H*', $certRootDER ), true ) . PHP_EOL;
        $ret = X509extractSignature($certRootDER);
        if ( FALSE === $ret )
        {
            //echo 'X509extractSignature fail' . __FILE__ . __LINE__ . PHP_EOL;
            return false;
        }
        else
        {
            $certRoot = $ret;
            //echo 'ROOT_PEM cert(DER)' . var_export( unpack('H*', $ret['cert']), true ) . PHP_EOL;
            //echo 'ROOT_PEM signature OID' . var_export( $ret['sigOID'], true ) . PHP_EOL;
            //echo 'ROOT_PEM signature(encrypted)' . var_export( unpack('H*', $ret['signature']), true ) . PHP_EOL;
        }
    }

    if ( null != $certLeaf && null != $certAnchor )
    {
        $ret = X509checkSignature( $certLeaf, $certAnchorPEM );
        if ( false === $ret )
        {
            $result = false;
        }
    }

    if ( null != $certAnchor && null != $certRoot )
    {
        $ret = X509checkSignature( $certAnchor, $certRootPEM );
        if ( false === $ret )
        {
            $result = false;
        }
    }

    if ( null == $certAnchor && null == $certRoot )
    {
        $result = false;
    }

    return $result;
}

function getHashAlgorithmFromOID($oid)
{
    $algo = null;

    switch( $oid )
    {
    case '1.2.840.113549.2.2':
        $algo = 'md2';
        break;
    case '1.2.840.113549.2.4':
        $algo = 'md4';
        break;
    case '1.2.840.113549.2.5':
        $algo = 'md5';
        break;

    case '1.3.14.3.2.18':
        $algo = 'sha';
        break;
    case '1.3.14.3.2.26':
        $algo = 'sha1';
        break;

    case '2.16.840.1.101.3.4.2.1':
        $algo = 'sha256';
        break;
    case '2.16.840.1.101.3.4.2.2':
        $algo = 'sha384';
        break;
    case '2.16.840.1.101.3.4.2.3':
        $algo = 'sha512';
        break;
    default:
        error_log( 'unknown hash OID:' . $oid . __FILE__ . __LINE__ . PHP_EOL );
        break;
    }
    
    return $algo;
}

function X509extractSignature($der)
{
    $result = array();

    /*
     * Class: 00 Univaersal
     * P/C: 1 Constructed
     * TagNum: 16 SEQUENCE
     * 00 1 10000 = 0x30
     */
    if ( 0x30 !== ord($der[0]) )
    {
        return FALSE;
    }

    $certLen = 0;
    $index = 0;
    {
        $c = ord($der[1]);
        if ( $c & 0x80 )
        {
            $bytes = $c & 0x7F;
            if ( 0 == $bytes )
            {
                // not implement variable length
                return FALSE;
            }
            $certLen = 0;
            for ( $i = 0; $i < $bytes; ++$i )
            {
                $certLen = ($certLen << 8);
                $certLen += ord($der[2+$i]) & 0xFF;
            }
            $index = 2 + $bytes;
        }
        else
        {
            // too small
            return FALSE;
        }
    }

    //echo 'tbsCertificate:' . $index . var_export( unpack('H*', substr($der, $index) ), true ) . PHP_EOL;
    if ( 0x30 !== ord($der[$index]) )
    {
        return FALSE;
    }
    {
        $c = ord($der[$index+1]);
        if ( $c & 0x80 )
        {
            $bytes = $c & 0x7F;
            if ( 0 == $bytes )
            {
                // not implement variable length
                return FALSE;
            }
            $certLen = 0;
            for ( $i = 0; $i < $bytes; ++$i )
            {
                $certLen = ($certLen << 8);
                $certLen += ord($der[$index+2+$i]) & 0xFF;
            }

            //$result['cert'] = substr( $der, $index + 2 + $bytes, $certLen );
            $result['cert'] = substr( $der, $index, $certLen + 2 + $bytes );
            $index += (2 + $bytes + $certLen);
        }
        else
        {
            // too small
            return FALSE;
        }
    }

    //echo 'signatureAlgorithm:' . $index . var_export( unpack('H*', substr($der, $index) ), true ) . PHP_EOL;
    if ( 0x30 !== ord($der[$index]) )
    {
        return FALSE;
    }
    {
        $indexOID = 0;
        $c = ord($der[$index+1]);
        if ( $c & 0x80 )
        {
            $bytes = $c & 0x7F;
            if ( 0 == $bytes )
            {
                // not implement variable length
                return FALSE;
            }
            $sigAlgoLen = 0;
            for ( $i = 0; $i < $bytes; ++$i )
            {
                $sigAlgoLen = ($sigAlgoLen << 8);
                $sigAlgoLen += ord($der[$index+2+$i]) & 0xFF;
            }

            $indexOID = $index + 2 + $bytes;
            $index += (2 + $bytes + $sigAlgoLen);
        }
        else
        {
            $indexOID = $index + 2;
            $index += (2 + ($c & 0x7F));
        }

        if ( 0 < $indexOID )
        {
            //echo ' signatureAlgoOID:' . $indexOID . var_export( unpack('H*', substr($der, $indexOID) ), true ) . PHP_EOL;
            if ( 0x06 == ord($der[$indexOID]) )
            {
                $oidLen = 0;

                $c = ord($der[$indexOID+1]);
                if ( $c & 0x80 )
                {
                    $bytes = $c & 0x7F;
                    if ( 0 == $bytes )
                    {
                        // not implement variable length
                        return FALSE;
                    }
                    for ( $i = 0; $i < $bytes; ++$i )
                    {
                        $oidLen = ($oidLen << 8);
                        $oidLen += ord($der[$indexOID+2+$i]) & 0xFF;
                    }

                    $indexOID = $indexOID + 2 + $bytes;
                }
                else
                {
                    $oidLen = $c;
                    $indexOID = $indexOID + 2;
                }

                //echo ' signatureAlgoOID:' . $indexOID . var_export( unpack('H*', substr($der, $indexOID, $oidLen) ), true ) . PHP_EOL;
                
                $xy = ord($der[$indexOID]);
                $sigAlgoOID = floor( $xy / 40 );
                $sigAlgoOID .= '.';
                $sigAlgoOID .= $xy % 40;
                {
                    $value = 0;
                    for ( $i = 1; $i < $oidLen; ++$i )
                    {
                        $c = ord($der[$indexOID+$i]);
                        $value = $value << 7;
                        $value |= ($c & 0x7F);
                        if ( !($c & 0x80) )
                        {
                            $sigAlgoOID .= '.' . $value;
                            $value = 0;
                        }
                    }
                }
                //echo ' signatureAlgoOID:' . $indexOID . var_export( $sigAlgoOID, true ) . PHP_EOL;
                $result['sigOID'] = $sigAlgoOID;
            }
        }
    }

    //echo 'signatureValue:' . $index . var_export( unpack('H*', substr($der, $index) ), true ) . PHP_EOL;
    /*
     * Class: 00 Univaersal
     * P/C: 0 Primitive
     * TagNum: 3 BIT STRING
     * 00 0 00011 = 0x03
     */
    if ( 0x03 !== ord($der[$index]) )
    {
        return FALSE;
    }
    {
        $c = ord($der[$index+1]);
        if ( $c & 0x80 )
        {
            $bytes = $c & 0x7F;
            if ( 0 == $bytes )
            {
                // not implement variable length
                return FALSE;
            }
            $sigLen = 0;
            for ( $i = 0; $i < $bytes; ++$i )
            {
                $sigLen = ($sigLen << 8);
                $sigLen += ord($der[$index+2+$i]) & 0xFF;
            }

            $result['signature'] = substr( $der, $index + 2 + $bytes+1, $sigLen );
            $index += (2 + $bytes + $certLen);
        }
        else
        {
            // too small
            return FALSE;
        }
    }
    

    return $result;
}

function X509extractSignatureValue($der)
{
    $result = array();

    /*
     * Class: 00 Univaersal
     * P/C: 1 Constructed
     * TagNum: 16 SEQUENCE
     * 00 1 10000 = 0x30
     */
    if ( 0x30 !== ord($der[0]) )
    {
        return FALSE;
    }

    $signatureLen = 0;
    $index = 0;
    {
        $c = ord($der[1]);
        if ( $c & 0x80 )
        {
            $bytes = $c & 0x7F;
            if ( 0 == $bytes )
            {
                // not implement variable length
                return FALSE;
            }
            $signatureLen = 0;
            for ( $i = 0; $i < $bytes; ++$i )
            {
                $signatureLen = ($signatureLen << 8);
                $signatureLen += ord($der[2+$i]) & 0xFF;
            }
            $index = 2 + $bytes;
        }
        else
        {
            $signatureLen = $c & 0x7F;
            $index = 2;
        }
    }

    //echo 'sig:' . $index . var_export( unpack('H*', substr($der, $index) ), true ) . PHP_EOL;
    if ( 0x30 !== ord($der[$index]) )
    {
        return FALSE;
    }
    {
        $indexOID = 0;
        $c = ord($der[$index+1]);
        if ( $c & 0x80 )
        {
            $bytes = $c & 0x7F;
            if ( 0 == $bytes )
            {
                // not implement variable length
                return FALSE;
            }
            $sigAlgoLen = 0;
            for ( $i = 0; $i < $bytes; ++$i )
            {
                $sigAlgoLen = ($sigAlgoLen << 8);
                $sigAlgoLen += ord($der[$index+2+$i]) & 0xFF;
            }

            $indexOID = $index + 2 + $bytes;
            $index += (2 + $bytes + $sigAlgoLen);
        }
        else
        {
            $indexOID = $index + 2;
            $index += (2 + ($c & 0x7F));
        }

        if ( 0 < $indexOID )
        {
            //echo ' signatureAlgoOID:' . $indexOID . var_export( unpack('H*', substr($der, $indexOID) ), true ) . PHP_EOL;
            if ( 0x06 == ord($der[$indexOID]) )
            {
                $oidLen = 0;

                $c = ord($der[$indexOID+1]);
                if ( $c & 0x80 )
                {
                    $bytes = $c & 0x7F;
                    if ( 0 == $bytes )
                    {
                        // not implement variable length
                        return FALSE;
                    }
                    for ( $i = 0; $i < $bytes; ++$i )
                    {
                        $oidLen = ($oidLen << 8);
                        $oidLen += ord($der[$indexOID+2+$i]) & 0xFF;
                    }

                    $indexOID = $indexOID + 2 + $bytes;
                }
                else
                {
                    $oidLen = $c;
                    $indexOID = $indexOID + 2;
                }

                //echo ' signatureAlgoOID:' . $indexOID . var_export( unpack('H*', substr($der, $indexOID, $oidLen) ), true ) . PHP_EOL;
                
                $xy = ord($der[$indexOID]);
                $sigAlgoOID = floor( $xy / 40 );
                $sigAlgoOID .= '.';
                $sigAlgoOID .= $xy % 40;
                {
                    $value = 0;
                    for ( $i = 1; $i < $oidLen; ++$i )
                    {
                        $c = ord($der[$indexOID+$i]);
                        $value = $value << 7;
                        $value |= ($c & 0x7F);
                        if ( !($c & 0x80) )
                        {
                            $sigAlgoOID .= '.' . $value;
                            $value = 0;
                        }
                    }
                }
                //echo ' signatureAlgoOID:' . $indexOID . var_export( $sigAlgoOID, true ) . PHP_EOL;
                $result['sigOID'] = $sigAlgoOID;
            }
        }
    }

    //echo 'signatureValue:' . $index . var_export( unpack('H*', substr($der, $index) ), true ) . PHP_EOL;
    /*
     * Class: 00 Univaersal
     * P/C: 0 Primitive
     * TagNum: 4 OCTET STRING
     * 00 0 00011 = 0x04
     */
    if ( 0x04 !== ord($der[$index]) )
    {
        return FALSE;
    }
    {
        $c = ord($der[$index+1]);
        if ( $c & 0x80 )
        {
            $bytes = $c & 0x7F;
            if ( 0 == $bytes )
            {
                // not implement variable length
                return FALSE;
            }
            $sigLen = 0;
            for ( $i = 0; $i < $bytes; ++$i )
            {
                $sigLen = ($sigLen << 8);
                $sigLen += ord($der[$index+2+$i]) & 0xFF;
            }

            $result['signature'] = substr( $der, $index + 2 + $bytes+1, $sigLen );
            $index += (2 + $bytes + $sigLen);
        }
        else
        {
            $sigLen = $c & 0x7F;
            $result['signature'] = substr( $der, $index + 2, $sigLen );
            $index += 2 + $sigLen;
        }
    }
    

    return $result;
}

?>
