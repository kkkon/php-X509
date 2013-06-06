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

require_once 'jp/kkkon/constants.php';
require_once 'jp/kkkon/fetchX509.php';
require_once 'jp/kkkon/convert_iTSPEM.php';

class X509Test extends PHPUnit_Framework_TestCase
{

    public static function setUpBeforeClass()
    {
        fetchX509( CACERT_URL, CACERT_FILEPATH );
        fetchX509( APPLE_CACERT_URL, APPLE_CACERT_FILEPATH, TRUE );
        convertITS_Intermediate( ITS_INTERMEDIATE_FILEPATH );
    }
    
    public static function tearDownAfterClass()
    {
        
    }


    public function testX509checkSignature()
    {
        $intermediateRaw = null;
        {
            $pem = file_get_contents( ITS_INTERMEDIATE_FILEPATH );
            $der = X509pem2der($pem);
            echo 'ITS_INTERMEDIATE(DER)' . var_export( unpack('H*', $der ), true ) . PHP_EOL;
            $ret = X509extractSignature($der);
            if ( FALSE === $ret )
            {
                echo 'X509extractSignature fail';
                return;
            }
            else
            {
                $intermediateRaw = $ret;
                echo 'ITS_INTERMEDIATE cert(DER)' . var_export( unpack('H*', $ret['cert']), true ) . PHP_EOL;
                echo 'ITS_INTERMEDIATE signature OID' . var_export( $ret['sigOID'], true ) . PHP_EOL;
                echo 'ITS_INTERMEDIATE signature' . var_export( unpack('H*', $ret['signature']), true ) . PHP_EOL;
            }
        }
        {
            $certpem = file_get_contents( APPLE_CACERT_FILEPATH );
            $checkResult = X509checkSignature( $intermediateRaw, $certpem );
            $this->assertTrue( $checkResult );
        }
    }

    public function testX509certPathValidate()
    {
        $certAnchor = file_get_contents( ITS_INTERMEDIATE_FILEPATH );
        $certRoot = file_get_contents( APPLE_CACERT_FILEPATH );
        $checkResult = X509certPathValidate( null, $certAnchor, $certRoot );
        $this->assertTrue( $checkResult );
    }
    
}//CLASS

?>
