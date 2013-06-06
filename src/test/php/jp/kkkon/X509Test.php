<?php

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
                echo 'extractSignature fail';
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

}//CLASS

?>
