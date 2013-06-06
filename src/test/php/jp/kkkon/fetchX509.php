<?php

function fetchX509( $url, $dest_filepath, $isder = false )
{
    $ch = curl_init();
    if (!$ch) {
        die('curl_init fail.');
    }

    $ret = curl_setopt( $ch, CURLOPT_RETURNTRANSFER, TRUE );
    if ( FALSE === $ret )
    {
        die( curl_error( $ch ) );
        curl_close( $ch );
        $ch = null;
    }
    $ret = curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, TRUE );
    $ret = curl_setopt( $ch, CURLOPT_CAINFO, CACERT_FILEPATH );

    //$ret = curl_setopt( $ch, CURLOPT_VERBOSE, TRUE );
    $ret = curl_setopt( $ch, CURLOPT_URL, $url );
    
    $ret = curl_exec( $ch );
    if ( FALSE === $ret )
    {
        die( curl_error( $ch ) );
        curl_close( $ch );
        $ch = null;
    }
    else
    {
        $info = curl_getinfo( $ch );
        //var_dump( $info );

        if ( 200 === (int)$info['http_code'] )
        {
            $handle = fopen( $dest_filepath, 'wb' );
            if ( $handle )
            {
                if ( $isder )
                {
                    fwrite( $handle, '-----BEGIN CERTIFICATE-----' . "\n" );
                    $certpem = chunk_split(base64_encode($ret), 64, "\n");
                    fwrite( $handle, $certpem );
                    fwrite( $handle, '-----END CERTIFICATE-----' . "\n" );
                }
                else
                {
                    fwrite( $handle, $ret );
                }
                fflush( $handle );
                fclose( $handle );
                $handle = NULL;
            }
        }
        else
        {
            die( 'HTTP code=' . $info['http_code'] );
        }

        curl_close( $ch );
        
    }
}

?>

