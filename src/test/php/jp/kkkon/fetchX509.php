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

