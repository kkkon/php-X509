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

function convertITS_Intermediate($dest_filepath)
{

// VerificationController.m
// unsigned char iTS_intermediate_der[]
$itunes_intermediate_array = array(
    0x30, 0x82, 0x04, 0x0b, 0x30, 0x82, 0x02, 0xf3, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x01, 0x1a, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x62, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0a, 0x41, 0x70, 0x70,
    0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x26, 0x30, 0x24, 0x06,
    0x03, 0x55, 0x04, 0x0b, 0x13, 0x1d, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20,
    0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x31,
    0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0d, 0x41, 0x70,
    0x70, 0x6c, 0x65, 0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x30,
    0x1e, 0x17, 0x0d, 0x30, 0x39, 0x30, 0x35, 0x31, 0x39, 0x31, 0x38, 0x33,
    0x31, 0x33, 0x30, 0x5a, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x35, 0x31, 0x38,
    0x31, 0x38, 0x33, 0x31, 0x33, 0x30, 0x5a, 0x30, 0x7f, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13,
    0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0a, 0x41, 0x70, 0x70,
    0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x26, 0x30, 0x24, 0x06,
    0x03, 0x55, 0x04, 0x0b, 0x0c, 0x1d, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x20,
    0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x31,
    0x33, 0x30, 0x31, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x2a, 0x41, 0x70,
    0x70, 0x6c, 0x65, 0x20, 0x69, 0x54, 0x75, 0x6e, 0x65, 0x73, 0x20, 0x53,
    0x74, 0x6f, 0x72, 0x65, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
    0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f,
    0x72, 0x69, 0x74, 0x79, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
    0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xa4, 0xbc, 0xaf, 0x32, 0x94, 0x43, 0x3e, 0x0b, 0xbc, 0x37, 0x87,
    0xcd, 0x63, 0x89, 0xf2, 0xcc, 0xd9, 0xbe, 0x20, 0x4d, 0x5a, 0xb4, 0xfe,
    0x87, 0x67, 0xd2, 0x9a, 0xde, 0x1a, 0x54, 0x9d, 0xa2, 0xf3, 0xdf, 0x87,
    0xe4, 0x4c, 0xcb, 0x93, 0x11, 0x78, 0xa0, 0x30, 0x8f, 0x34, 0x41, 0xc1,
    0xd3, 0xbe, 0x66, 0x6d, 0x47, 0x6c, 0x98, 0xb8, 0xec, 0x7a, 0xd5, 0xc9,
    0xdd, 0xa5, 0xe4, 0xea, 0xc6, 0x70, 0xf4, 0x35, 0xd0, 0x91, 0xf7, 0xb3,
    0xd8, 0x0a, 0x11, 0x99, 0xab, 0x3a, 0x62, 0x3a, 0xbd, 0x7b, 0xf4, 0x56,
    0x4f, 0xdb, 0x9f, 0x24, 0x93, 0x51, 0x50, 0x7c, 0x20, 0xd5, 0x66, 0x4d,
    0x66, 0xf3, 0x18, 0xa4, 0x13, 0x96, 0x22, 0x16, 0xfd, 0x31, 0xa7, 0xf4,
    0x39, 0x66, 0x9b, 0xfb, 0x62, 0x69, 0x5c, 0x4b, 0x9f, 0x94, 0xa8, 0x4b,
    0xe8, 0xec, 0x5b, 0x64, 0x5a, 0x18, 0x79, 0x8a, 0x16, 0x75, 0x63, 0x42,
    0xa4, 0x49, 0xd9, 0x8c, 0x33, 0xde, 0xad, 0x7b, 0xd6, 0x39, 0x04, 0xf4,
    0xe2, 0x9d, 0x0a, 0x69, 0x8c, 0xeb, 0x4b, 0x12, 0x28, 0x4b, 0x34, 0x48,
    0x07, 0x9b, 0x0e, 0x59, 0xf9, 0x1f, 0x62, 0xb0, 0x03, 0x9f, 0x36, 0xb8,
    0x4e, 0xa3, 0xd3, 0x75, 0x59, 0xd4, 0xf3, 0x3a, 0x05, 0xca, 0xc5, 0x33,
    0x3b, 0xf8, 0xc0, 0x06, 0x09, 0x08, 0x93, 0xdb, 0xe7, 0x4d, 0xbf, 0x11,
    0xf3, 0x52, 0x2c, 0xa5, 0x16, 0x35, 0x15, 0xf3, 0x41, 0x02, 0xcd, 0x02,
    0xd1, 0xfc, 0xf5, 0xf8, 0xc5, 0x84, 0xbd, 0x63, 0x6a, 0x86, 0xd6, 0xb6,
    0x99, 0xf6, 0x86, 0xae, 0x5f, 0xfd, 0x03, 0xd4, 0x28, 0x8a, 0x5a, 0x5d,
    0xaf, 0xbc, 0x65, 0x74, 0xd1, 0xf7, 0x1a, 0xc3, 0x92, 0x08, 0xf4, 0x1c,
    0xad, 0x69, 0xe8, 0x02, 0x4c, 0x0e, 0x95, 0x15, 0x07, 0xbc, 0xbe, 0x6a,
    0x6f, 0xc1, 0xb3, 0xad, 0xa1, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x81,
    0xae, 0x30, 0x81, 0xab, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
    0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
    0xff, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14,
    0x36, 0x1d, 0xe8, 0xe2, 0x9d, 0x82, 0xd2, 0x01, 0x18, 0xb5, 0x32, 0x6b,
    0x0e, 0xd7, 0x43, 0x0b, 0x91, 0x58, 0x43, 0x3a, 0x30, 0x1f, 0x06, 0x03,
    0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x2b, 0xd0, 0x69,
    0x47, 0x94, 0x76, 0x09, 0xfe, 0xf4, 0x6b, 0x8d, 0x2e, 0x40, 0xa6, 0xf7,
    0x47, 0x4d, 0x7f, 0x08, 0x5e, 0x30, 0x36, 0x06, 0x03, 0x55, 0x1d, 0x1f,
    0x04, 0x2f, 0x30, 0x2d, 0x30, 0x2b, 0xa0, 0x29, 0xa0, 0x27, 0x86, 0x25,
    0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x61,
    0x70, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x70, 0x70,
    0x6c, 0x65, 0x63, 0x61, 0x2f, 0x72, 0x6f, 0x6f, 0x74, 0x2e, 0x63, 0x72,
    0x6c, 0x30, 0x10, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64,
    0x06, 0x02, 0x02, 0x04, 0x02, 0x05, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x82,
    0x01, 0x01, 0x00, 0x75, 0xa6, 0x90, 0xe6, 0x9a, 0xa7, 0xdb, 0x65, 0x70,
    0xa6, 0x09, 0x93, 0x6f, 0x08, 0xdf, 0x2c, 0xdb, 0xe9, 0x28, 0x8d, 0x40,
    0x1b, 0x57, 0x5e, 0xa0, 0xea, 0xf4, 0xec, 0x13, 0x65, 0x1b, 0x71, 0x4a,
    0x4d, 0xdc, 0x80, 0x48, 0x4f, 0xf2, 0xe5, 0xa9, 0xfb, 0x85, 0x6c, 0xb7,
    0x1e, 0x9d, 0xdb, 0xf4, 0x18, 0x48, 0x10, 0x79, 0x17, 0xea, 0xc3, 0x3d,
    0x87, 0xd8, 0xb4, 0x79, 0x6d, 0x14, 0x50, 0xad, 0xd2, 0xbf, 0x3d, 0x4e,
    0xfc, 0x0d, 0xe2, 0xc5, 0x03, 0x94, 0x75, 0x80, 0x73, 0x4d, 0xa5, 0xa1,
    0x91, 0xfe, 0x1c, 0xde, 0x15, 0x17, 0xac, 0x89, 0x71, 0x2a, 0x6f, 0x0f,
    0x67, 0x0a, 0xd3, 0x9c, 0x30, 0xa1, 0x68, 0xfb, 0xcf, 0x70, 0x17, 0xca,
    0xd9, 0x40, 0xfc, 0xf8, 0x1b, 0xbf, 0xce, 0xb0, 0xc4, 0xae, 0xf4, 0x4a,
    0x2d, 0xa9, 0x99, 0x87, 0x06, 0x42, 0x09, 0x86, 0x22, 0x6a, 0x84, 0x40,
    0x39, 0xf4, 0xbb, 0xac, 0x56, 0x18, 0xf7, 0x9a, 0x1c, 0x01, 0x81, 0x5c,
    0x8c, 0x6e, 0x41, 0xf2, 0x5d, 0x19, 0x2c, 0x17, 0x1c, 0x49, 0x46, 0xd9,
    0x1c, 0x7e, 0x93, 0x12, 0x13, 0xc8, 0x67, 0x99, 0xc2, 0xea, 0x83, 0xe3,
    0xa2, 0x8c, 0x0e, 0xb8, 0x3b, 0x2a, 0xdf, 0x1c, 0xbf, 0x4b, 0x8b, 0x6f,
    0x1a, 0xb8, 0xee, 0x97, 0x67, 0x4a, 0xd8, 0xab, 0xaf, 0x8b, 0xa4, 0xda,
    0x5c, 0x87, 0x1e, 0x20, 0xb8, 0xc5, 0xf3, 0xb1, 0xc4, 0x98, 0xa2, 0x37,
    0xf8, 0x9e, 0xc6, 0x9a, 0x6b, 0xa5, 0xad, 0xf6, 0x78, 0x96, 0x0e, 0x82,
    0x8f, 0x04, 0x46, 0x1c, 0xb2, 0xa5, 0xfd, 0x9a, 0x30, 0x51, 0x28, 0xfd,
    0x52, 0x04, 0x15, 0x03, 0xd5, 0x3c, 0xad, 0xfe, 0xf6, 0x78, 0xe0, 0xea,
    0x35, 0xef, 0x65, 0xb5, 0x21, 0x76, 0xdb, 0xa4, 0xef, 0xcb, 0x72, 0xef,
    0x54, 0x6b, 0x01, 0x0d, 0xc7, 0xdd, 0x1a
    );

$der = '';
foreach( $itunes_intermediate_array as $value )
{
    $der .= chr($value);
}

//var_dump( unpack('H*', $der ) );

$handle = fopen( $dest_filepath, 'wb' );
{
    fwrite( $handle, '-----BEGIN CERTIFICATE-----' . "\n" );
    $certpem = chunk_split(base64_encode($der), 64, "\n");
    fwrite( $handle, $certpem );
    fwrite( $handle, '-----END CERTIFICATE-----' . "\n" );
    fflush( $handle );
    fclose( $handle );
    $handle = NULL;
}
}


?>
