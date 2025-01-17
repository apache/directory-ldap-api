/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.api.asn1.util;


import java.nio.charset.StandardCharsets;


/**
 * Little helper class for the asn1 package.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class Asn1StringUtils
{
    /** Hex chars */
    private static final byte[] HEX_CHAR = new byte[]
        { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    /**
     * The empty byte[]
     */
    public static final byte[] EMPTY_BYTES = new byte[]
        {};

    /**
     * Private constructor
     */
    private Asn1StringUtils()
    {
        // Nothing to do
    }

    /**
     * Helper function that dump a byte in hex form
     *
     * @param octet The byte to dump
     * @return A string representation of the byte
     */
    public static String dumpByte( byte octet )
    {
        return new String( new byte[]
            { '0', 'x', HEX_CHAR[( octet & 0x00F0 ) >> 4], HEX_CHAR[octet & 0x000F] }, StandardCharsets.UTF_8 );
    }


    /**
     * Helper function that dump an array of bytes in hex form
     *
     * @param buffer The bytes array to dump
     * @return A string representation of the array of bytes
     */
    public static String dumpBytes( byte[] buffer )
    {
        if ( buffer == null )
        {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        for ( byte b : buffer )
        {
            sb.append( "0x" ).append( ( char ) ( HEX_CHAR[( b & 0x00F0 ) >> 4] ) ).append(
                ( char ) ( HEX_CHAR[b & 0x000F] ) ).append( " " );
        }

        return sb.toString();
    }


    /**
     * Helper function that dump an array of bytes in hex form
     *
     * @param buffer The bytes array to dump
     * @param start The starting point in the buffer
     * @param length The number of bytes to print
     * @return A string representation of the array of bytes
     */
    public static String dumpBytes( byte[] buffer, int start, int length )
    {
        if ( buffer == null )
        {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        for ( int i = start; i < start + length; i++ )
        {
            byte b = buffer[i];

            sb.append( "0x" ).append( ( char ) ( HEX_CHAR[( b & 0x00F0 ) >> 4] ) ).append(
                ( char ) ( HEX_CHAR[b & 0x000F] ) ).append( " " );
        }

        return sb.toString();
    }


    /**
     * Return UTF-8 encoded byte[] representation of a String
     *
     * @param string The string to be transformed to a byte array
     * @return The transformed byte array
     */
    public static byte[] getBytesUtf8( String string )
    {
        if ( string == null )
        {
            return EMPTY_BYTES;
        }

        return string.getBytes( StandardCharsets.UTF_8 );
    }


    /**
     * Transform a string to an array of ASCII bytes, where the byte array will contain
     * only values in [0, 127].
     *
     * @param string The byte array to transform
     * @return The resulting string
     */
    public static byte[] asciiStringToByte( String string )
    {
        if ( ( string == null ) || ( string.length() == 0 ) )
        {
            return EMPTY_BYTES;
        }

        byte[] result = new byte[string.length()];

        for ( int i = 0; i < result.length; i++ )
        {
            result[i] = ( byte ) string.charAt( i );
        }

        return result;
    }
}
