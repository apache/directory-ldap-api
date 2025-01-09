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
package org.apache.directory.api.util;


import javax.naming.InvalidNameException;

import org.apache.directory.api.i18n.I18n;


/**
 * Various hex and string manipulation methods that are more efficient then
 * chaining operations: all is done in the same buffer without creating a bunch
 * of intermediate String objects.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class Hex
{
    /** &lt;hex&gt; ::= [0x30-0x39] | [0x41-0x46] | [0x61-0x66] */
    private static final byte[] HEX_VALUE =
        {
            // 00 -> 0F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            // 10 -> 1F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            // 20 -> 2F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            // 30 -> 3F ( 0, 1,2, 3, 4,5, 6, 7, 8, 9 )
             0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, 
             // 40 -> 4F ( A, B, C, D, E, F )
            -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
            // 50 -> 5F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            // 60 -> 6F ( a, b, c, d, e, f )
            -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
            // 70 -> 7F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    };

    /** Used to build output as Hex */
    private static final char[] HEX_CHAR =
        { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };


    /** 
     * A private constructor so that nobody can instanciate this class
     */
    private Hex()
    {
    }


    /**
     * Translate two chars to an hex value. The chars must be
     * in [a-fA-F0-9]
     *
     * @param high The high value
     * @param low The low value
     * @return A byte representation of the two chars
     */
    public static byte getHexValue( char high, char low )
    {
        if ( ( high > 127 ) || ( low > 127 ) )
        {
            return -1;
        }

        return ( byte ) ( ( HEX_VALUE[high] << 4 ) | HEX_VALUE[low] & 0xff );
    }


    /**
     * Translate two bytes to an hex value. The bytes must be
     * in [0-9a-fA-F]
     *
     * @param high The high value
     * @param low The low value
     * @return A byte representation of the two bytes
     */
    public static byte getHexValue( byte high, byte low )
    {
        if ( ( ( high & 0x7F ) != high ) || ( ( low & 0x7F ) != low ) )
        {
            return -1;
        }

        return ( byte ) ( ( HEX_VALUE[high] << 4 ) | HEX_VALUE[low] & 0xff );
    }


    /**
     * Return an hex value from a single char
     * The char must be in [0-9a-fA-F]
     *
     * @param c The char we want to convert
     * @return A byte between 0 and 15
     */
    public static byte getHexValue( char c )
    {
        if ( c > 127 )
        {
            return -1;
        }

        return HEX_VALUE[c];
    }


    /**
     * Decodes values of attributes in the DN encoded in hex into a UTF-8
     * String.  RFC2253 allows a DN's attribute to be encoded in hex.
     * The encoded value starts with a # then is followed by an even
     * number of hex characters.
     *
     * @param str the string to decode
     * @return the decoded string
     * @throws InvalidNameException If we can't decode the String to an UTF-8 String
     */
    public static String decodeHexString( String str ) throws InvalidNameException
    {
        if ( str == null || str.length() == 0 )
        {
            throw new InvalidNameException( I18n.err( I18n.ERR_17037_MUST_START_WITH_SHARP ) );
        }

        char[] chars = str.toCharArray();

        if ( chars[0] != '#' )
        {
            throw new InvalidNameException( I18n.err( I18n.ERR_17038_MUST_START_WITH_ESC_SHARP, str ) );
        }

        // the bytes representing the encoded string of hex
        // this should be ( length - 1 )/2 in size
        byte[] decoded = new byte[( chars.length - 1 ) >> 1];

        for ( int ii = 1, jj = 0; ii < chars.length; ii += 2, jj++ )
        {
            int ch = ( HEX_VALUE[chars[ii]] << 4 )
                + ( HEX_VALUE[chars[ii + 1]] & 0xff );
            decoded[jj] = ( byte ) ch;
        }

        return Strings.utf8ToString( decoded );
    }


    /**
     * Convert an escaoed list of bytes to a byte[]
     *
     * @param str the string containing hex escapes
     * @return the converted byte[]
     * @throws InvalidNameException If we can't convert the String to a byte[]
     */
    public static byte[] convertEscapedHex( String str ) throws InvalidNameException
    {
        if ( str == null )
        {
            throw new InvalidNameException( I18n.err( I18n.ERR_17039_NON_NULL_EXPECTED_STRING ) );
        }

        int length = str.length();

        if ( length == 0 )
        {
            throw new InvalidNameException( I18n.err( I18n.ERR_17040_EXPECTED_NON_EMPTY_STRING ) );
        }

        // create buffer and add everything before start of scan
        byte[] buf = new byte[str.length() / 3];
        int pos = 0;

        // start scaning until we find an escaped series of bytes
        for ( int i = 0; i < length; i++ )
        {
            char c = str.charAt( i );

            if ( c == '\\' )
            {
                // we have the start of a hex escape sequence
                if ( Chars.isHex( str, i + 1 ) && Chars.isHex( str, i + 2 ) )
                {
                    byte value = ( byte ) ( ( HEX_VALUE[str.charAt( i + 1 )] << 4 )
                        + ( HEX_VALUE[str.charAt( i + 2 )] & 0xff ) );

                    i += 2;
                    buf[pos++] = value;
                }
            }
            else
            {
                throw new InvalidNameException( I18n.err( I18n.ERR_17041_VALID_ESC_CHARS_EXPECTED ) );
            }
        }

        return buf;
    }


    /**
     * Converts an array of bytes into an array of characters representing the
     * hexadecimal values of each byte in order. The returned array will be
     * double the length of the passed array, as it takes two characters to
     * represent any given byte.
     *
     * @param data a byte[] to convert to Hex characters
     * @return A char[] containing hexadecimal characters
     */
    public static char[] encodeHex( byte[] data )
    {
        int l = data.length;

        char[] out = new char[l << 1];

        // two characters form the hex value.
        int j = 0;
        
        for ( int i = 0; i < l; i++ )
        {
            out[j++] = HEX_CHAR[( 0xF0 & data[i] ) >>> 4];
            out[j++] = HEX_CHAR[0x0F & data[i]];
        }

        return out;
    }
}
