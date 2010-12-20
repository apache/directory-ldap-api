/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.shared.util;


import java.io.UnsupportedEncodingException;
import java.util.Set;

/**
 * Various string manipulation methods that are more efficient then chaining
 * string operations: all is done in the same buffer without creating a bunch of
 * string objects.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Strings
{
    /**
     * The empty String <code>""</code>.
     *
     * @since 2.0
     */
    public static final String EMPTY = "";

    /**
     * The empty String[]
     */
    public static final String[] EMPTY_STRINGS = new String[] {};


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

        StringBuffer sb = new StringBuffer();

        for ( byte bite : buffer )
        {
            sb.append( "0x" ).append( ( char ) ( CharConstants.HEX_CHAR [ ( bite & 0x00F0 ) >> 4 ] ) ).append(
                    ( char ) ( CharConstants.HEX_CHAR [ bite & 0x000F ] ) ).append( " " );
        }

        return sb.toString();
    }


    /**
     * Test if the current character is a digit &lt;digit> ::= '0' | '1' | '2' |
     * '3' | '4' | '5' | '6' | '7' | '8' | '9'
     *
     * @param car the character to test
     *
     * @return <code>true</code> if the character is a Digit
     */
    public static boolean isDigit( char car )
    {
        return ( car >= '0' ) && ( car <= '9' );
    }


    /**
     * Test if the current byte is an Alpha character :
     * &lt;alpha> ::= [0x41-0x5A] | [0x61-0x7A]
     *
     * @param c The byte to test
     *
     * @return <code>true</code> if the byte is an Alpha
     *         character
     */
    public static boolean isAlpha( byte c )
    {
        return ( ( c > 0 ) && ( c <= 127 ) && CharConstants.ALPHA[c] );
    }


    /**
     * Test if the current character is an Alpha character :
     * &lt;alpha> ::= [0x41-0x5A] | [0x61-0x7A]
     *
     * @param c The char to test
     *
     * @return <code>true</code> if the character is an Alpha
     *         character
     */
    public static boolean isAlpha( char c )
    {
        return ( ( c > 0 ) && ( c <= 127 ) && CharConstants.ALPHA[c] );
    }


    /**
     * Check if the current char is in the unicodeSubset : all chars but
     * '\0', '(', ')', '*' and '\'
     *
     * @param c The char to check
     * @return True if the current char is in the unicode subset
     */
    public static boolean isUnicodeSubset( char c )
    {
        return ( ( c > 127 ) || CharConstants.UNICODE_SUBSET[c] );
    }


    /**
     * <p>
     * Checks if a String is empty ("") or null.
     * </p>
     *
     * <pre>
     *  StringUtils.isEmpty(null)      = true
     *  StringUtils.isEmpty(&quot;&quot;)        = true
     *  StringUtils.isEmpty(&quot; &quot;)       = false
     *  StringUtils.isEmpty(&quot;bob&quot;)     = false
     *  StringUtils.isEmpty(&quot;  bob  &quot;) = false
     * </pre>
     *
     * <p>
     * NOTE: This method changed in Lang version 2.0. It no longer trims the
     * String. That functionality is available in isBlank().
     * </p>
     *
     * @param str the String to check, may be null
     * @return <code>true</code> if the String is empty or null
     */
    public static boolean isEmpty( String str )
    {
        return str == null || str.length() == 0;
    }


    /**
     * Checks if a bytes array is empty or null.
     *
     * @param bytes The bytes array to check, may be null
     * @return <code>true</code> if the bytes array is empty or null
     */
    public static boolean isEmpty( byte[] bytes )
    {
        return bytes == null || bytes.length == 0;
    }


    /**
     * Return an UTF-8 encoded String
     *
     * @param bytes The byte array to be transformed to a String
     * @return A String.
     */
    public static String utf8ToString( byte[] bytes )
    {
        if ( bytes == null )
        {
            return "";
        }

        try
        {
            return new String( bytes, "UTF-8" );
        }
        catch ( UnsupportedEncodingException uee )
        {
            // if this happens something is really strange
            throw new RuntimeException( uee );
        }
    }


    /**
     * Return an UTF-8 encoded String
     *
     * @param bytes The byte array to be transformed to a String
     * @param length The length of the byte array to be converted
     * @return A String.
     */
    public static String utf8ToString( byte[] bytes, int length )
    {
        if ( bytes == null )
        {
            return "";
        }

        try
        {
            return new String( bytes, 0, length, "UTF-8" );
        }
        catch ( UnsupportedEncodingException uee )
        {
            // if this happens something is really strange
            throw new RuntimeException( uee );
        }
    }


    /**
     * Return an UTF-8 encoded String
     *
     * @param bytes  The byte array to be transformed to a String
     * @param start the starting position in the byte array
     * @param length The length of the byte array to be converted
     * @return A String.
     */
    public static String utf8ToString( byte[] bytes, int start, int length )
    {
        if ( bytes == null )
        {
            return "";
        }

        try
        {
            return new String( bytes, start, length, "UTF-8" );
        }
        catch ( UnsupportedEncodingException uee )
        {
            // if this happens something is really strange
            throw new RuntimeException( uee );
        }
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
            return new byte[0];
        }

        try
        {
            return string.getBytes( "UTF-8" );
        }
        catch ( UnsupportedEncodingException uee )
        {
            // if this happens something is really strange
            throw new RuntimeException( uee );
        }
    }


    /**
     * Utility method that return a String representation of a set
     *
     * @param set The set to transform to a string
     * @return A csv string
     */
    public static String setToString( Set<?> set )
    {
        if ( ( set == null ) || ( set.size() == 0 ) )
        {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        boolean isFirst = true;

        for ( Object elem : set )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                sb.append( ", " );
            }

            sb.append( elem );
        }

        return sb.toString();
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
        if ( ( high > 127 ) || ( low > 127 ) || ( high < 0 ) | ( low < 0 ) )
        {
            return -1;
        }

        return (byte)( ( CharConstants.HEX_VALUE[high] << 4 ) | CharConstants.HEX_VALUE[low] );
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
        if ( ( high > 127 ) || ( low > 127 ) || ( high < 0 ) | ( low < 0 ) )
        {
            return -1;
        }

        return (byte)( ( CharConstants.HEX_VALUE[high] << 4 ) | CharConstants.HEX_VALUE[low] );
    }

    /**
     * Return an hex value from a sinle char
     * The char must be in [0-9a-fA-F]
     *
     * @param c The char we want to convert
     * @return A byte between 0 and 15
     */
    public static byte getHexValue( char c )
    {
        if ( ( c > 127 ) || ( c < 0 ) )
        {
            return -1;
        }

        return CharConstants.HEX_VALUE[c];
    }

    /**
     * Check if the current byte is an Hex Char
     * &lt;hex> ::= [0x30-0x39] | [0x41-0x46] | [0x61-0x66]
     *
     * @param b The byte we want to check
     * @return <code>true</code> if the current byte is a Hex byte
     */
    public static boolean isHex( byte b )
    {
        return ( ( b | 0x7F ) == 0x7F ) || CharConstants.HEX[b];
    }

    /**
     * Check if the current character is an Hex Char &lt;hex> ::= [0x30-0x39] |
     * [0x41-0x46] | [0x61-0x66]
     *
     * @param bytes The buffer which contains the data
     * @param index Current position in the buffer
     * @return <code>true</code> if the current character is a Hex Char
     */
    public static boolean isHex( byte[] bytes, int index )
    {
        if ( ( bytes == null ) || ( bytes.length == 0 ) || ( index < 0 ) || ( index >= bytes.length ) )
        {
            return false;
        }
        else
        {
            byte c = bytes[index];

            if ( ( ( c | 0x7F ) != 0x7F ) || ( CharConstants.HEX[c] == false ) )
            {
                return false;
            }
            else
            {
                return true;
            }
        }
    }

    /**
     * Check if the current character is an Hex Char &lt;hex> ::= [0x30-0x39] |
     * [0x41-0x46] | [0x61-0x66]
     *
     * @param chars The buffer which contains the data
     * @param index Current position in the buffer
     * @return <code>true</code> if the current character is a Hex Char
     */
    public static boolean isHex( char[] chars, int index )
    {
        if ( ( chars == null ) || ( chars.length == 0 ) || ( index < 0 ) || ( index >= chars.length ) )
        {
            return false;
        }
        else
        {
            char c = chars[index];

            if ( ( c > 127 ) || ( CharConstants.HEX[c] == false ) )
            {
                return false;
            }
            else
            {
                return true;
            }
        }
    }

    /**
     * Check if the current character is an Hex Char &lt;hex> ::= [0x30-0x39] |
     * [0x41-0x46] | [0x61-0x66]
     *
     * @param string The string which contains the data
     * @param index Current position in the string
     * @return <code>true</code> if the current character is a Hex Char
     */
    public static boolean isHex( String string, int index )
    {
        if ( string == null )
        {
            return false;
        }

        int length = string.length();

        if ( ( length == 0 ) || ( index < 0 ) || ( index >= length ) )
        {
            return false;
        }
        else
        {
            char c = string.charAt( index );

            if ( ( c > 127 ) || ( CharConstants.HEX[c] == false ) )
            {
                return false;
            }
            else
            {
                return true;
            }
        }
    }

    /**
     * Count the number of bytes needed to return an Unicode char. This can be
     * from 1 to 6.
     *
     * @param bytes The bytes to read
     * @param pos Position to start counting. It must be a valid start of a
     *            encoded char !
     * @return The number of bytes to create a char, or -1 if the encoding is
     *         wrong. TODO : Should stop after the third byte, as a char is only
     *         2 bytes long.
     */
    public static int countBytesPerChar( byte[] bytes, int pos )
    {
        if ( bytes == null )
        {
            return -1;
        }

        if ( ( bytes[pos] & CharConstants.UTF8_MULTI_BYTES_MASK ) == 0 )
        {
            return 1;
        }
        else if ( ( bytes[pos] & CharConstants.UTF8_TWO_BYTES_MASK ) == CharConstants.UTF8_TWO_BYTES )
        {
            return 2;
        }
        else if ( ( bytes[pos] & CharConstants.UTF8_THREE_BYTES_MASK ) == CharConstants.UTF8_THREE_BYTES )
        {
            return 3;
        }
        else if ( ( bytes[pos] & CharConstants.UTF8_FOUR_BYTES_MASK ) == CharConstants.UTF8_FOUR_BYTES )
        {
            return 4;
        }
        else if ( ( bytes[pos] & CharConstants.UTF8_FIVE_BYTES_MASK ) == CharConstants.UTF8_FIVE_BYTES )
        {
            return 5;
        }
        else if ( ( bytes[pos] & CharConstants.UTF8_SIX_BYTES_MASK ) == CharConstants.UTF8_SIX_BYTES )
        {
            return 6;
        }
        else
        {
            return -1;
        }
    }
}
