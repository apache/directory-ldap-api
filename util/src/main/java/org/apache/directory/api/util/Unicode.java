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


import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;


/**
 * Various unicode manipulation methods that are more efficient then chaining
 * operations: all is done in the same buffer without creating a bunch of string
 * objects.
 * 
 * Note that UTF-8 can use up to 8 bytes to encode an Unicode value. This is
 * define by <a href="https://datatracker.ietf.org/doc/html/rfc3629">RFC 3629</a>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class Unicode
{
    /** The UTF-8 multi-bytes mask */
    private static final int UTF8_MULTI_BYTES_MASK = 0x0080;

    /** The UTF-8 two-bytes mask */
    private static final int UTF8_TWO_BYTES_MASK = 0x00E0;
    
    /** A marker if the UTF-8 string has 2 bytes */
    private static final int UTF8_TWO_BYTES = 0x00C0;

    /** The UTF-8 three-bytes mask */
    private static final int UTF8_THREE_BYTES_MASK = 0x00F0;

    /** A marker if the UTF-8 string has 3 bytes */
    private static final int UTF8_THREE_BYTES = 0x00E0;

    /** The UTF-8 four-bytes mask */
    private static final int UTF8_FOUR_BYTES_MASK = 0x00F8;

    /** A marker if the UTF-8 string has 4 bytes */
    private static final int UTF8_FOUR_BYTES = 0x00F0;

    /** %01-%27 %2B-%5B %5D-%7F */
    private static final boolean[] UNICODE_SUBSET =
        {
            // '\0'
            false, true,  true,  true,  true,  true,  true,  true, 
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            // '(', ')', '*'
            false, false, false, true,  true,  true,  true,  true, 
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            // '\'
            true,  true,  true,  true,  false, true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
        };
    
    /** A mask to get a one byte UTF-8 character */
    private static final int CHAR_ONE_BYTE_MASK = 0xFFFFFF80;
    
    /** A mask to get a two bytes UTF-8 character */
    private static final int CHAR_TWO_BYTES_MASK = 0xFFFFF800;
    
    /** A mask to get a three bytes UTF-8 character */
    private static final int CHAR_THREE_BYTES_MASK = 0xFFFF0000;
    
    /** A mask to get a four bytes UTF-8 character */
    private static final int CHAR_FOUR_BYTES_MASK = 0xFFE00000;
    
    /** 
     * A private constructor. This class should not be instanciated 
     */
    private Unicode()
    {
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

        if ( ( bytes[pos] & UTF8_MULTI_BYTES_MASK ) == 0 )
        {
            return 1;
        }
        else if ( ( bytes[pos] & UTF8_TWO_BYTES_MASK ) == UTF8_TWO_BYTES )
        {
            return 2;
        }
        else if ( ( bytes[pos] & UTF8_THREE_BYTES_MASK ) == UTF8_THREE_BYTES )
        {
            return 3;
        }
        else if ( ( bytes[pos] & UTF8_FOUR_BYTES_MASK ) == UTF8_FOUR_BYTES )
        {
            return 4;
        }
        else
        {
            return -1;
        }
    }


    /**
     * Return the Unicode char which is coded in the bytes at position 0.
     *
     * @param bytes The byte[] represntation of an Unicode string.
     * @return The first char found.
     */
    public static char bytesToChar( byte[] bytes )
    {
        return bytesToChar( bytes, 0 );
    }


    /**
     * Return the Unicode char which is coded in the bytes at the given
     * position.
     *
     * @param bytes The byte[] represntation of an Unicode string.
     * @param pos The current position to start decoding the char
     * @return The decoded char, or -1 if no char can be decoded TODO : Should
     *         stop after the third byte, as a char is only 2 bytes long.
     */
    public static char bytesToChar( byte[] bytes, int pos )
    {
        if ( bytes == null )
        {
            return ( char ) -1;
        }

        if ( ( bytes[pos] & UTF8_MULTI_BYTES_MASK ) == 0 )
        {
            return ( char ) bytes[pos];
        }
        else
        {
            if ( ( bytes[pos] & UTF8_TWO_BYTES_MASK ) == UTF8_TWO_BYTES )
            {
                // Two bytes char
                // 110x-xxyy 10zz-zzzz -> 0000-0xxx yyzz-zzzz
                return ( char ) ( ( ( bytes[pos] & 0x1C ) << 6 ) + ( ( bytes[pos] & 0x03 ) << 6 ) + ( bytes[pos + 1] & 0x3F ) );
            }
            else if ( ( bytes[pos] & UTF8_THREE_BYTES_MASK ) == UTF8_THREE_BYTES )
            {
                // Three bytes char
                // 1110-tttt 10xx-xxyy 10zz-zzzz -> tttt-xxxx yyzz-zzzz (FF FF)
                return ( char ) ( ( ( bytes[pos] & 0x0F ) << 12 )
                    + ( ( bytes[pos + 1] & 0x3C ) << 6 )
                    + ( ( bytes[pos + 1] & 0x03 ) << 6 )
                    + ( bytes[pos + 2] & 0x3F )
                );
            }
            else if ( ( bytes[pos] & UTF8_FOUR_BYTES_MASK ) == UTF8_FOUR_BYTES )
            {
                // Four bytes char
                return ( char ) (
                // 1111-0ttt 10uu-vvvv 10xx-xxyy 10zz-zzzz -> 000t-ttuu vvvv-xxxx yyzz-zzzz (1FFFFF)
                ( ( bytes[pos] & 0x07 ) << 18 )
                    + ( ( bytes[pos + 1] & 0x30 ) << 16 )
                    + ( ( bytes[pos + 1] & 0x0F ) << 12 )
                    + ( ( bytes[pos + 2] & 0x3C ) << 6 )
                    + ( ( bytes[pos + 2] & 0x03 ) << 6 )
                    + ( bytes[pos + 3] & 0x3F )
                );
            }
            else
            {
                return ( char ) -1;
            }
        }
    }


    /**
     * Return the number of bytes that hold an Unicode char.
     *
     * @param car The character to be decoded
     * @return The number of bytes to hold the char. TODO : Should stop after
     *         the third byte, as a char is only 2 bytes long.
     */
    public static int countNbBytesPerChar( char car )
    {
        if ( ( car & CHAR_ONE_BYTE_MASK ) == 0 )
        {
            return 1;
        }
        else if ( ( car & CHAR_TWO_BYTES_MASK ) == 0 )
        {
            return 2;
        }
        else if ( ( car & CHAR_THREE_BYTES_MASK ) == 0 )
        {
            return 3;
        }
        else if ( ( car & CHAR_FOUR_BYTES_MASK ) == 0 )
        {
            return 4;
        }
        else
        {
            return -1;
        }
    }


    /**
     * Count the number of bytes included in the given char[].
     *
     * @param chars The char array to decode
     * @return The number of bytes in the char array
     */
    public static int countBytes( char[] chars )
    {
        if ( chars == null )
        {
            return 0;
        }

        int nbBytes = 0;
        int currentPos = 0;

        while ( currentPos < chars.length )
        {
            int nbb = countNbBytesPerChar( chars[currentPos] );

            // If the number of bytes necessary to encode a character is
            // above 3, we will need two UTF-16 chars
            currentPos += ( nbb < 4 ? 1 : 2 );
            nbBytes += nbb;
        }

        return nbBytes;
    }


    /**
     * Count the number of chars included in the given byte[].
     *
     * @param bytes The byte array to decode
     * @return The number of char in the byte array
     */
    public static int countChars( byte[] bytes )
    {
        if ( bytes == null )
        {
            return 0;
        }

        int nbChars = 0;
        int currentPos = 0;

        while ( currentPos < bytes.length )
        {
            currentPos += countBytesPerChar( bytes, currentPos );
            nbChars++;
        }

        return nbChars;
    }


    /**
     * Return the Unicode char which is coded in the bytes at the given
     * position.
     *
     * @param car The character to be transformed to an array of bytes
     *
     * @return The byte array representing the char
     *
     * TODO : Should stop after the third byte, as a char is only 2 bytes long.
     */
    public static byte[] charToBytes( char car )
    {
        if ( car <= 0x007F )
        {
            byte[] bytes = new byte[1];

            // Single byte char
            bytes[0] = ( byte ) car;
            
            return bytes;
        }
        else if ( car <= 0x07FF )
        {
            byte[] bytes = new byte[2];

            // two bytes char
            bytes[0] = ( byte ) ( 0x00C0 + ( ( car & 0x07C0 ) >> 6 ) );
            bytes[1] = ( byte ) ( 0x0080 + ( car & 0x3F ) );
            
            return bytes;
        }
        else
        {
            byte[] bytes = new byte[3];

            // Three bytes char
            bytes[0] = ( byte ) ( 0x00E0 + ( ( car & 0xF000 ) >> 12 ) );
            bytes[1] = ( byte ) ( 0x0080 + ( ( car & 0x0FC0 ) >> 6 ) );
            bytes[2] = ( byte ) ( 0x0080 + ( car & 0x3F ) );
            
            return bytes;
        }
    }


    /**
     * Check if the current char is in the unicodeSubset : all chars but
     * '\0', '(', ')', '*' and '\'
     *
     * @param str The string to check
     * @param pos Position of the current char
     * @return True if the current char is in the unicode subset
     */
    public static boolean isUnicodeSubset( String str, int pos )
    {
        if ( ( str == null ) || ( str.length() <= pos ) || ( pos < 0 ) )
        {
            return false;
        }

        char c = str.charAt( pos );

        return ( c > 127 ) || UNICODE_SUBSET[c];
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
        return ( c > 127 ) || UNICODE_SUBSET[c];
    }


    /**
     * Check if the current byte is in the unicodeSubset : all chars but
     * '\0', '(', ')', '*' and '\'
     *
     * @param b The byte to check
     * @return True if the current byte is in the unicode subset
     */
    public static boolean isUnicodeSubset( byte b )
    {
        return ( b < 0 ) || ( b > 127 ) || UNICODE_SUBSET[b];
    }


    /**
     *
     * Writes four bytes of length information to the output stream, followed by the modified UTF-8 representation
     * of every character in the string str. If str is null, the string value 'null' is written with a length of 0
     * instead of throwing an NullPointerException. Each character in the string s  is converted to a group of one,
     * two, or three bytes, depending on the value of the character.
     *
     * Due to given restrictions (total number of written bytes in a row can't exceed 65535) the total length is
     * written in the length information (four bytes (writeInt)) and the string is split into smaller parts
     * if necessary and written. As each character may be converted to a group of maximum 3 bytes and 65535 bytes
     * can be written at maximum we're on the save side when writing a chunk of only 21845 (65535/3) characters at
     * once.
     *
     * See also {@link java.io.DataOutput#writeUTF(String)}.
     *
     * @param objectOutput The objectOutput to write to
     * @param str The value to write
     * @throws java.io.IOException If the value can't be written to the file
     */
    public static void writeUTF( ObjectOutput objectOutput, String str ) throws IOException
    {
        // Write a 'null' string
        if ( str == null )
        {
            objectOutput.writeInt( 0 );
            objectOutput.writeUTF( "null" );
        }
        else
        {
            // Write length of string
            objectOutput.writeInt( str.length() );

            StringBuilder strBuf = new StringBuilder( str );

            // Write the string in portions not larger than 21845 characters
            while ( strBuf != null )
            {
                if ( strBuf.length() < 21845 )
                {
                    objectOutput.writeUTF( strBuf.substring( 0, strBuf.length() ) );
                    strBuf = null;
                }
                else
                {
                    objectOutput.writeUTF( strBuf.substring( 0, 21845 ) );
                    strBuf.delete( 0, 21845 );
                }
            }
        }
    }


    /**
     *
     * Reads in a string that has been encoded using a modified UTF-8  format. The general contract of readUTF  is
     * that it reads a representation of a Unicode character string encoded in modified UTF-8 format; this string of
     * characters is then returned as a String.
     *
     * First, four bytes are read (readInt) and used to construct an unsigned 16-bit integer in exactly the manner
     * of the readUnsignedShort  method . This integer value is called the UTF length and specifies the number of
     * additional bytes to be read. These bytes are then converted to characters by considering them in groups. The
     * length of each group is computed from the value of the first byte of the group. The byte following a group, if
     * any, is the first byte of the next group.
     *
     *See also {@link java.io.DataInput#readUTF()}.
     *
     * @param objectInput The objectInput to read from
     * @return The read string
     * @throws java.io.IOException If the value can't be read
     */
    public static String readUTF( ObjectInput objectInput ) throws IOException
    {
        // Read length of the string
        int strLength = objectInput.readInt();

        // Start reading the string
        StringBuilder strBuf = new StringBuilder( objectInput.readUTF() );

        if ( ( strLength == 0 ) && ( "null".equals( strBuf.toString() ) ) ) 
        {
            // The special case of a 'null' string
            return null;
        }
        else
        {
            while ( strLength > strBuf.length() )
            {
                strBuf.append( objectInput.readUTF() );
            }
            return strBuf.toString();
        }
    }
}
