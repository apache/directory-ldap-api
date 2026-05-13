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
package org.apache.directory.api.ldap.model.name;


import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Position;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.directory.api.util.ParserUtil.isMatchChar;
import static org.apache.directory.api.util.ParserUtil.hasMoreChars;
import static org.apache.directory.api.util.ParserUtil.matchChar;

import static org.apache.directory.api.util.ParserUtil.COMMA;
import static org.apache.directory.api.util.ParserUtil.DOT;
import static org.apache.directory.api.util.ParserUtil.DQUOTE;
import static org.apache.directory.api.util.ParserUtil.EQUAL;
import static org.apache.directory.api.util.ParserUtil.ESC;
import static org.apache.directory.api.util.ParserUtil.LANGLE;
import static org.apache.directory.api.util.ParserUtil.PLUS;
import static org.apache.directory.api.util.ParserUtil.RANGLE;
import static org.apache.directory.api.util.ParserUtil.SEMI_COLON;
import static org.apache.directory.api.util.ParserUtil.SHARP;
import static org.apache.directory.api.util.ParserUtil.SPACE;

/**
 * A Dn parser that is able to parse complex DNs. 
 * 
 * This is an hand written parser.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
/* No protection*/final class DnParser
{
    /** The LoggerFactory used by this class */
    protected static final Logger LOG = LoggerFactory.getLogger( DnParser.class );
    
    /** A private enum listing the AttributeType state machine states */
    private enum AttributTypeStates 
    {
        START,
        STATE_1,
        STATE_2,
        STATE_3,
        STATE_4,
        STATE_5,
        STATE_6,
        STATE_7,
        STATE_8,
        STATE_9,
        STATE_10,
        END
    }
    
    /** A private enum listing the AttributeValue state machine states */
    private enum AttributeValuestates 
    {
        START,
        STRING_PAIR,
        STRING_PAIR_HEX1,
        STRING_MIDDLE,
        STRING_PAIR_MIDDLE,
        STRING_PAIR_HEX1_MIDDLE,
        END
    }
    
    /**
     * A flag used to tell which part of a hex value we are dealing with
     */
    private static final boolean EVEN = true;
    private static final boolean ODD = false;   

    /** No constructor allowed */
    private DnParser() 
    {
        throw new UnsupportedOperationException( "This is a utility class and cannot be instantiated" );
    }
    
    
    /**
     * Create a normalized AVA
     */
    private static String createNormAva( Ava ava )
    {
        StringBuilder rdnNormStr = new StringBuilder();
        Value value = ava.getValue(); 

        rdnNormStr.append( ava.getNormType() );
        rdnNormStr.append( EQUAL );

        if ( value != null )
        {
            if ( value.getNormalized() != null )
            {
                rdnNormStr.append( value.getNormalized() );
            }
            else
            {
                // We can't tell if the value is HR or not. 
                // Use the Value User Provided value
                rdnNormStr.append( value.getUpValue() );
            }
        }

        return rdnNormStr.toString();
    }

    
    /**
     * Parse a HexString:
     * 
     * <pre>
     * hexstring ::= SHARP hexpair hexpair*
     * hexpair ::= HEX HEX
     * </pre>
     */
    private static byte[] parseHexString( Position pos )
            throws ParseException
    {
        // We should at least have one hexpair. The '#' has already been read.
        // We start with a NONE value: we haven't seen any yet
        boolean hexPair = EVEN;
        int hexValue = 0;
        
        // The maximum length, divided by two. We allocate a byte array 
        // of this size, just in case
        int maxLength = ( pos.length - pos.start ) >> 1;
        byte[] result = new byte[maxLength];
                
        // Keep a track of the first hexPair
        int start = pos.start;
        int current = 0;
        
        // The position of any space after the value: we should keep them
        // in the upValue, but ignore them for the normValue
        int spaceStart = -1;
        
        // A flag used to exit the loop
        boolean valueRead = false; 

        while ( hasMoreChars( pos ) && !valueRead )
        {
            byte b = pos.getByte();
            
            switch ( b )
            {
                case '0': case '1': case '2': case '3':
                case '4': case '5': case '6': case '7':
                case '8': case '9': 
                    if ( hexPair == EVEN )
                    {
                        // A new hexPair
                        hexValue = b - '0';
                        hexPair = ODD;
                    }
                    else
                    {
                        // Ok, we have an hex pair, let's convert it
                        result[current++] = ( byte ) ( ( hexValue << 4 ) + b - '0' );
                        
                        hexPair = EVEN;
                    }

                    pos.start++;
                    break;

                case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                    if ( hexPair == EVEN )
                    {
                        hexValue = b - 'a' + 10;
                        hexPair = ODD;
                    }
                    else
                    {
                        // Ok, we have an hex pair, let's convert it
                        result[current++] = ( byte ) ( ( hexValue << 4 ) + b - 'a' + 10 );
                        hexPair = EVEN;
                    }
                    
                    pos.start++;
                    break;
                    
                case 'A': case 'B': case 'C': case 'D':case 'E':case 'F':
                    if ( hexPair == EVEN )
                    {
                        hexValue = b - 'A' + 10;
                        hexPair = ODD;
                    }
                    else
                    {
                        // Ok, we have an hex pair, let's convert it
                        result[current++] = ( byte ) ( ( hexValue << 4 ) + b - 'A' + 10 );
                        hexPair = EVEN;
                    }
                    
                    pos.start++;
                    break;
                    
                case SPACE:
                    // A special case: we have to ignore them
                    if ( spaceStart == -1 )
                    {
                        spaceStart = pos.start;
                    }
                    
                    pos.start++;
                    break;
                    
                case PLUS: case COMMA: case SEMI_COLON:
                    // The end, we should have either one or more space,
                    // a '+', a ',' a ';' or nothing. But here, we just stop
                    // Copy the bytes read
                    valueRead  = true;
                    break;

                default:
                    // This is an error
                    throw new ParseException( I18n.err( I18n.ERR_13613_VALUE_NOT_IN_HEX_FORM_ODD_NUMBER ), pos.start );
            }
        }
        
        // Ok, we are done. Check that we have had only hex pairs
        if ( ( hexPair == ODD ) || ( current == 0 ) )
        {
            // This is an error, we have an even number of chars.
            throw new ParseException( I18n.err( I18n.ERR_13613_VALUE_NOT_IN_HEX_FORM_ODD_NUMBER ), pos.start );
        }
        
        // Deal with spaces at the end of the value. We should not copy them
        int realSize = pos.start;
        
        if ( spaceStart > 0 )
        {
            realSize = spaceStart;
        }
        
        realSize = ( realSize - start ) >> 1;
        
        byte[] valueBytes = Arrays.copyOf( result, realSize );
        
        return valueBytes;
    }
    
    
    /**
     * Parse a hex pair 
     */
    private static void parsePair( Position pos, StringBuilder upValue, byte[] result, int[] bPos )
            throws ParseException
    {
        // We have either a couple of hex chars, or some special char
        if ( !hasMoreChars( pos ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13631_WRONG_ESCAPED_SEQUENCE ), pos.start );
        }
        
        // Let's process the first state
        byte b = pos.getByte();
        int firstHex = 0;

        switch ( b )
        {
            case ESC: 
            case DQUOTE: 
            case PLUS: 
            case COMMA: 
            case SEMI_COLON: 
            case LANGLE:
            case RANGLE:
            case SPACE:
            case SHARP:
            case EQUAL:
                // An escaped special char
                upValue.append( ESC );
                upValue.append( ( char ) b );
                result[bPos[0]++] = b;
                pos.start++;

                return;
            
            case '0': case '1': case '2': case '3':  case '4': 
            case '5': case '6': case '7': case '8': case '9': 
                firstHex = b - '0';
                break;
                
            case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': 
                firstHex = b - 'a' + 10;
                break;
                
            case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': 
                firstHex = b - 'A' + 10;
                break;
                
            default:
                // An error: we are supposed to have an escaped sequence
                throw new ParseException( I18n.err( I18n.ERR_13631_WRONG_ESCAPED_SEQUENCE ), pos.start );
        }
        
        // Let's check the second char now
        pos.start++;
        
        if ( hasMoreChars( pos ) )
        {
            b = pos.getByte();
            byte bb = 0;
            
            switch ( b )
            {
                case '0': case '1': case '2': case '3':  case '4': 
                case '5': case '6': case '7': case '8': case '9': 
                    bb = ( byte ) ( ( firstHex << 4 ) + b - '0' );
                    
                    break;
                    
                case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': 
                    bb = ( byte ) ( ( firstHex << 4 ) + b - 'a' + 10 );

                    break;
                    
                case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': 
                    bb = ( byte ) ( ( firstHex << 4 ) + b - 'A' + 10 );

                    break;
                    
                default:
                    // An error: we are supposed to have an escaped sequence
                    throw new ParseException( I18n.err( I18n.ERR_13631_WRONG_ESCAPED_SEQUENCE ), pos.start );
            }
            
            result[bPos[0]++] = bb;
            pos.start++;
        }
        else
        {
            // This is an error, we must have a second char
            throw new ParseException( I18n.err( I18n.ERR_13632_WRONG_HEX_PAIR ), pos.start );
        }
        
        return;
    }
    
    
    /**
     * Get an UTF0 byte (0x80-0xBF)
     */
    private static byte getUTF0( Position pos, byte[] result, int[] bPos ) throws ParseException
    {
        if ( hasMoreChars( pos ) )
        {
            byte b = pos.getByte();
            
            // Must be an UTF0 (0x80-0xBF)
            if ( ( b >= ( byte ) 0x0080 ) && ( b <= ( byte ) 0x00BF ) )
            {
                pos.start++;
                result[bPos[0]++] = b;
                
                return b;
            }
            else
            {
                // Error
                byte[] wrongBytes = new byte[] { b };
                throw new ParseException( I18n.err( I18n.ERR_13633_INVALID_UTFMB, 
                        Strings.dumpBytes( wrongBytes ) ), pos.start );
            }
        }
        else
        {
            // Error
            throw new ParseException( I18n.err( I18n.ERR_13634_INCOMPLETE_UTFMB ), pos.start );
        }
    }

    
    /**
     * Parse the following char:
     * 
     * <pre>
     * UTF2 = %xC2-DF UTF0
     * </pre>
     */
    private static char parseUTF2( Position pos, byte u1, byte[] result, int[] bPos ) throws ParseException
    {
        result[bPos[0]++] = u1;

        // UTF2, get the next byte, which must be between 0x80-0xBF
        byte u2 = getUTF0( pos, result, bPos );

        // Convert to unicode: 
        // C2 -> DF: 110[0 0010] - 110[1 1111], mask is 0x1F
        // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
        char c = ( char ) ( ( ( u1 & 0x001F ) << 6 ) | ( u2 & 0x003F ) );
        
        return c;
    }

    
    /**
     * Parse the following char:
     * 
     * <pre>
     * UTF3 = %xE0 %xA0-BF UTF0
     * </pre>
     */
    private static char parseUTF3First( Position pos, byte u1, byte[] result, int[] bPos ) throws ParseException
    {
        result[bPos[0]++] = u1;

        // UTF3, get the next byte, which must be between 0xA0-0xBF
        if ( hasMoreChars( pos ) )
        {
            byte u2 = pos.getByte();
            
            if ( ( u2 >= ( byte ) 0x00A0 ) && ( u2 <= ( byte ) 0x00BF ) )
            {
                pos.start++;
                result[bPos[0]++] = u2;

                
                // The third byte must be an UTF-0
                byte u3 = getUTF0( pos, result, bPos );
                    
                // Convert to unicode: 
                // E0 -> 1110 [0000] mask is 0x0F
                // A0 -> BF: 10[10 0000] - 10[11 1111], mask is 0x3F
                // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
                char c = ( char ) ( ( ( u1 & 0x0010F ) << 12 ) 
                        | ( ( u2 & 0x003F ) << 6 ) 
                        | ( u3 & 0x003F ) );
                
                return c;
            }
            else
            {
                // Error
                byte[] wrongBytes = new byte[] { u1, u2 };
                throw new ParseException( I18n.err( I18n.ERR_13633_INVALID_UTFMB, 
                        Strings.dumpBytes( wrongBytes ) ), pos.start );
            }
        }
        else
        {
            // Error
            byte[] wrongBytes = new byte[] { u1 };
            throw new ParseException( I18n.err( I18n.ERR_13633_INVALID_UTFMB, 
                    Strings.dumpBytes( wrongBytes ) ), pos.start );
        }
    }
    
    
    /**
     * Parse the following char:
     * 
     * <pre>
     * UTF3 = %xE1-EC 2(UTF0)
     * </pre>
     */
    private static char parseUTF3Second( Position pos, byte u1, byte[] result, int[] bPos ) throws ParseException
    {
        result[bPos[0]++] = u1;

        // UTF3, get the next byte, which must be between 0x80-0xBF
        byte u2 = getUTF0( pos, result, bPos );
        byte u3 = getUTF0( pos, result, bPos );
        
        // Convert to unicode: 
        // E1 -> EC: 1110 [0001] - 1110 [1100], mask is 0x0F
        // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
        // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
        char c = ( char ) ( ( ( u1 & 0x000F ) << 12 ) 
                | ( ( u2 & 0x003F ) << 6 ) 
                | ( u3 & 0x003F ) );
        
        return c;
    }

    
    /**
     * Parse the following char:
     * 
     * <pre>
     * UTF3 = %xED %x80-9F UTF0
     * </pre>
     */
    private static char parseUTF3Third( Position pos, byte u1, byte[] result, int[] bPos ) throws ParseException
    {
        result[bPos[0]++] = u1;

        // UTF3, get the next byte, which must be between 0x80-0x9F
        if ( hasMoreChars( pos ) )
        {
            byte u2 = pos.getByte();
            
            if ( ( u2 >= ( byte ) 0x0080 ) && ( u2 <= ( byte ) 0x009F ) )
            {
                pos.start++;
                result[bPos[0]++] = u2;

                
                // The third byte must be an UTF-0 (0x80-0xBF)
                byte u3 = getUTF0( pos, result, bPos );

                // Convert to unicode: 
                // E0 -> 1110 [1101] Value 0x0D
                // A0 -> BF: 100[0 0000] - 100[1 1111], mask is 0x1F
                // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
                char c = ( char ) ( ( ( 0x000D ) << 12 ) 
                        | ( ( u2 & 0x001F ) << 6 ) 
                        | ( u3 & 0x003F ) );
                
                return c;
            }
            else
            {
                // Error
                byte[] wrongBytes = new byte[] { u1, u2 };
                throw new ParseException( I18n.err( I18n.ERR_13633_INVALID_UTFMB, 
                        Strings.dumpBytes( wrongBytes ) ), pos.start );
            }
        }
        else
        {
            // Error
            byte[] wrongBytes = new byte[] { u1 };
            throw new ParseException( I18n.err( I18n.ERR_13633_INVALID_UTFMB, 
                    Strings.dumpBytes( wrongBytes ) ), pos.start );
        }
    }
    
    
    /**
     * Parse the following char:
     * 
     * <pre>
     * UTF3 = %xEE-EF 2(UTF0)
     * </pre>
     */
    private static char parseUTF3Forth( Position pos, byte u1, byte[] result, int[] bPos ) throws ParseException
    {
        result[bPos[0]++] = u1;

        // UTF3, get the next byte, which must be between 0x80-0xBF
        byte u2 = getUTF0( pos, result, bPos );
        byte u3 = getUTF0( pos, result, bPos );

        // Convert to unicode: 
        // EE -> EF: 1110 [1110] - 1110 [1111], mask is 0x0F
        // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
        // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
        char c = ( char ) ( ( ( u1 & 0x000F ) << 12 ) 
                | ( ( u2 & 0x003F ) << 6 ) 
                | ( u3 & 0x003F ) );
        
        return c;
    }
    
    
    /**
     * As we have 20 bits to deal with, and as a char can only contains 16 bits, the value is
     * split in two 10 bits values:
     * 
     * <pre>
     *   byte 1     byte 2     byte 3     byte 4
     * [1111 0]xab  [10]01 0000  [10]00 0000  [10]00 0000   Min
     *              [10]11 1111  [10]11 1111  [10]11 1111   Max
     *          <>      <----->      <----->      <----->   Value bits from 0 to 19 (20 bits)
     *          11      11 1111      11 0000      00 0000 
     *          98      76 5432      10 9876      54 3210
     *          [   High surrogate    ] [ Low Surrogate ]
     * </pre>
     * 
     * <ul>
     *   <li>The Low Surrogate uses bits from 0 to 9</li>
     *   <li>The High Surrigate uses bits from 10 to 19</li>
     * </ul>
     * 
     * Now, we add 0xD800 to the high surrogate (1101 1000  0000 0000)
     * and 0xDC00 to the low surrogate (1101 1100 0000 0000)
     * 
     * That gives two values, from 0xD800 to 0xDBFF (high surrogate) and from 0xDC00 to 0xDFFF (low surrogate).
     * 
     * The returned int will contains those two values, as (High Surrogate << 16) & Low Surrogate
     */
    private static int computeSurrogates( int value )
    {
        // Remove 0x10000
        value -= 0x10000;
        
        // Split it in two surrogates, using 10 high bits (mask 0x000F FC00)
        // and 10 low bits (mask 0x000003FF)
        int highSurrogate = ( ( value & 0x000F_FC00 ) >> 10 ) | 0xD800;
        int lowSurrogate  = ( value & 0x0000_03FF ) | 0xDC00;
        
        // And combine both
        return ( highSurrogate << 16 ) | lowSurrogate;
    }
    
    
    /**
     * Parse the following char:
     * 
     * <pre>
     * UTF4    = %xF0 %x90-BF 2(UTF0)
     * </pre>
     * 
     * It will be encoded as an int, using a high surrogate and a low surrogate.
     * The reason is that we can't encode an unicode value above 0xFFFF into a char, as a char
     * only contains an UTF-16 value.
     * 
     * The bits layout for an UTF4 is the following:
     * <pre>
     *   byte 1     byte 2     byte 3     byte 4
     * [1111 0]x00  [10]01 0000  [10]00 0000  [10]00 0000   Min
     *              [10]11 1111  [10]11 1111  [10]11 1111   Max
     *          <>      <----->      <----->      <----->   Value bits from 0 to 19 (20 bits)
     *          11      11 1111      11 0000      00 0000 
     *          98      76 5432      10 9876      54 3210
     * </pre>
     */
    private static int parseUTF4First( Position pos, byte u1, byte[] result, int[] bPos ) throws ParseException
    {
        result[bPos[0]++] = u1;

        // UTF4, get the next byte, which must be between 0x90-0xBF
        if ( hasMoreChars( pos ) )
        {
            byte u2 = pos.getByte();
            
            if ( ( u2 >= ( byte ) 0x0090 ) && ( u2 <= ( byte ) 0x00BF ) )
            {
                pos.start++;
                result[bPos[0]++] = u2;

                
                byte u3 = getUTF0( pos, result, bPos );
                byte u4 = getUTF0( pos, result, bPos );
                    
                // Convert to unicode: 
                // F0 -> 1111 00[00] Value 0x00
                // 90 -> BF: 10[01 0000] - 10[11 1111], mask is 0x3F
                // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
                // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
                int i = ( int ) ( ( ( u2 & 0x003F ) << 12 ) 
                        | ( ( u3 & 0x003F ) << 6 ) 
                        | ( u4 & 0x003F ) );
                
                // And convert to surrogates
                return computeSurrogates( i );
            }
            else
            {
                // Error
                byte[] wrongBytes = new byte[] { u1, u2 };
                throw new ParseException( I18n.err( I18n.ERR_13633_INVALID_UTFMB, 
                        Strings.dumpBytes( wrongBytes ) ), pos.start );
            }
        }
        else
        {
            // Error
            byte[] wrongBytes = new byte[] { u1 };
            throw new ParseException( I18n.err( I18n.ERR_13633_INVALID_UTFMB, 
                    Strings.dumpBytes( wrongBytes ) ), pos.start );
        }
    }
    
    
    /**
     * Parse the following char:
     * 
     * <pre>
     * UTF4    = %xF1-F3 3(UTF0)
     * </pre>
     * 
     * Same that the parseUTF4_1 method, the result will be encoded as an int
     */
    private static int parseUTF4Second( Position pos, byte u1, byte[] result, int[] bPos ) throws ParseException
    {
        result[bPos[0]++] = u1;

        // UTF4, get the next byte, which must be between 0x90-0xBF
        byte u2 = getUTF0( pos, result, bPos );
        byte u3 = getUTF0( pos, result, bPos );
        byte u4 = getUTF0( pos, result, bPos );

        // Convert to unicode: 
        // F1-F3:    1111 0[001] - 1111 0[011], mask is 0x07
        // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
        // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
        // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
        int i = ( int ) ( ( ( u1 & 0x0007 ) << 18 ) 
                | ( ( u2 & 0x003F ) << 12 ) 
                | ( ( u3 & 0x003F ) << 6 ) 
                | ( u4 & 0x003F ) );
        
        // And convert to surrogates
        return computeSurrogates( i );
    }
    
    
    /**
     * Parse the following char:
     * 
     * <pre>
     * UTF4    =  %xF4 %x80-8F 2(UTF0)
     * </pre>
     */
    private static int parseUTF4Third( Position pos, byte u1, byte[] result, int[] bPos ) throws ParseException
    {
        result[bPos[0]++] = u1;

        // UTF4, get the next byte, which must be between 0x80-0xBF
        if ( hasMoreChars( pos ) )
        {
            byte u2 = pos.getByte();
            
            if ( ( u2 >= ( byte ) 0x0080 ) && ( u2 <= ( byte ) 0x00BF ) )
            {
                pos.start++;
                result[bPos[0]++] = u2;

                
                byte u3 = getUTF0( pos, result, bPos );
                byte u4 = getUTF0( pos, result, bPos );
            
                // Convert to unicode: 
                // F4:       1111 0100, Value is 0x04
                // 80 -> 8F: 10[00 0000] - 10[00 1111], mask is 0x0F
                // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
                // 80 -> BF: 10[00 0000] - 10[11 1111], mask is 0x3F
                int i = ( int ) ( ( ( 0x0004 ) << 18 ) 
                        | ( ( u2 & 0x000F ) << 12 ) 
                        | ( ( u3 & 0x003F ) << 6 ) 
                        | ( u4 & 0x003F ) );
                
                return computeSurrogates( i );
            }
            else
            {
                // Error
                byte[] wrongBytes = new byte[] { u1, u2 };
                throw new ParseException( I18n.err( I18n.ERR_13633_INVALID_UTFMB, 
                        Strings.dumpBytes( wrongBytes ) ), pos.start );
            }
        }
        else
        {
            // Error
            byte[] wrongBytes = new byte[] { u1 };
            throw new ParseException( I18n.err( I18n.ERR_13633_INVALID_UTFMB, 
                    Strings.dumpBytes( wrongBytes ) ), pos.start );
        }
    }

    
    /**
     * Parse an UTFMB char:
     * 
     * <pre>
     * UTFMB   = UTF2 / UTF3 / UTF4
     * UTF0    = %x80-BF
     * UTF1    = %x00-7F
     * UTF2    = %xC2-DF UTF0
     * UTF3    = %xE0 %xA0-BF UTF0 / %xE1-EC 2(UTF0) / %xED %x80-9F UTF0 / %xEE-EF 2(UTF0)
     * UTF4    = %xF0 %x90-BF 2(UTF0) / %xF1-F3 3(UTF0) / %xF4 %x80-8F 2(UTF0)
     * </pre> 
     * 
     * Basically:
     * 
     * <ul>
     *   <li>UTF1 is used for chars between 0x0000 and 0x007F</li>
     *   <li>UTF2 is used for chars between 0x0080 and 0x07FF</li>
     *   <li>UTF3 is used for chars between 0x0800 and 0xFFFF</li>
     *   <li>UTF4 is used for chars between 0x10000 and 0x10FFFF, and will be stored in 2 chars</li>
     * </ul>
     * 
     * Note, from RFC 3629:
     * 
     * <pre>
     * The first octet values C0, C1, F5 to FF never appear.
     * C0 (1100 0000) followed by [80-BF] (1000 0000 to 1011 1111) would encode for 0000 0000 
     * to 0011 1111 (0x00 - 0x3F), so are covered by UTF1.
     * C1 (1100 0001) followed by [80-BF] (1000 0000 to 1011 1111) would encode for 0100 0000 
     * to 0111 1111 (0x40 - 0x7F), so are covered by UTF1.
     * </pre>
     * 
     * This can translate into one (UTF2/UTF3) or two (UTF4) chars, so we return an int instead.
     */
    private static int parseUTFMB( Position pos, byte[] result, int[] bPos ) throws ParseException
    {
        byte u1 = pos.getByte();
        pos.start++;

        switch ( u1 )
        {
            // UTF2    = %xC2-DF UTF0
            case ( byte ) 0xC2: case ( byte ) 0xC3: case ( byte ) 0xC4: case ( byte ) 0xC5:
            case ( byte ) 0xC6: case ( byte ) 0xC7: case ( byte ) 0xC8: case ( byte ) 0xC9:
            case ( byte ) 0xCA: case ( byte ) 0xCB: case ( byte ) 0xCC: case ( byte ) 0xCD:
            case ( byte ) 0xCE: case ( byte ) 0xCF: case ( byte ) 0xD0: case ( byte ) 0xD1:
            case ( byte ) 0xD2: case ( byte ) 0xD3: case ( byte ) 0xD4: case ( byte ) 0xD5:
            case ( byte ) 0xD6: case ( byte ) 0xD7: case ( byte ) 0xD8: case ( byte ) 0xD9:
            case ( byte ) 0xDA: case ( byte ) 0xDB: case ( byte ) 0xDC: case ( byte ) 0xDD:
            case ( byte ) 0xDE: case ( byte ) 0xDF:
                char c = parseUTF2( pos, u1, result, bPos );
            
                return c;
                
            // UTF3-1    = %xE0 %xA0-BF UTF0
            case ( byte ) 0xE0:
                return parseUTF3First( pos, u1, result, bPos );

            // UTF3-2    = %xE1-EC 2(UTF0)
            case ( byte ) 0xE1: case ( byte ) 0xE2: case ( byte ) 0xE3: case ( byte ) 0xE4:
            case ( byte ) 0xE5: case ( byte ) 0xE6: case ( byte ) 0xE7: case ( byte ) 0xE8:
            case ( byte ) 0xE9: case ( byte ) 0xEA: case ( byte ) 0xEB: case ( byte ) 0xEC:
                return parseUTF3Second( pos, u1, result, bPos );

            // UTF3    = %xED %x80-9F UTF0
            case ( byte ) 0xED:
                return parseUTF3Third( pos, u1, result, bPos );
 
            // UTF3    = %xEE-EF 2(UTF0)
            case ( byte ) 0xEE: case ( byte ) 0xEF:
                return parseUTF3Forth( pos, u1, result, bPos );

            // UTF4    = %xF0 %x90-BF 2(UTF0)
            case ( byte ) 0xF0:
                return parseUTF4First( pos, u1, result, bPos );

            // UTF4    = %xF1-F3 3(UTF0)
            case ( byte ) 0xF1: case ( byte ) 0xF2: case ( byte ) 0xF3:
                return parseUTF4Second( pos, u1, result, bPos );

            // UTF4    = %xF4 %x80-8F 2(UTF0)
            case ( byte ) 0xF4:
                return parseUTF4Third( pos, u1, result, bPos );
            
            default:
                // This is an error
                byte[] wrongBytes = new byte[] { u1 };
                throw new ParseException( I18n.err( I18n.ERR_13633_INVALID_UTFMB, 
                        Strings.dumpBytes( wrongBytes ) ), pos.start );
        }
    }

    
    /**
     * Parse an attributeValue. The RFC 4514 grammar is:
     * 
     * <pre>
     * attributeValue ::= string? | hexstring
     * hexstring ::= SHARP hexpair hexpair*
     * string ::= ( lutf1 | utfmb | pair ) ( sutf1 | utfmb | pair )* (tutf1 | utfmb | pair)?
     * hexpair ::= HEX HEX
     * 
     * lutf1 ::= '\u0001'..'\u001F' | '\u0021' | '\u0024'..'\u002A' | '\u002D'..'\u003A' |
     *           '\u003D' | '\u003F'..'\u005B' | '\u005D'..'\u007F'
     * sutf1 ::= \u0001'..'\u0021' | '\u0023'..'\u002A' | '\u002D'..'\u003A' |
     *           '\u003D' | '\u003F'..'\u005B' | '\u005D'..'\u007F' 
     * tutf1 ::= '\u0001'..'\u001F' | '\u0021' | '\u0023'..'\u002A' | '\u002D'..'\u003A' |
     *           '\u003D' | '\u003F'..'\u005B' | '\u005D'..'\u007F' 
     * utfmb ::= '\u0080'..'\uFFFE'
     * pair ::= ESCESC | ESCSHARP | ESC special | HEXPAIR
     * ESCESC ::= ESC ESC
     * ESCSHARP ::= ESC SHARP
     * special ::= DQUOTE | PLUS | COMMA | SEMI | LANGLE | RANGLE | SPACE | SHARP | EQUALS
     * HEXPAIR ::= ESC HEX HEX
     * HEXVALUE ::= SHARP ( HEX HEX )+
     * HEX ::= DIGIT | 'a'..'f' | 'A'..'F';
     * NUMBER ::= DIGIT | ( LDIGIT ( DIGIT )+ )
     * DIGIT ::= '0'..'9'
     * LDIGIT ::= '1'..'9'
     * COMMA ::= ',' ('\u002C')
     * DOT ::= '.' ('\u002E')
     * DQUOTE ::= '"' ('\u0022')
     * EQUALS ::= '=' ('\u003D')
     * ESC ::= '\\' ('\u005C')
     * HYPHEN ::= '-' ('\u002D')
     * LANGLE ::= '<' ('\u003C')
     * PLUS ::= '+' ('\u002B')
     * RANGLE ::= '>' ('\u003E')
     * SEMI ::= ';' ('\u003B')
     * SHARP = '#' ('\u0023')
     * SPACE ::= ' ' ('\u0020')
     * UNDERSCORE = '_' ('\u005F')
     * </pre>
     * 
     * Actually, in Java, the String is already converted to an array of unicode
     * chars, so we can simplify the grammar to:
     * 
     * <pre>
     * attributeValue = string | SHARP HEX HEX *(HEX HEX) | e
     * string ::= [(LUTF1/Unicode/pair)[*(SUTF1/Unicode>/pair)(TUTF1/Unicode/pair)]]
     * LUTF1 ::= %x01-1F / %x21 / %x24-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
     * SUTF1 ::= %x01-21 /        %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
     * TUTF1 ::= %x01-1F / %x21 / %x23-2A / %x2D-3A / %x3D / %x3F-5B / %x5D-7F
     * pair ::= ESC(ESC/DQUOTE/PLUS/COMMA/SEMI/LANGLE/RANGLE/SPACE/SHARP/EQUALS/HEX HEX)
     *
     * HEX ::= DIGIT | 'a'..'f' | 'A'..'F';
     * COMMA ::= ',' ('\u002C')
     * DIGIT ::= '0'..'9'
     * DQUOTE ::= '"' ('\u0022')
     * EQUALS ::= '=' ('\u003D')
     * ESC ::= '\\' ('\u005C')
     * LANGLE ::= '<' ('\u003C')
     * PLUS ::= '+' ('\u002B')
     * RANGLE ::= '>' ('\u003E')
     * SEMI ::= ';' ('\u003B')
     * SHARP = '#' ('\u0023')
     * SPACE ::= ' ' ('\u0020')
     * </pre>
     */
    private static Value parseAttributeValue( SchemaManager schemaManager1, AttributeType attributeType,
            Position pos ) throws ParseException, LdapInvalidAttributeValueException
    {
        AttributeValuestates state = AttributeValuestates.START;
                
        // Used to keep a track of the last suite of spaces in the value.
        int spaceNb = 0;
        
        // If the value starts with a '#', we will only have hex pairs
        if ( isMatchChar( ( byte ) SHARP, pos ) ) 
        {
            // It's a hexstring. We can only have pairs of hex
            byte[] valueHex = parseHexString( pos );
            //String upValue = Strings.utf8ToString( pos.getBytes(), start, pos.start - start );
            Value value = null;
            
            if ( attributeType.getSyntax() != null )
            {
                if ( attributeType.isHR() )
                {
                    value = new Value( attributeType, Strings.utf8ToString( valueHex ) );
                }
                else
                {
                    value = new Value( attributeType, valueHex );
                }
            }
            else
            {
                value = new Value( valueHex );
            }
            
            return value;
        }
        
        boolean noValue = true;
        StringBuilder upValue = new StringBuilder();

        byte[] result = new byte[ pos.length << 1 ];
        int[] bPos = new int[1];
        bPos[0] = 0;
        boolean completed = false;
        
        // Not a hexstring, it can be either a string or nothing (empty value)
        while ( hasMoreChars( pos ) && !completed )
        {
            switch ( state )
            {
                case START:
                    byte b = pos.getByte();
                    
                    if ( ( b >= 0 ) && ( b < 0x0080 ) )
                    {
                        // Pure ascii. Some chars aren't allowed in START state
                        switch ( b )
                        {
                            case '\0':
                            case SPACE:
                                // Special case: we skip spaces at the beginning of a value
                                upValue.append( SPACE );
                                result[bPos[0]++] = b;
                                pos.start++;
                                break;

                            case DQUOTE:
                            case SHARP:
                            case LANGLE:
                            case RANGLE:
                                // Forbidden, we will assume the Value is invalid
                                throw new ParseException( I18n.err( 
                                        I18n.ERR_13635_INVALID_VALUE_CHARACTER, ( char ) b ), pos.start );

                            case PLUS:
                            case COMMA:
                            case SEMI_COLON:
                                // Forbidden, we will assume the value is null
                                Value value = new Value( Strings.EMPTY_STRING );

                                return value;
                                
                            case ESC:
                                // stringPair
                                pos.start++;
                                parsePair( pos, upValue, result, bPos );
                                state = AttributeValuestates.STRING_MIDDLE; 
                                
                                break;

                            default:
                                upValue.append( ( char ) b );
                                result[bPos[0]++] = b;
                                state = AttributeValuestates.STRING_MIDDLE;
                                pos.start++;
                                break;
                        }
                    }
                    else
                    {
                        // unicode, parse the UTFMB
                        int utfmb = parseUTFMB( pos, result, bPos );
                        
                        // Can be 2 chars
                        if ( utfmb > 0x0000FFFF )
                        {
                            // 2 chars
                            char c1 = ( char ) ( utfmb >> 16 );
                            char c2 = ( char ) ( utfmb & 0x0000FFFF );
                            
                            upValue.append( c1 );
                            upValue.append( c2 );
                        }
                        else
                        {
                            // 1 char
                            char c = ( char ) ( utfmb & 0x0000FFFF );
                            upValue.append( c );
                        }

                        state = AttributeValuestates.STRING_MIDDLE;
                    }
                    
                    noValue = false;
                    break;
                    
                case STRING_MIDDLE:
                    // Pretty much the same as for the START state, except that '#' is accepted, so is space
                    b = pos.getByte();
                    
                    if ( ( b >= 0 ) && ( b < 0x0080 ) )
                    {
                        // Pure ascii. Some chars aren't allowed in STRING_MIDDLE state
                        switch ( b )
                        {
                            case ' ':
                                // Special case: we keep track of where we have seen spaces
                                // so that we can eliminate them at the end of the value
                                // parsing, because they are not significant. We just want to
                                // keep track of the first space in a suite of spaces.
                                spaceNb++;
                                pos.start++;
                                
                                break;
                                
                            case '\0':
                            case DQUOTE:
                            case PLUS:
                            case COMMA:
                            case SEMI_COLON:
                            case LANGLE:
                            case RANGLE:
                                // Forbidden, we will assume this is the end of the value
                                completed = true;
                                break;
                                
                            case ESC:
                                // Add the previous spaces if needed
                                if ( spaceNb > 0 )
                                {
                                    for ( int i = 0; i < spaceNb; i++ )
                                    {
                                        upValue.append( SPACE );
                                        result[bPos[0]++] = ( byte ) SPACE;
                                    }
                                        
                                    spaceNb = 0;
                                }

                                // stringPair in the middle of a String
                                pos.start++;
                                parsePair( pos, upValue, result, bPos );
                                
                                break;

                            default:
                                // Add the previous spaces if needed
                                if ( spaceNb > 0 )
                                {
                                    for ( int i = 0; i < spaceNb; i++ )
                                    {
                                        upValue.append( SPACE );
                                        result[bPos[0]++] = ( byte ) SPACE;
                                    }
                                        
                                    spaceNb = 0;
                                }

                                upValue.append( ( char ) b );
                                result[bPos[0]++] = b;
                                pos.start++;

                                break;
                        }
                    }
                    else
                    {
                        // UTFMB, get the character in Unicode
                        int utfmb = parseUTFMB( pos, result, bPos );
                        
                        // Add the previous spaces if needed
                        if ( spaceNb > 0 )
                        {
                            for ( int i = 0; i < spaceNb; i++ )
                            {
                                upValue.append( SPACE );
                                result[bPos[0]++] = ( byte ) SPACE;
                            }
                                
                            spaceNb = 0;
                        }

                        // Can be 2 chars
                        if ( utfmb > 0x0000FFFF )
                        {
                            // 2 chars
                            char c1 = ( char ) ( utfmb >> 16 );
                            char c2 = ( char ) ( utfmb & 0x0000FFFF );
                            
                            upValue.append( c1 );
                            upValue.append( c2 );
                        }
                        else
                        {
                            // 1 char
                            char c = ( char ) ( utfmb & 0x0000FFFF );
                            upValue.append( c );
                        }
                        
                        state = AttributeValuestates.STRING_MIDDLE;
                    }
                    
                    noValue = false;
                    
                    break;
                    
                default:
                    // can't be...
            }
        }

        switch ( state )
        {
            case STRING_PAIR_HEX1:
                // We are supposed to have a second hex char
                throw new ParseException( I18n.err( I18n.ERR_13632_WRONG_HEX_PAIR ), pos.start );

            case STRING_PAIR:
                // We are supposed to have some escaped char
                throw new ParseException( I18n.err( I18n.ERR_13631_WRONG_ESCAPED_SEQUENCE ), pos.start );
                
            default:
                // Nothing to do...
        }
        
        if ( noValue )
        {
            if ( ( attributeType != null ) && ( attributeType.getSyntaxOid() != null ) )
            {
                if ( attributeType.isHR() )
                {
                    // A String attribute
                    return new Value( attributeType, Strings.EMPTY_STRING );
                }
                else
                {
                    return new Value( attributeType, Strings.EMPTY_BYTES );
                }
            }
            else
            {
                // By default, we will consider teh value as HR if we don't have an AttributeType
                return new Value( Strings.EMPTY_STRING );
            }
        }
        else
        {
            //String upValueStr = Strings.utf8ToString( pos.getBytes(), start, pos.start - start );
            byte[] realBytes = new byte[ bPos[0] ];
            System.arraycopy( result, 0, realBytes, 0, bPos[0] );

            if ( ( attributeType != null ) && ( attributeType.getSyntaxOid() != null ) )
            {
                if ( attributeType.isHR() )
                {
                    // A String attribute
                    return new Value( attributeType, Strings.utf8ToString( realBytes ) );
                }
                else
                {
                    return new Value( attributeType, realBytes );
                }
            }
            else
            {
                // By default, we will consider teh value as HR if we don't have an AttributeType
                return new Value( Strings.utf8ToString( realBytes ) );
            }
        }
    }

    
    /**
     * Parse an attributeType. The grammar is the following:
     * 
     * <pre>
     * attributeType ::= descr | numericoid
     * descr ::= ALPHA ( ALPHA | DIGIT | HYPHEN | UNDERSCORE )*
     * numericoid ::= NUMERICOID 
     * NUMERICOID ::= ( "oid." )? NUMBER ( DOT NUMBER )+
     * DOT::= '.'
     * NUMBER ::= DIGIT | ( LDIGIT ( DIGIT )+ )
     * LDIGIT ::= '1'..'9'
     * ALPHA ::= 'a'..'z', ‘A’..’Z’
     * DIGIT ::= '0'..'9'
     * HYPHEN ::= '-'555567
     * UNDERSCORE ::= '_'
     * </pre>
     * 
     * It will use the following state machine:
     * <pre>
     * START --[a..zA..Z] / [oO]--> S1
     * START --[1..9]--> S2
     * START --'0'--> S3
     * START --[oO]--> S4
     * S1 --[a..zA..Z0..9-_]--> S1
     * S1 --![a..zA..Z0..9-_]--> END
     * S2 --[0..9]--> S2
     * S2 --![0..9]--> error
     * S2 --'.'--> S7
     * S3 --'.'--> S7
     * S3 --!'.'--> error
     * S4 --[iI]--> S5
     * S4 --[a..zA..Z0..9-_]/[iI]--> S1
     * S4 --![a..zA..Z0..9-_]--> END
     * S5 --[dD]--> S6
     * S5 --[a..zA..Z0..9-_]/[dD]--> S1
     * S5 --![a..zA..Z0..9-_]--> END
     * S6 --'.'--> S7
     * S6 --[a..zA..Z0..9-_]/'.'--> S1
     * S6 --![a..zA..Z0..9-_.]--> END
     * S7 --'0'-->S8
     * S7 --[1..9]--> S9
     * S7 --![0..9]--> error
     * S8 --'.'--> S7
     * S8 --!'.'--> error
     * S9 --[0..9] -> S9
     * S9 --'.'--> S7
     * S9 --![0..9.]--> end
     * </pre>
     */
    private static String parseAttributeType( Position pos ) throws ParseException
    {
        AttributTypeStates state = AttributTypeStates.START;
        
        int start = pos.start;
        
        while ( hasMoreChars( pos ) )
        {
            switch ( state )
            {
                case START:
                    // We may have either a 'O', 'o' or an ALPHA (but 'o' or 'O') 
                    // or a NUMBER
                    byte b = pos.getByte();
                    
                    switch ( b )
                    {
                        case '0':
                            // A numeric OID
                            state = AttributTypeStates.STATE_3;
                            pos.start++;
                            
                            break;

                        case '1': case '2': case '3': case '4': case '5': 
                        case '6': case '7': case '8': case '9':
                            // Numeric oid again
                            state = AttributTypeStates.STATE_2;
                            pos.start++;
                            
                            break;

                        case 'o': case 'O':
                            // An 'oid.' start?
                            state = AttributTypeStates.STATE_4;
                            pos.start++;
                            
                            break;
                            
                        case 'a': case 'b': case 'c': case 'd': case 'e': 
                        case 'f': case 'g': case 'h': case 'i': case 'j': 
                        case 'k': case 'l': case 'm': /* no 'o' */case 'n':
                        case 'p': case 'q': case 'r': case 's': case 't': 
                        case 'u': case 'v': case 'w': case 'x': case 'y': 
                        case 'z': case 'A': case 'B': case 'C': case 'D': 
                        case 'E': case 'F': case 'G': case 'H': case 'I': 
                        case 'J': case 'K': case 'L': case 'M': case 'N': 
                        /* no 'O' */case 'P': case 'Q': case 'R': case 'S': 
                        case 'T': case 'U': case 'V': case 'W': case 'X': 
                        case 'Y': case 'Z': case '-': case '_':
                            // A descr
                            state = AttributTypeStates.STATE_1;
                            pos.start++;
                            
                            break;
                        
                        default:
                            // Not an attributeType...
                            LOG.debug( "Cannot parse an attributeType at {}", pos );
                            
                            return "";
                    }
                    
                    break;
                    
                case STATE_1:
                    // We may have either an ALPHA or a NUMBER, or '-' or '_'
                    b = pos.getByte();
                    
                    switch ( b )
                    {
                        case '0': case '1': case '2': case '3': case '4': 
                        case '5': case '6': case '7': case '8': case '9':
                        case 'a': case 'b': case 'c': case 'd': case 'e': 
                        case 'f': case 'g': case 'h': case 'i': case 'j': 
                        case 'k': case 'l': case 'm': case 'o': case 'n':
                        case 'p': case 'q': case 'r': case 's': case 't': 
                        case 'u': case 'v': case 'w': case 'x': case 'y': 
                        case 'z': case 'A': case 'B': case 'C': case 'D': 
                        case 'E': case 'F': case 'G': case 'H': case 'I': 
                        case 'J': case 'K': case 'L': case 'M': case 'N': 
                        case 'O': case 'P': case 'Q': case 'R': case 'S': 
                        case 'T': case 'U': case 'V': case 'W': case 'X': 
                        case 'Y': case 'Z': case '-': case '_':
                            // A descr continuation
                            state = AttributTypeStates.STATE_1;
                            pos.start++;
                            
                            break;
                        
                        default:
                            // The end, return the found attributeType
                            String attributType = Strings.utf8ToString( pos.getBytes(), start, pos.start - start );
                            LOG.debug( "Parsed attributeType '{}'", attributType );
                            
                            return attributType;
                    }
                    
                    break;

                case STATE_2:
                    b = pos.getByte();
                    
                    switch ( b )
                    {
                        case '0': case '1': case '2': case '3': case '4': 
                        case '5': case '6': case '7': case '8': case '9':
                            // Numeric oid or descr, we don't know yet
                            state = AttributTypeStates.STATE_2;
                            pos.start++;
                            
                            break;
                            
                        case '.':
                            // Definitively numericOid
                            state = AttributTypeStates.STATE_7;
                            pos.start++;
                            
                            break;
                            
                        default:
                            // We should have at least another '.' and number
                            String attributType = Strings.getString( 
                                    pos.getBytes(), start, pos.start - start, StandardCharsets.UTF_8 );
                            LOG.error( "Wrong attributeType '{}' at {}", attributType, pos );
                            
                            throw new ParseException( 
                                    I18n.err( I18n.ERR_13630_BAD_OID_ATTRIBUTE_TYPE, pos ), pos.start );
                    }
                    
                    break;

                case STATE_3:
                    b = pos.getByte();
                    pos.start++;
                    
                    if ( b == '.' )
                    {
                        // An NUMERICOID starting with '0.'
                        state = AttributTypeStates.STATE_7;
                    }
                    else
                    {
                        // We should have at least another '.' and number
                        String attributType = Strings.getString( 
                                pos.getBytes(), start, pos.start - start, StandardCharsets.UTF_8 );
                        LOG.error( "Wrong attributeType '{}' at {}", attributType, pos );
                        
                        throw new ParseException( 
                                I18n.err( I18n.ERR_13630_BAD_OID_ATTRIBUTE_TYPE, pos ), pos.start );
                    }
                    
                    break;
                    
                case STATE_4:
                    // We may have either an ALPHA but 'i' or 'I',  or a NUMBER, 
                    // or '-' or '_' or 'i' or 'I'
                    b = pos.getByte();
                    
                    switch ( b )
                    {
                        case 'i': case 'I':
                            // An 'oid.' start?
                            state = AttributTypeStates.STATE_5;
                            pos.start++;
                            
                            break;
                    
                        case '0': case '1': case '2': case '3': case '4': 
                        case '5': case '6': case '7': case '8': case '9':
                        case 'a': case 'b': case 'c': case 'd': case 'e': 
                        case 'f': case 'g': case 'h': /* not 'i' */ case 'j': 
                        case 'k': case 'l': case 'm': case 'o': case 'n':
                        case 'p': case 'q': case 'r': case 's': case 't': 
                        case 'u': case 'v': case 'w': case 'x': case 'y': 
                        case 'z': case 'A': case 'B': case 'C': case 'D': 
                        case 'E': case 'F': case 'G': case 'H': /* not 'I' */ 
                        case 'J': case 'K': case 'L': case 'M': case 'N': 
                        case 'O': case 'P': case 'Q': case 'R': case 'S': 
                        case 'T': case 'U': case 'V': case 'W': case 'X': 
                        case 'Y': case 'Z': case '-': case '_':
                            // A descr continuation
                            state = AttributTypeStates.STATE_1;
                            pos.start++;
                            
                            break;
                        
                        default:
                            // the descr is just 'o' or 'O'
                            String attributType = Strings.getString( 
                                    pos.getBytes(), start, pos.start - start, StandardCharsets.UTF_8 );
                            LOG.debug( "Parsed attributeType '{}'", attributType );
                            
                            return attributType;
                    }
                    
                    break;

                case STATE_5:
                    // We may have either an ALPHA but 'd' or 'D',  or a NUMBER, 
                    // or '-' or '_', or 'd' or 'D'
                    b = pos.getByte();
                    
                    switch ( b )
                    {
                        case 'd': case 'D':
                            // An 'oid.' start?
                            state = AttributTypeStates.STATE_6;
                            pos.start++;
                            
                            break;
                    
                        case '0': case '1': case '2': case '3': case '4': 
                        case '5': case '6': case '7': case '8': case '9':
                        case 'a': case 'b': case 'c': /* not 'd' */ case 'e': 
                        case 'f': case 'g': case 'h': case 'i': case 'j': 
                        case 'k': case 'l': case 'm': case 'o': case 'n':
                        case 'p': case 'q': case 'r': case 's': case 't': 
                        case 'u': case 'v': case 'w': case 'x': case 'y': 
                        case 'z': case 'A': case 'B': case 'C': /* not 'D' */ 
                        case 'E': case 'F': case 'G': case 'H': case 'I':
                        case 'J': case 'K': case 'L': case 'M': case 'N': 
                        case 'O': case 'P': case 'Q': case 'R': case 'S': 
                        case 'T': case 'U': case 'V': case 'W': case 'X': 
                        case 'Y': case 'Z': case '-': case '_':
                            // A descr continuation
                            state = AttributTypeStates.STATE_1;
                            pos.start++;
                            
                            break;
                        
                        default:
                            // the descr is just '[oO][iI]' 
                            String attributType = Strings.getString( 
                                    pos.getBytes(), start, pos.start - start, StandardCharsets.UTF_8 );
                            LOG.debug( "Parsed attributeType '{}'", attributType );
                            
                            return attributType;
                    }
                    
                    break;

                case STATE_6:
                    // We may have either an ALPHA or a NUMBER, 
                    // or '-' or '_', or '.'
                    b = pos.getByte();
                    
                    switch ( b )
                    {
                        case '.':
                            // An 'oid.' start?
                            state = AttributTypeStates.STATE_7;
                            pos.start++;
                            
                            break;
                    
                        case '0': case '1': case '2': case '3': case '4': 
                        case '5': case '6': case '7': case '8': case '9':
                        case 'a': case 'b': case 'c': case 'd': case 'e': 
                        case 'f': case 'g': case 'h': case 'i': case 'j': 
                        case 'k': case 'l': case 'm': case 'o': case 'n':
                        case 'p': case 'q': case 'r': case 's': case 't': 
                        case 'u': case 'v': case 'w': case 'x': case 'y': 
                        case 'z': case 'A': case 'B': case 'C': case 'D': 
                        case 'E': case 'F': case 'G': case 'H': case 'I':
                        case 'J': case 'K': case 'L': case 'M': case 'N': 
                        case 'O': case 'P': case 'Q': case 'R': case 'S': 
                        case 'T': case 'U': case 'V': case 'W': case 'X': 
                        case 'Y': case 'Z': case '-': case '_':
                            // A descr continuation
                            state = AttributTypeStates.STATE_1;
                            pos.start++;
                            
                            break;
                        
                        default:
                            // the descr is just '[oO][iI][dD]' 
                            String attributType = Strings.getString( 
                                    pos.getBytes(), start, pos.start - start, StandardCharsets.UTF_8 );
                            LOG.debug( "Parsed attributeType '{}'", attributType );
                            
                            return attributType;
                    }
                    
                    break;

                case STATE_7:
                    b = pos.getByte();
                    
                    switch ( b )
                    {
                        case '0': 
                            state = AttributTypeStates.STATE_8;
                            pos.start++;
                            
                            break;

                        case '1': case '2': case '3': case '4': case '5': 
                        case '6': case '7': case '8': case '9':
                            state = AttributTypeStates.STATE_9;
                            pos.start++;
                            
                            break;
                            
                        default:
                            // We should have at least another '.' and number
                            String attributType = Strings.getString( 
                                    pos.getBytes(), start, pos.start - start, StandardCharsets.UTF_8 );
                            LOG.error( "Wrong attributeType '{}' at {}", attributType, pos );
                            
                            throw new ParseException( 
                                    I18n.err( I18n.ERR_13630_BAD_OID_ATTRIBUTE_TYPE, pos ), pos.start );
                    }
                    
                    break;

                case STATE_8:
                    b = pos.getByte();

                    if ( b == DOT )
                    {
                        state = AttributTypeStates.STATE_7;
                        pos.start++;
                        
                        break;
                    }
                    else
                    {
                        // Then end, the numericOID is complete
                        String attributType = Strings.getString( 
                                pos.getBytes(), start, pos.start - start, StandardCharsets.UTF_8 );
                        LOG.debug( "Parsed attributeType '{}'", attributType );
                        
                        return attributType;
                    }
                    
                case STATE_9:
                    b = pos.getByte();
                    
                    switch ( b )
                    {
                        case '0': case '1': case '2': case '3': case '4': 
                        case '5': case '6': case '7': case '8': case '9':
                            state = AttributTypeStates.STATE_9;
                            pos.start++;
                            
                            break;
                            
                        case '.':
                            state = AttributTypeStates.STATE_7;
                            pos.start++;
                            
                            break;
                            
                        default:
                            // The end, the numericOID is complete
                            String attributType = Strings.getString( 
                                    pos.getBytes(), start, pos.start - start, StandardCharsets.UTF_8 );
                            LOG.debug( "Parsed attributeType '{}'", attributType );
                            
                            return attributType;
                    }
                    
                    break;
                    
                default: 
                    // Can't be...
            }
        }
        
        // Depending on the current state, the end of stream might correspond to an error
        switch ( state )
        {
            case START:
                // Not an attributeType...
                LOG.debug( "Cannot parse an attributeType at {}", pos );
                return "";

            case STATE_1:
            case STATE_4:
            case STATE_5:
            case STATE_6:
            case STATE_9:
            case STATE_8:
               // The end, return the found attributeType
                String attributType = Strings.getString( 
                        pos.getBytes(), start, pos.start - start, StandardCharsets.UTF_8 );
                LOG.debug( "Parsed attributeType '{}'", attributType );
                
                return attributType;

            case STATE_2:
            case STATE_3:
                // We should have at least another '.' and number
                attributType = Strings.getString( 
                        pos.getBytes(), start, pos.start - start, StandardCharsets.UTF_8 );
                LOG.error( "Wrong attributeType '{}' at {}", attributType, pos );
                
                throw new ParseException( I18n.err( I18n.ERR_13630_BAD_OID_ATTRIBUTE_TYPE, attributType ), pos.start );

            case STATE_7:
                // We should have at least another '.' and number
                attributType = Strings.getString( 
                        pos.getBytes(), start, pos.start - start, StandardCharsets.UTF_8 );
                LOG.error( "Wrong attributeType '{}' at {}", attributType, pos );
                
                throw new ParseException( 
                        I18n.err( I18n.ERR_13630_BAD_OID_ATTRIBUTE_TYPE, pos ), pos.start );

            default:
                return "";
        }
    }

    
    /**
     * Parse an AttributeType and Value. The grammar is the following:
     * 
     * <pre>
     * attributeTypeAndValue ::=
     *   ( SPACE )* attributeType ( SPACE )* EQUALS ( SPACE )* attributeValue ( SPACE )*
     * </pre>
     */
    private static Ava parseAttributeTypeAndValue( SchemaManager schemaManager, byte[] bytes,
            Position pos ) throws LdapInvalidDnException, ParseException, LdapInvalidAttributeValueException
    {
        AttributeType attributeType = null;
        StringBuilder upName = new StringBuilder();
        
        int start = pos.start;

        // ( SPACE )*
        while ( isMatchChar( ( byte ) SPACE, pos ) )
        {
            upName.append( SPACE );
        }
        
        // attributeType
        String type = parseAttributeType( pos );
        
        if ( Strings.isEmpty( type ) )
        {
            // If we don't have a type, it's an error
            throw new LdapInvalidDnException( I18n.err( I18n.ERR_13622_DN_OR_RDN_NULL, pos ) );
        }
                    
        upName.append( type );
        
        if ( schemaManager != null )
        {
            String realType = type;
            
            // Special case for oid.xxx attributeType
            if ( Strings.toLowerCaseAscii( type ).startsWith( "oid." ) )
            {
                realType = type.substring( 4 );
            }

            attributeType = schemaManager.getAttributeType( realType );
        }
        else
        {
            attributeType = new AttributeType( type );
        }
        
        // ( SPACE )*
        while ( isMatchChar( ( byte ) SPACE, pos ) )
        {
            upName.append( SPACE );
        }
        
        // EQUALS
        matchChar( bytes, ( byte ) EQUAL, pos );
        upName.append( EQUAL );
                
        // ( SPACE )*
        while ( isMatchChar( ( byte ) SPACE, pos ) )
        {
            upName.append( SPACE );
        }

        start = pos.start;

        // And now, the value
        Value value = parseAttributeValue( schemaManager, attributeType, pos );

        String upValue = Strings.utf8ToString( bytes, start, pos.start - start );
        
        Ava ava = new Ava( schemaManager, type,  Strings.lowerCaseAscii( Strings.trim( type ) ), value );
        upName.append( upValue );
        ava.upName = upName.toString();
        
        return ava;
    }


    /**
     * Parse a RDN. The grammar is the following:
     * <pre>
     * relativeDistinguishedName ::=
     *     attributeTypeAndValue ( PLUS attributeTypeAndValue )*
     * </pre>
     */
    private static void parseRelativeDistinguishedName( SchemaManager schemaManager, byte[] bytes, Rdn rdn, 
            Position pos ) throws LdapInvalidDnException, ParseException, LdapInvalidAttributeValueException
    {
        StringBuilder rdnUpStr = new StringBuilder();
        StringBuilder rdnNormStr = new StringBuilder();

        // The list of parsed Ava for a later post-processing, if needed
        boolean isFirst = true;
        Ava ava = null;

        while ( hasMoreChars( pos ) )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                if ( isMatchChar( ( byte ) PLUS, pos ) )
                {
                    rdnUpStr.append( PLUS );
                    rdn.avas = Rdn.addOrdered( rdn.avas, ava );
                    ava = null;
                }
                else
                {
                    // No more AVA
                    break;
                }
            }
            
            ava = parseAttributeTypeAndValue( schemaManager, bytes, pos );
            
            rdn.nbAvas++;
            rdnUpStr.append( ava.getName() );
        }
        
        if ( rdn.nbAvas > 1 )
        {
            rdn.avas = Rdn.addOrdered( rdn.avas, ava );
        }
        else
        {
            rdn.ava = ava;
        }
        
        // Now, build the Rdn
        switch ( rdn.nbAvas )
        {
            case 0:
                // Can't be...
                
            case 1:
                // One single Ava
                rdn.upName = rdnUpStr.toString();
                rdn.normName = createNormAva( rdn.ava );
                rdn.avaType = rdn.ava.getType();
                break;

            default:
                rdn.ava = null;                
                rdn.upName = rdnUpStr.toString();
                rdn.avaTypes = new HashMap<String, List<Ava>>();
                isFirst = true;

                for ( Ava parsedAva : rdn.avas )
                {
                    if ( isFirst  )
                    {
                        isFirst = false;
                    }
                    else
                    {
                        rdnNormStr.append( PLUS );
                    }

                    String type;

                    if ( schemaManager != null )
                    {
                        // TODO: what if parsedAva.getAttributeType() returns null?
                        type = parsedAva.getAttributeType().getOid();
                    }
                    else
                    {
                        type = parsedAva.normType;
                    }

                    rdnNormStr.append( createNormAva( parsedAva ) );

                    List<Ava> avaList = rdn.avaTypes.get( type );

                    if ( avaList == null )
                    {
                        avaList = new ArrayList<>();
                    }

                    avaList.add( parsedAva );
                    rdn.avaTypes.put( type, avaList );
                }

                rdn.normName = rdnNormStr.toString();

                break;
        }

        rdn.hashCode();
    }


    /**
     * Parses an Rdn.
     * 
     * @param schemaManager The SchemaManager
     * @param name the string representation of the relative distinguished name
     * @param rdn the (empty) Rdn where parsed ATAVs are put into
     * 
     * @throws LdapInvalidDnException the invalid name exception
     */
    /* No protection*/static void parseRdn( SchemaManager schemaManager, String name, Rdn rdn ) throws LdapInvalidDnException
    {
        if ( Strings.isNotEmpty( name ) )
        {
            try
            {
                // First convert the String to an UTF-8 byte[]
                byte[] bytes = Strings.getBytesUtf8( name );
                
                parseRdn( schemaManager, bytes, rdn );
            }
            catch ( Exception e )
            {
                throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, e.getMessage(), e );
            }
        }
    }


    /**
     * Parses an Rdn.
     * 
     * @param schemaManager The SchemaManager
     * @param name the string representation of the relative distinguished name
     * @param rdn the (empty) Rdn where parsed ATAVs are put into
     * 
     * @throws LdapInvalidDnException the invalid name exception
     */
    /* No protection*/static void parseRdn( SchemaManager schemaManager, byte[] bytes, Rdn rdn ) throws LdapInvalidDnException
    {
        try
        {
            Position pos = new Position( bytes );
            pos.length = bytes.length;
            
            // We must have a following RDN, let's parse it
            parseRelativeDistinguishedName( schemaManager, bytes, rdn, pos );
        }
        catch ( Exception e )
        {
            throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, e.getMessage(), e );
        }
    }
    
    
    /**
     * Parse the following grammar:
     * <pre>
     * distinguishedName :== [ relativeDistinguishedName
          *( COMMA relativeDistinguishedName ) ]
     * </pre>
     * 
     * @param schemaManager The SchemaManager instance. May be null
     * @param bytes The DN to parse, stored in a byte[]
     * @param rdns 
     * @return
     * @throws LdapInvalidDnException
     */
    /* no protection */static String parseDn( SchemaManager schemaManager, byte[] bytes, List<Rdn> rdns ) 
            throws LdapInvalidDnException
    {
        if ( Strings.isEmpty( bytes ) )
        {
            return Strings.EMPTY_STRING;
        }
        
        try
        {
            Position pos = new Position( bytes );
            pos.length = bytes.length;
            
            StringBuilder dnNormSb = new StringBuilder();
            boolean isFirst = true;
            
            while ( hasMoreChars( pos ) )
            {
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    // We accept ',' (RFC 2253/4514 form) or ';' (RFC 1779 form) 
                    // as a separator between RDNs
                    if ( isMatchChar( ( byte ) COMMA, pos ) || isMatchChar( ( byte ) SEMI_COLON, pos ) )
                    {
                        // Add the parsed RDN to the RDN list
                        dnNormSb.append( COMMA );
                    }
                    else
                    {
                        // The end...
                        break;
                    }
                }

                // We must have a following RDN, let's parse it
                Rdn rdn = new Rdn( schemaManager );
                parseRelativeDistinguishedName( schemaManager, bytes, rdn, pos );
                
                rdns.add( rdn ); 
                dnNormSb.append( rdn.getNormName() );
            }
            
            // No more char, return the normalized dn
            return dnNormSb.toString();
        }
        catch ( Exception e )
        {
            throw new LdapInvalidDnException( ResultCodeEnum.INVALID_DN_SYNTAX, e.getMessage(), e );
        }
    }

    
    /* no protection */static String parseDn( SchemaManager schemaManager, String upName, List<Rdn> rdns ) 
            throws LdapInvalidDnException
    {
        if ( ( upName == null ) || Strings.isEmpty( upName.trim() ) )
        {
            return Strings.EMPTY_STRING;
        }
        
        byte[] bytes = Strings.getBytesUtf8( upName );
        
        return parseDn( schemaManager, bytes, rdns );
    }

    
    /**
     * Parses a Dn from a String
     *
     * @param name The Dn to parse
     * @return A valid Dn
     * @throws org.apache.directory.api.ldap.model.exception.LdapException If the Dn was invalid
     */
    /* No protection*/static Dn parseDn( String name ) throws LdapException
    {
        Dn dn = new Dn();
        String normName = parseDn( null, name, dn.rdns );
        dn.setUpName( name );
        dn.setNormName( normName );
        
        return dn;
    }
}
