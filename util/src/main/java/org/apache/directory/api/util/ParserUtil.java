/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.util;

import java.text.ParseException;

import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;

/**
 * An utility class used when parsing some of LDAP elements
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class ParserUtil 
{
    /** Define two constants for optional or mandatory elements */
    public static final boolean ZERO_N = true;
    public static final boolean ONE_N = false;

    /** The various found characters */
    public static final char COLON      = ':';
    public static final char DOLLAR     = '$';
    public static final char DOT        = '.';
    public static final char DQUOTE     = '"';
    public static final char EQUAL      = '=';
    public static final char HYPHEN     = '-';
    public static final char LCURLY     = '{';
    public static final char LPAREN     = '(';
    public static final char RCURLY     = '}';
    public static final char RPAREN     = ')';
    public static final char SEMI_COLON = ';';
    public static final char SEP        = ',';
    public static final char USCORE     = '_';
    public static final char ZERO       = '0';

    /** A terminaison token. It's not in the grammar */
    public static final String END = "END";
    
    /**
     * A private constructor for this static class
     */
    private ParserUtil()
    {
    }

    /**
     * Checks if there are more characters.
     * 
     * @param pos the pos
     * 
     * @return <code>true</code> if more characters are available
     */
    public static boolean hasMoreChars( Position pos )
    {
        return pos.start < pos.length;
    }
    
    
    /**
     * Skip spaces at the current position of the string. It may require
     * a first space to be present, or not.
     * 
     * @param str The string to process
     * @param pos The current position in the string
     * @param optional A flag indication if at least one space must be present
     * @return <code>true</code> if some space were removed, <code>false</code> otherwise
     */
    public static boolean skipSpaces( String str, Position pos, boolean optional )
    {
        while ( hasMoreChars( pos ) )
        {
            char c = str.charAt( pos.start );
            
            switch ( c )
            {
                case ' ':
                case '\t':
                case '\r':
                case '\n':
                    pos.start++;
                    optional = true;
                    break;
                    
                default: 
                    return optional;
            }
        }
        
        return optional;
    }
    
    
    /**
     * Parse an integer
     * <pre>
     *   INTEGER: DIGIT | ( LDIGIT ( DIGIT )+ ) 
     *   DIGIT: '0' | LDIGIT 
     *   LDIGIT: '1'..'9'
     * </pre>
     * 
     * @param str The string to process
     * @param pos The current position in the string
     * @throws ParseException If the parsed integer overflows (2^32-1) or we don't have any digit
     * @return The parsed integer
     */
    public static int parseInteger( String str, Position pos ) throws ParseException
    {
        if ( isMatchChar( str, ZERO, pos ) )
        {
            // This is only allowed if we have one single digit
            if ( hasMoreChars( pos ) && !Chars.isDigit( str.charAt( pos.start ) ) )
            {
                // Ok, the next char is not a digit
                return 0;
            }
            else
            {
                // This is an error: either we have digits following, or the Subtree
                // specification string is empty (ie a '}' is required)
                throw new ParseException( 
                        I18n.err( I18n.ERR_17078_INVALID_INTEGER_STARTING_WITH_ZERO ), pos.start );
            }
        }
        
        int integer = str.charAt( pos.start ) - '0';
        pos.start++;

        while ( hasMoreChars( pos ) )
        {
            char c = str.charAt( pos.start );
            
            if ( ( c >= '0' ) && ( c <= '9' ) )
            {
                if ( integer > ( Integer.MAX_VALUE / 10 ) )
                {
                    // We will overflow...
                    throw new ParseException( 
                            I18n.err( I18n.ERR_17079_OVERFLOWN_INTEGER, 
                                    Long.toString( integer ) + c ), pos.start );
                }
                
                integer = integer * 10 + ( c - '0' );
            }
            else
            {
                // We are done
                break;
            }
            
            pos.start++;
        }
        
        return integer;
    }

    
    /**
     * Skip any comments at the beginning of a string
     * 
     * @param str The string to process
     * @param pos The current position in the string
     * @return <code>true</code> if a comment has been removed, <code>false</code> otherwise
     */
    public static boolean skipComment( String str, Position pos )
    {
        // If the line starts with a #, skip it
        skipSpaces( str, pos, ZERO_N );
        
        if ( hasMoreChars( pos ) && ( str.charAt( pos.start ) == '#' ) )
        {
            pos.start++;
            
            while ( hasMoreChars( pos ) )
            {
                char c = str.charAt( pos.start );
                pos.start++;
                
                if ( c == '\n' )
                {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    
    /**
     * Match a specific character at the current position in the string.
     * If present, move forward the current position.
     * 
     * @param str The string to process
     * @param c The expected character
     * @param pos The current position in the string
     * @throws ParseException If the required character is not found at current position
     */
    public static void matchChar( String str, char c, Position pos ) throws ParseException
    {
        if ( !hasMoreChars( pos ) || str.charAt( pos.start ) != c )
        {
            throw new ParseException( I18n.err( I18n.ERR_17073_CHAR_REQUIRED, c ), pos.start );
        }
        
        pos.start++;
    }
    
    
    /**
     * Check if a specific character is present at the current position in the string.
     * If the character is found, the position will be moved forward.
     * 
     * @param schema The string to process
     * @param c The expected character
     * @param pos The current position in the string
     * @return <code>true</code> if the character is present at the current position,
     * <code>false</code> if the character is not present or if we are at the end of the string.
     */
    public static boolean isMatchChar( String str, char c, Position pos )
    {
        if ( !hasMoreChars( pos ) || str.charAt( pos.start ) != c )
        {
            return false;
        }
        
        pos.start++;
        
        return true;
    }


    /**
     * Parse a Numeric OID, which grammar is:
     * 
     * <pre>
     *   DIGIT   = %x30 / LDIGIT       ; "0"-"9"
     *   LDIGIT  = %x31-39             ; "1"-"9"
     *   DOT     = %x2E ; period (".")
     *   number  = DIGIT / ( LDIGIT 1*DIGIT )
     *   numericoid = number 1*( DOT number )
     * </pre>
     * 
     * @param str The string to parse
     * @param pos The current position in the string
     * @return The parsed NumericOid
     */
    public static String parseNumericOid( String str, Position pos ) throws ParseException
    {
        int start = pos.start;
        
        while ( hasMoreChars( pos ) 
                && ( Chars.isAlphaDigit( str, pos.start ) 
                        || Chars.isCharASCII( str, pos.start, DOT ) ) )
        {
            pos.start++;
        }
        
        String oid = str.substring( start, pos.start );
        
        return oid;
    }

    
    /**
     * Get a token (which is a suite of alphabetic or dash characters
     * prefixed with a '$'
     * 
     * @param str The string to parse
     * @param pos The current position in the string
     * @return The found token
     */
    public static String getDollarToken( String str, Position pos )
    {
        int start = pos.start;
        
        if ( hasMoreChars( pos ) && ( str.charAt( pos.start ) == DOLLAR ) )
        {
            pos.start++;
        }
        else
        {
            return "";
        }
        
        while ( hasMoreChars( pos ) )
        {
            char c = str.charAt( pos.start );
            
            if ( Chars.isAlpha( c ) || ( c == HYPHEN ) || ( c == USCORE ) )
            {
                pos.start++;
            }
            else
            {
                break;
            }
        }
        
        if ( start == pos.start )
        {
            // Nothing to read: the end
            return END;
        }
        
        return str.substring( start, pos.start );
    }

    
    /**
     * Get a token (which is a suite of alphabetic or dash characters
     * 
     * @param schema The schema to parse
     * @param pos The current position in the schema
     * @return The found token
     */
    public static String getToken( String schema, Position pos )
    {
        int start = pos.start;
        
        while ( hasMoreChars( pos ) )
        {
            char c = schema.charAt( pos.start );
            
            if ( Chars.isAlpha( c ) || ( c == HYPHEN ) || ( c == USCORE ) )
            {
                pos.start++;
            }
            else
            {
                break;
            }
        }
        
        if ( start == pos.start )
        {
            // Nothing to read: the end
            return END;
        }
        
        return schema.substring( start, pos.start );
    }

    
    /**
     * Parse the Descr, following this grammar:
     * 
     * <pre>
     *   ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
     *   DIGIT   = %x30 / LDIGIT       ; "0"-"9"
     *   LDIGIT  = %x31-39             ; "1"-"9"
     *   HYPHEN  = %x2D ; hyphen ("-")
     *   keychar = ALPHA / DIGIT / HYPHEN
     *   leadkeychar = ALPHA
     *   keystring = leadkeychar *keychar
     *   descr = keystring
     * </pre>
     * 
     * @param str The str to parse
     * @param pos The current position in the string
     * @return The found descr
     * @throws ParseException If there is a missing starting or ending quote, or if the descr is wrong
     **/
    public static String parseDescr( String str, Position pos ) throws ParseException
    {
        int start = pos.start;
                
        if ( !hasMoreChars( pos ) || !Chars.isAlpha( str.charAt( pos.start ) ) )
        {
            throw new ParseException( 
                    I18n.err( I18n.ERR_17074_DESCR_INCORRECT_FIRST_CHAR, str.charAt( pos.start ) ), pos.start );
        }
        
        pos.start++;
        
        while ( hasMoreChars( pos ) )
        {
            char c = str.charAt( pos.start );
            
            if ( !Chars.isAlphaDigitMinus( c ) )
            {
                break;
            }
            
            pos.start++;
        }

        String qdescr = str.substring( start, pos.start );
        
        return qdescr;
    }

    
    /**
     * Parse an oid.
     * It follows this grammar:
     * 
     * <pre>
     *   numericoid = number 1*( DOT number )
     *   number  = DIGIT / ( LDIGIT 1*DIGIT )
     *   DIGIT   = %x30 / LDIGIT       ; "0"-"9"
     *   LDIGIT  = %x31-39             ; "1"-"9"
     *   descr = keystring
     *   keystring = leadkeychar *keychar
     *   leadkeychar = ALPHA
     *   keychar = ALPHA / DIGIT / HYPHEN
     *   ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
     *   DIGIT   = %x30 / LDIGIT       ; "0"-"9"
     *   HYPHEN  = %x2D ; hyphen ("-")
     *   oid = descr / numericoid
     * </pre>
     * 
     * The only difference between a descr and a OID is that descr starts with a letter
     * while an OID starts with a digit.
     * 
     * @param str The schema to parse
     * @param pos The current position in the schema
     * @return The found oid
     * @throws ParseException If the oid is incorrect 
     */
    public static String parseOid( String str, Position pos ) throws ParseException
    {
        // There might be some spaces
        skipSpaces( str, pos, ZERO_N );
        
        if ( Chars.isDigit( str.charAt( pos.start ) ) )
        {
            int start = pos.start;
            
            // A numeric OID
            String numericOid = parseNumericOid( str, pos );
            
            if ( !Oid.isOid( numericOid ) )
            {
                throw new ParseException( I18n.err( I18n.ERR_15008_OID_REQUIRED, numericOid ), start );
            }
               
            return numericOid;
        }
        else
        {
            // This is a descr
            String descr = parseDescr( str, pos );

            return descr;
        }
    }

    
    /**
     * Parse a DistinguishedName, following this grammar:
     * 
     * <pre>
     *   StringValue       = dquote *SafeUTF8Character dquote
     *   dquote            = %x22 ; " (double quote)
     *   SafeUTF8Character = %x00-21 / %x23-7F /   ; ASCII minus dquote
     *                       dquote dquote /       ; escaped double quote
     *                       %xC0-DF %x80-BF /     ; 2 byte UTF-8 character
     *                       %xE0-EF 2(%x80-BF) /  ; 3 byte UTF-8 character
     *                       %xF0-F7 3(%x80-BF)    ; 4 byte UTF-8 character
     * </pre>
     * 
     * @param str The string to parse
     * @param pos The current position in the string
     * @return The found DN string
     * @throws ParseException If there is a missing starting or ending dquote, or if the DN is incorrect
     **/
    public static String parseQuotedSafeUtf8( String str, Position pos ) throws ParseException
    {
        // We get the DN, which is double quoted. 
        matchChar( str, DQUOTE, pos );
        
        StringBuilder dnStr = new StringBuilder();
        int start = pos.start;
        
        while ( hasMoreChars( pos ) )
        {
            char c = str.charAt( pos.start );
            
            if ( Character.isHighSurrogate( c ) )
            {
                // Multibytes char
                pos.start++;
                
                if ( !hasMoreChars( pos ) )
                {
                    // This is an error
                    throw new ParseException( 
                            I18n.err( I18n.ERR_17075_MISSING_LOW_SURROGATE_CHAR ), pos.start );
                }
                
                char c2 = str.charAt( pos.start );
                pos.start++;

                if ( Character.isLowSurrogate( c2 ) )
                {
                    dnStr.append( c );
                    dnStr.append( c2 );
                }
                else
                {
                    // This is an error
                    throw new ParseException( 
                            I18n.err( I18n.ERR_17076_IMPROPER_MULTI_BYTE_CHAR ), pos.start );
                }
            }
            else
            {
                pos.start++;

                // check if it's a "
                if ( c == DQUOTE )
                {
                    // Check the next char if any
                    if ( !hasMoreChars( pos ) )
                    {
                        // Ok, we are done
                        break;
                    }
                    
                    if ( str.charAt( pos.start ) == DQUOTE )
                    {
                        // In order to be able to parse the DN, we need to replace
                        // the "" by \" in the string
                        dnStr.append( "\\\"" );
                        pos.start++;
                    }
                    else
                    {
                        // This is the end of the DN
                        break;
                    }
                }
                else
                {
                    // Move forward
                    dnStr.append( c );
                }
            }
        }
        
        if ( pos.start == start )
        {
            // We haven't get a final "
            throw new ParseException( 
                    I18n.err( I18n.ERR_17077_MISSING_CLOSING_DQUOTE ), pos.start );
        }
        
        return dnStr.toString();
    }
}
