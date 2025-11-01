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
package org.apache.directory.api.ldap.schema.converter;


import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.schema.ObjectClassTypeEnum;
import org.apache.directory.api.ldap.model.schema.UsageEnum;
import org.apache.directory.api.util.Chars;
import org.apache.directory.api.util.IOUtils;
import org.apache.directory.api.util.Position;
import org.apache.directory.api.util.Strings;
import static org.apache.directory.api.util.ParserUtil.getToken;
import static org.apache.directory.api.util.ParserUtil.hasMoreChars;
import static org.apache.directory.api.util.ParserUtil.isMatchChar;
import static org.apache.directory.api.util.ParserUtil.matchChar;
import static org.apache.directory.api.util.ParserUtil.parseDescr;
import static org.apache.directory.api.util.ParserUtil.parseNumericOid;
import static org.apache.directory.api.util.ParserUtil.parseOid;
import static org.apache.directory.api.util.ParserUtil.skipComment;
import static org.apache.directory.api.util.ParserUtil.skipSpaces;
import static org.apache.directory.api.util.ParserUtil.END;
import static org.apache.directory.api.util.ParserUtil.LCURLY;
import static org.apache.directory.api.util.ParserUtil.LPAREN;
import static org.apache.directory.api.util.ParserUtil.ONE_N;
import static org.apache.directory.api.util.ParserUtil.RCURLY;
import static org.apache.directory.api.util.ParserUtil.ZERO_N;


/**
 * A SchemaElement parser.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SchemaParser
{
    /** The various found characters */
    private static final char BACKSLASH = '\\';
    private static final char DOLLAR = '$';
    private static final char RPAREN = ')';
    private static final char SQUOTE = '\'';

    /** The tokens */
    private static final String ABSTRACT = "ABSTRACT";
    private static final String AUXILIARY = "AUXILIARY";
    private static final String DESC = "DESC";
    private static final String DIRECTORY_OPERATION = "DIRECTORYOPERATION";
    private static final String DISTRIBUTED_OPERATION = "DISTRIBUTEDOPERATION";
    private static final String DSA_OPERATION = "DSAOPERATION";
    private static final String EQUALITY = "EQUALITY";
    private static final String ORDERING = "ORDERING";
    private static final String SUBSTR = "SUBSTR";
    private static final String SYNTAX = "SYNTAX";
    private static final String SINGLE_VALUE = "SINGLE-VALUE";
    private static final String COLLECTIVE = "COLLECTIVE";
    private static final String NO_USER_MODIFICATION = "NO-USER-MODIFICATION";
    private static final String MAY = "MAY";
    private static final String MUST = "MUST";
    private static final String NAME = "NAME";
    private static final String OBSOLETE = "OBSOLETE";
    private static final String STRUCTURAL = "STRUCTURAL";
    private static final String SUP = "SUP";
    private static final String USAGE = "USAGE";
    private static final String USER_APPLICATIONS = "USERAPPLICATIONS";
    private static final String X_HYPHEN = "X-";
    
    /** The schema elements */
    private static final String ATTRIBUTE_TYPE = "ATTRIBUTETYPE";
    private static final String OBJECT_CLASS = "OBJECTCLASS";

    /**
     * Creates a reusable instance of an SchemaParser.
     *
     * @throws java.io.IOException if the pipe cannot be formed
     */
    public SchemaParser() throws IOException
    {
    }
    
    
    /**
     * Parse the QDescrs, following this grammar:
     * 
     * <pre>
     *   qdescr = SQUOTE descr SQUOTE
     * </pre>
     * 
     * @param schema The schema to parse
     * @param pos The current position in the schema
     * @return The found qdescr without quotes
     * @throws ParseException If there is a missing starting or ending quote, or if the descr is wrong
     **/
    private String parseQDescr( String schema, Position pos ) throws ParseException
    {
        if ( !isMatchChar( schema, SQUOTE, pos ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_15010_MISSING_QDESCR_LQUOTE ), pos.start );
        }
        
        String descr = parseDescr( schema, pos ); 
        
        if ( !hasMoreChars( pos ) || !isMatchChar( schema, SQUOTE, pos ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_15013_QDESCR_INCOMPLET ), pos.start );
        }
        
        return descr;
    }
    
    
    /**
     * Parse the QDescrs, following this grammar:
     * 
     * <pre>
     *   qdescrlist = [ qdescr *( SP qdescr ) ]
     *   qdescrs = qdescr / ( LPAREN WSP qdescrlist WSP RPAREN )
     * </pre>
     * 
     * @param schema The schema to parse
     * @param pos The current position in the schema
     * @return The list of parsed quoted descriptions
     * @throws ParseException If there is a wrong qdescr or a missing space or a missing right parenthesis
     */
    private List<String> parseQDescrs( String schema, Position pos ) throws ParseException
    {
        List<String> qdescrs = new ArrayList<>();
        
        // First check if we have a left parenthesis
        if ( isMatchChar( schema, LPAREN, pos ) )
        {
            pos.start++;
            skipSpaces( schema, pos, ZERO_N );
            boolean isFirst = true;
            boolean hasSpace = false;
            
            // Parse each qdescr
            while ( true )
            {
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    if ( !hasSpace )
                    {
                        throw new ParseException( I18n.err( I18n.ERR_15006_SPACE_REQUIRED ), pos.start );
                    }
                }
                
                String qdescr = parseQDescr( schema, pos );
                
                qdescrs.add( qdescr );
                
                // Skip potential spaces. We must have some if threr are 
                // more qdescr
                hasSpace = skipSpaces( schema, pos, ZERO_N );
                
                if ( isMatchChar( schema, RPAREN, pos ) )
                {
                    // No more descr
                    return qdescrs;
                }
            }
        }
        else
        {
            // A single qdescr
            String qdescr = parseQDescr( schema, pos );
            
            qdescrs.add( qdescr );
        }
        
        return qdescrs;
    }
    
    
    /**
     * Parse the NAME part. The grammar is the following:
     * 
     * <pre>
     *   [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     * </pre>
     * 
     * @param schema The schema to parse
     * @param pos The current position in the schema
     * @return The list of parsed names
     * @throws ParseException If there is a missing space or a wrong qdescrs
     */
    private List<String> parseName( String schema, Position pos ) throws ParseException
    {
        // The optional NAME has already been parse
        // Skip one or N spaces
        if ( !skipSpaces( schema, pos, ONE_N ) )
        {
            // error
            throw new ParseException( I18n.err( I18n.ERR_15018_MANDATORY_SPACE_MISSING ), pos.start );
        }
        
        // Parse the qdescrs
        List<String> names = parseQDescrs( schema, pos );
        
        return names;
    }
    
    
    /**
     * Process the DESC part, using this grammar:
     * 
     * <pre>
     *   ESC      = %x5C ; backslash ("\")
     *   UTF0     = %x80-BF
     *   UTF1     = %x00-7F
     *   UTF2     = %xC2-DF UTF0
     *   UTF2     = %xC2-DF UTF0
     *   UTF3     = %xE0 %xA0-BF UTF0 / %xE1-EC 2(UTF0) / %xED %x80-9F UTF0 / %xEE-EF 2(UTF0)
     *   UTF4     = %xF0 %x90-BF 2(UTF0) / %xF1-F3 3(UTF0) / %xF4 %x80-8F 2(UTF0)
     *   UTFMB    = UTF2 / UTF3 / UTF4
     *   QUTF1    = %x00-26 / %x28-5B / %x5D-7F ; Any ASCII character except %x27 ("\'") and %x5C ("\")
     *   QUTF8    = QUTF1 / UTFMB ; Any UTF-8 encoded Unicode character except %x27 ("\'") and %x5C ("\")
     *   QS       =  ESC %x35 ( %x43 / %x63 ) ; "\5C" / "\5c"
     *   QQ       =  ESC %x32 %x37 ; "\27"
     *   dstring  = 1*( QS / QQ / QUTF8 )   ; escaped UTF-8 string
     *   qdstring = SQUOTE dstring SQUOTE
     *   SP "DESC" SP qdstring
     * </pre>
     * 
     * Bottom line, the content is any UTF-8 char but '\'. If a '\' is found, it must be followed
     * either by "27", "5c" or "5C".
     * 
     * @param schema The schema to parse
     * @param pos The current position in the schema
     * @return
     * @throws ParseException
     */
    private String parseQDString( String schema, Position pos ) throws ParseException
    {
        // There must be some spaces, followed by the description
        if ( !skipSpaces( schema, pos, ONE_N ) )
        { 
            // error
            throw new ParseException( I18n.err( I18n.ERR_15018_MANDATORY_SPACE_MISSING ), pos.start );
        }

        if ( !isMatchChar( schema, SQUOTE, pos ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_15015_MISSING_DESC_LQUOTE ), pos.start );
        }
        
        StringBuilder sb = new StringBuilder();
        
        while ( hasMoreChars( pos ) )
        {
            char c = schema.charAt( pos.start );
            
            switch ( c )
            {
                case BACKSLASH:
                    pos.start++;

                    // we are expecting either 27, 5c or 5C
                    if ( !hasMoreChars( pos ) )
                    {
                        throw new ParseException( I18n.err( I18n.ERR_15009_MISSING_ESCAPED_CHAR ), pos.start );
                    }
                    
                    switch ( schema.charAt( pos.start ) )
                    {
                        case '2':
                            // The escaped quote
                            pos.start++;
                            
                            if ( isMatchChar( schema, '7', pos ) )
                            {
                                sb.append( '\'' );
                            }
                            else
                            {
                                throw new ParseException( I18n.err( 
                                        I18n.ERR_15011_MISSING_ESCAPED_QUOTE, 
                                        schema.charAt( pos.start ) ), pos.start );
                            }
                            
                            break;
                            
                        case '5':
                            // The escaped backslash
                            if ( !hasMoreChars( pos ) )
                            {
                                throw new ParseException( I18n.err( 
                                        I18n.ERR_15012_MISSING_ESCAPED_ESCAPE, 
                                        schema.charAt( pos.start ) ), pos.start );
                            }
                            
                            pos.start++;

                            c = schema.charAt( pos.start );
                            
                            if ( ( c == 'c' ) || ( c == 'C' ) )
                            {
                                pos.start++;
                                sb.append( '\\' );
                            }
                            
                            break;
                            
                        default:
                            throw new ParseException(
                                    I18n.err( I18n.ERR_15007_UNEXPECTED_ESCAPED_SECOND_CHAR, c ), pos.start );
                    }
                    
                    break;
                    
                case SQUOTE:
                    // This is the end. Get out
                    pos.start++;
                    
                    return sb.toString();
                    
                default:
                    pos.start++;
                    sb.append( c );
                    
                    break;
            }
        }
        
        throw new ParseException( I18n.err( I18n.ERR_15016_MISSING_QDSTRING_RPAREN ), pos.start );
    }

    
    /**
     * Parse the list of oids. It's used for SUP, MAY and MUST.
     * It follows this grammar:
     * 
     * <pre>
     *   oidlist = oid *( WSP DOLLAR WSP oid )
     *   oids = oid / ( LPAREN WSP oidlist WSP RPAREN )
     * </pre>
     * 
     * The only difference between a descr and a OID is that descr starts with a letter
     * while an OID starts with a digit.
     * 
     * @param schema The schema to parse
     * @param pos The current position in the schema
     * @return The list of found OIDs
     * @throws ParseException If there is a wrong oid or a missing '$' or a missing closing parenthesis
     */
    private List<String> parseOids( String schema, Position pos ) throws ParseException
    {
        // There must be some spaces, followed by the description
        if ( !skipSpaces( schema, pos, ONE_N ) )
        {
            // error
            throw new ParseException( I18n.err( 
                    I18n.ERR_15018_MANDATORY_SPACE_MISSING ), pos.start );
        }
        
        List<String> oids = new ArrayList<>();

        if ( isMatchChar( schema, LPAREN, pos ) )
        {
            // We have many oids. First, skip starting spaces
            skipSpaces( schema, pos, ZERO_N );
            
            while ( hasMoreChars( pos ) )
            {
                String oid = parseOid( schema, pos );
                
                oids.add( oid );
                
                skipSpaces( schema, pos, ZERO_N );
                
                if ( !isMatchChar( schema, DOLLAR, pos ) )
                {
                    // We have no more oid, check for a closing parenthesis
                    skipSpaces( schema, pos, ZERO_N );
                    
                    if ( !isMatchChar( schema, RPAREN, pos ) )
                    {
                        throw new ParseException( 
                                I18n.err( 
                                        I18n.ERR_15019_MISSING_OIDS_RPAREN, schema.charAt( pos.start ) ), pos.start );
                    }
                    
                    return oids;
                }
            }
            
            return oids;
        }
        else
        {
            String oid = parseOid( schema, pos );
            
            oids.add( oid );
            
            return oids;
        }
    }

    
    /**
     * Parse the list of extensions. 
     * 
     * <pre>
     *   extensions = *( SP xstring SP qdstrings )
     *   xstring = "X" HYPHEN 1*( ALPHA / HYPHEN / USCORE )
     *   qdstrings = qdstring / ( LPAREN WSP qdstringlist WSP RPAREN )
     *   qdstringlist = [ qdstring *( SP qdstring ) ]
     *   qdstring = SQUOTE dstring SQUOTE
     *   dstring = 1*( QS / QQ / QUTF8 )   ; escaped UTF-8 string
     * </pre>
     * 
     * The only difference between a descr and a OID is that descr starts with a letter
     * while an OID starts with a digit.
     * 
     * @param schema The schema to parse
     * @param pos The current position in the schema
     * @param token The extension name
     * @return The list of found extensions
     * @throws ParseException If there is a wrong extension
     */
    private Map<String, List<String>> parseExtensions( String schema, Position pos, String token ) throws ParseException
    {
        // Check the extension name starts with 'X-'
        String extensionName = Strings.toUpperCaseAscii( token );
        
        Map<String, List<String>> extension = new HashMap<>();
        
        if ( extensionName.startsWith( X_HYPHEN ) && ( extensionName.length() > 2 ) )
        {
            // We must have a space before the values
            if ( !skipSpaces( schema, pos, ONE_N ) )
            {
                // error
                throw new ParseException( I18n.err( 
                        I18n.ERR_15018_MANDATORY_SPACE_MISSING ), pos.start );
            }
            
            List<String> values = new ArrayList<>();
            
            // Do we have more than one value?
            if ( isMatchChar( schema, LPAREN, pos ) )
            {
                skipSpaces( schema, pos, ZERO_N );
                boolean isFirst = true;
                
                while ( hasMoreChars( pos ) && !isMatchChar( schema, RPAREN, pos ) )
                {
                    if ( isFirst )
                    {
                        isFirst = false;
                    }
                    else
                    {
                        if ( !skipSpaces( schema, pos, ONE_N ) )
                        {
                            // error
                            throw new ParseException( I18n.err( 
                                    I18n.ERR_15018_MANDATORY_SPACE_MISSING ), pos.start );
                        }
                    }
                    
                    String value = parseQDString( schema, pos );
                    
                    values.add( value );
                }
            }
            else
            {
                String value = parseQDString( schema, pos );
                
                values.add( value );
            }
            
            extension.put( extensionName, values );

            return extension;

        }
        else
        {
            // This is not a proper extension
            throw new ParseException( I18n.err( I18n.ERR_15023_IMPROPER_EXTENSION_NAME, token ), pos.start );
        }
    }
    
    
    /**
     * Parse a token following one of schemaElement keyword.
     * It will either be a space, another token or a closing parenthesis.
     * 
     * @param schema The schema to parse
     * @param pos The current position in the schema
     * @throws ParseException 
     */
    private String parseToken( String schema, Position pos ) throws ParseException
    {
        // We may have nothing, otherwise it's necessarily
        // some spaces, followed by an identifier
        boolean hasSpaces = skipSpaces( schema, pos, ONE_N );
        
        if ( !hasSpaces )
        {
            // We must be at the end of the schema element, so we
            // expect a right parenthesis
            if ( hasMoreChars( pos ) && isMatchChar( schema, RPAREN, pos ) )
            {
                return END;
            }
            else
            {
                throw new ParseException( I18n.err( 
                        I18n.ERR_15020_MISSING_SCHEMA_ELEMENT_RPAREN ), pos.start );
            }
        }
        else
        {
            // We may be at the end of the schema element, so we
            // expect a right parenthesis
            if ( hasMoreChars( pos ) )
            {
                if ( isMatchChar( schema, RPAREN, pos ) )
                {
                    // The end of the schema Element
                    return END;
                }
                else
                {
                    // Get a new token
                    String token = getToken( schema, pos );

                    return Strings.toUpperCaseAscii( token );
                }
            }
            else
            {
                // No more char, no RPAREN? This is an error
                throw new ParseException( I18n.err( I18n.ERR_15022_SCHEMA_ELEMENT_MISSING_RPAREN ), pos.start );
            }
        }
    }
    
    
    /**
     * Parse an AttributeType schema element, following this grammar:
     * 
     * <pre>
     *  AttributeTypeDescription = LPAREN WSP
     *    numericoid                    ; object identifier
     *    [ SP "NAME" SP qdescrs ]      ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]     ; description
     *    [ SP "OBSOLETE" ]             ; not active
     *    [ SP "SUP" SP oid ]           ; supertype
     *    [ SP "EQUALITY" SP oid ]      ; equality matching rule
     *    [ SP "ORDERING" SP oid ]      ; ordering matching rule
     *    [ SP "SUBSTR" SP oid ]        ; substrings matching rule
     *    [ SP "SYNTAX" SP noidlen ]    ; value syntax
     *    [ SP "SINGLE-VALUE" ]         ; single-value
     *    [ SP "COLLECTIVE" ]           ; collective
     *    [ SP "NO-USER-MODIFICATION" ] ; not user modifiable
     *    [ SP "USAGE" SP usage ]       ; usage
     *    extensions WSP RPAREN         ; extensions
     *
     *    usage = "userApplications"     /  ; user
     *       "directoryOperation"   /  ; directory operational
     *       "distributedOperation" /  ; DSA-shared operational
     *       "dSAOperation"            ; DSA-specific operational
     * </pre>
     * 
     * @param schema The schema to parse
     * @param pos The current position in the schema
     * @throws ParseException 
     */
    private SchemaElement parseAttributeType( String schema, Position pos ) throws ParseException
    {
        // First zero or N skip spaces
        skipSpaces( schema, pos, ZERO_N );
        
        // Check the starting left parenthesis
        matchChar( schema, LPAREN, pos );
        
        // Skip zero or N spaces
        skipSpaces( schema, pos, ZERO_N );
        
        // The numeric OID
        String oid = parseNumericOid( schema, pos );
        
        AttributeTypeHolder atHolder = new AttributeTypeHolder( oid );
        
        // Starting from this point, everything is optional
        // but the order in which each element appears is 
        // mandatory. We don't really care if it's not ordered though
        String token;
        
        // This will stop when we get the END token, which is produced
        // by the parseToken method when it reaches the end of the schema
        while ( ( token = parseToken( schema, pos ) ) != null )
        {
            switch ( token )
            {
                case NAME:
                    List<String> names = parseName( schema, pos );
                    
                    atHolder.setNames( names );
                    
                    break;
                    
                case DESC:
                    String description  = parseQDString( schema, pos );
                    
                    atHolder.setDescription( description );
                    
                    break;
                    
                case OBSOLETE:
                    atHolder.setObsolete( true );

                    break;
                    
                case SUP:
                    String superior = parseOid( schema, pos );
                    
                    atHolder.setSuperior( superior );

                    break;
                    
                case EQUALITY:
                    String equality = parseOid( schema, pos );
                    
                    atHolder.setEquality( equality );

                    break;
                    
                case ORDERING:
                    String ordering = parseOid( schema, pos );
                    
                    atHolder.setOrdering( ordering );

                    break;
                    
                case SUBSTR:
                    String substring = parseOid( schema, pos );
                    
                    atHolder.setSubstr( substring );

                    break;
                    
                case SYNTAX:
                    String syntax = parseOid( schema, pos );
                    
                    // We may have a length
                    if ( isMatchChar( schema, LCURLY, pos ) )
                    {
                        int start = pos.start;
                        
                        while ( hasMoreChars( pos ) && Chars.isDigit( schema.charAt( pos.start ) ) )
                        {
                            pos.start++;
                        }
                        
                        if ( pos.start == start )
                        {
                            throw new ParseException( 
                                    I18n.err( I18n.ERR_15021_NO_SYTNAX_LEN ), pos.start );
                        }
                        
                        if ( isMatchChar( schema, RCURLY, pos ) )
                        {
                            String oidLen = schema.substring( start, pos.start - 1 );
                            
                            atHolder.setOidLen( Integer.parseInt( oidLen ) );
                        }
                        else
                        {
                            throw new ParseException( 
                                    I18n.err( I18n.ERR_15017_MISSING_OID_LEN_RIGHT_CURLY ), pos.start );
                        }
                    }
                    
                    atHolder.setSyntax( syntax );

                    break;
                    
                case SINGLE_VALUE:
                    atHolder.setSingleValue( true );
                    break;
                    
                case COLLECTIVE:
                        atHolder.setCollective( true );
                        break;
                        
                case NO_USER_MODIFICATION:
                    atHolder.setNoUserModification( true );
                    break;
                    
                case END:
                    // The end of the schema element, get rid of the ending spaces
                    skipSpaces( schema, pos, ZERO_N );

                    return atHolder;
                    
                case USAGE:
                    // Skip the spaes
                    if ( !skipSpaces( schema, pos, ONE_N ) )
                    {
                        // error
                        throw new ParseException( I18n.err( 
                                I18n.ERR_15018_MANDATORY_SPACE_MISSING ), pos.start );
                    }
                    
                    token = getToken( schema, pos );
                    
                    switch ( Strings.toUpperCaseAscii( token ) )
                    {
                        case DIRECTORY_OPERATION:
                            atHolder.setUsage( UsageEnum.DIRECTORY_OPERATION );
                            break;
                            
                        case DISTRIBUTED_OPERATION:
                            atHolder.setUsage( UsageEnum.DISTRIBUTED_OPERATION );
                            break;
                            
                        case DSA_OPERATION:
                            atHolder.setUsage( UsageEnum.DSA_OPERATION );
                            break;
                            
                        case USER_APPLICATIONS:
                            atHolder.setUsage( UsageEnum.USER_APPLICATIONS );
                            break;
                            
                        default:
                            throw new ParseException( I18n.err( I18n.ERR_15014_AT_WRONG_USAGE, token ), pos.start );
                    }
                    
                    break;
                  
                default:
                    // Must be extensions...
                    Map<String, List<String>> extensions = parseExtensions( schema, pos, token );
                    
                    atHolder.setExtensions( extensions );

                    break;
            }
        }

        // We should never get there
        return null;
    }
    
    
    /**
     * Parse an ObjectClass schema element, following this grammar:
     * 
     * <pre>
     * ObjectClassDescription = 
     *   LPAREN WSP
     *   numericoid                 ; object identifier
     *   [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *   [ SP "DESC" SP qdstring ]  ; description
     *   [ SP "OBSOLETE" ]          ; not active
     *   [ SP "SUP" SP oids ]       ; superior object classes
     *   [ SP kind ]                ; kind of class
     *   [ SP "MUST" SP oids ]      ; attribute types
     *   [ SP "MAY" SP oids ]       ; attribute types
     *   extensions WSP RPAREN
     *  extensions = *( SP xstring SP qdstrings )
     * </pre>
     * 
     * @param schema The schema to parse
     * @param pos The current position in the schema
     * @throws ParseException If the ObjectClass is incorrect
     */
    private SchemaElement parseObjectClass( String schema, Position pos ) throws ParseException
    {
        // First zero or N skip spaces
        skipSpaces( schema, pos, ZERO_N );
        
        // Check the starting left parenthesis
        matchChar( schema, LPAREN, pos );
        
        // Skip zero or N spaces
        skipSpaces( schema, pos, ZERO_N );
        
        // The numeric OID
        String oid = parseNumericOid( schema, pos );
        
        ObjectClassHolder ocHolder = new ObjectClassHolder( oid );

        // Starting from this point, everything is optional
        // but the order in which each element appears is 
        // mandatory. We don't really care if it's not ordered though
        String token;
        
        // This will stop when we get the END token, which is produced
        // by the parseToken method when it reaches the end of the schema
        while ( ( token = parseToken( schema, pos ) ) != null )
        {
            switch ( token )
            {
                case NAME:
                    List<String> names = parseName( schema, pos );
                    
                    ocHolder.setNames( names );
                    
                    break;
                    
                case DESC:
                    String description  = parseQDString( schema, pos );
                    
                    ocHolder.setDescription( description );
                    
                    break;
                    
                case OBSOLETE:
                    ocHolder.setObsolete( true );

                    break;
                    
                case SUP:
                    List<String> superiors = parseOids( schema, pos );
                    
                    ocHolder.setSuperiors( superiors );

                    break;
                    
                case ABSTRACT:
                    ocHolder.setClassType( ObjectClassTypeEnum.ABSTRACT );
                    
                    break;
                    
                case STRUCTURAL:
                    ocHolder.setClassType( ObjectClassTypeEnum.STRUCTURAL );

                    break;
                    
                case AUXILIARY:
                    ocHolder.setClassType( ObjectClassTypeEnum.AUXILIARY );

                    break;
                    
                case MUST:
                    List<String> must = parseOids( schema, pos );
                    ocHolder.setMust( must );

                    break;
                    
                case MAY:
                    List<String> may = parseOids( schema, pos );
                    ocHolder.setMay( may );

                    break;
                    
                case END:
                    // The end of the schema element, get rid of the ending spaces
                    skipSpaces( schema, pos, ZERO_N );

                    return ocHolder;
                  
                default:
                    // Must be extensions...
                    Map<String, List<String>> extensions = parseExtensions( schema, pos, token );
                    
                    ocHolder.setExtensions( extensions );

                    break;
            }
        }

        // We should never get there
        return null;
    }
    
    
    /**
     * Parse a schema element from its description.
     * 
     * The grammar is:
     * 
     * <pre>
     *   SchemaElement = 'objectClass' ObjectClassDescription |  
     *                   'attributeType' AttributeTypeDescription |
     *                   'matchingRule' MatchingRuleDescription |
     *                   'matchingRuleUse' MatchingRuleUseDescription |
     *                   'ldapSyntax' SyntaxDescription |
     *                   'dITContentRule' DITContentRuleDescription |
     *                   'dITStructureRule' DITStructureRuleDescription |
     *                   'nameForm' NameFormDescription
     * </pre>
     * 
     * @param schema The String containing the schema to parse
     * @param pos The position in the schema string
     * @return The parsed Schema element
     * @throws ParseException If the parsing failed
     */
    private SchemaElement parseSchemaElement( String schema, Position pos ) throws ParseException
    {
        if ( pos.start >= pos.length )
        { 
            // we are done, return
            return null;
        }
        // First skip spaces
        skipSpaces( schema, pos, ZERO_N );

        String token = getToken( schema, pos );
        
        if ( Strings.isEmpty( token ) )
        {
            return null;
        }
        
        switch ( Strings.toUpperCaseAscii( token ) )
        {
            case ATTRIBUTE_TYPE:
                SchemaElement attributeType = parseAttributeType( schema, pos );

                return attributeType;

            case OBJECT_CLASS:
                SchemaElement objectClass = parseObjectClass( schema, pos );
                
                return objectClass;
                
            default:
                return null;
        }
    }
    
    
    /**
     * Parses an OpenLDAP schemaObject elements/objects.
     *
     * @param SchemaStr a LDAP schema to parse
     * @return A list of schema elements
     * @throws ParseException  If we weren't able to parse the schema
     */
    public List<SchemaElement> parse( String schemaStr ) throws ParseException
    {
        Position pos = new Position();
        pos.start = 0;
        pos.length = schemaStr.length();
        
        // Get rid of comments. Checkstyle does not like empty loops, so 
        // it's coded this way instead of a while (slipComments);
        while ( true )
        {
            if ( !skipComment( schemaStr, pos ) )
            {
                break;
            }
        }
        
        // Ok, we may have either attributeType or objectClass
        SchemaElement schemaElement;
        List<SchemaElement> schemaElements = new ArrayList<>();
        
        while ( ( schemaElement = parseSchemaElement( schemaStr, pos ) ) != null )
        {
            schemaElements.add( schemaElement );
        }
        
        return schemaElements;
    }
    


    /**
     * Parses a stream of OpenLDAP schemaObject elements/objects.
     *
     * @param schemaIn a stream of schema objects
     * @return A list of schema elements
     * @throws IOException If the schema file can't be read
     * @throws ParseException  If we weren't able to parse the schema
     */
    public List<SchemaElement> parse( InputStream schemaIn ) throws IOException, ParseException
    {
        // First read fully the data
        String schemaStr = IOUtils.toString( schemaIn, StandardCharsets.UTF_8 );
        
        return parse( schemaStr );
    }
}
