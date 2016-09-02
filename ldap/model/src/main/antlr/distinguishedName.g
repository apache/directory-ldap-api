header {
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
package org.apache.directory.api.ldap.model.name;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import javax.naming.NameParser;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.schema.parsers.ParserMonitor;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.util.ExpansibleByteBuffer;
import org.apache.directory.api.util.Strings;
import org.apache.directory.api.util.Unicode;
}

/**
 * An antlr generated Dn lexer.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class AntlrDnLexer extends Lexer;

options    {
    k = 3 ;
    exportVocab=AntlrDn ;
    charVocabulary = '\u0000'..'\uFFFE';
    caseSensitive = false ;
    defaultErrorHandler = false ;
}

COMMA : ',' ;
EQUALS : '=' ;
PLUS : '+' ;
HYPHEN : '-' ;
UNDERSCORE : '_' ;
DQUOTE : '"' ;
SEMI : ';' ;
LANGLE : '<' ;
RANGLE : '>' ;
SPACE : ' ' ;

NUMERICOID_OR_ALPHA_OR_DIGIT 
    : ( NUMERICOID ) => NUMERICOID { $setType(NUMERICOID); }
    | ( DIGIT ) => DIGIT { $setType(DIGIT); }
    | ( ALPHA ) => ALPHA { $setType(ALPHA); }
    ;
protected NUMERICOID : ( "oid." )? NUMBER ( DOT NUMBER )+ ;
protected DOT: '.' ;
protected NUMBER: DIGIT | ( LDIGIT ( DIGIT )+ ) ;
protected LDIGIT : '1'..'9' ;
protected DIGIT : '0'..'9' ;
protected ALPHA : 'a'..'z' ;

HEXPAIR_OR_ESCESC_ESCSHARP_OR_ESC 
    : (ESC HEX HEX) => HEXPAIR { $setType(HEXPAIR); }
    | ESCESC { $setType(ESCESC); }
    | ESCSHARP { $setType(ESCSHARP); }
    | ESC { $setType(ESC); }
    ;
protected HEXPAIR : ESC! HEX HEX ;
protected ESC : '\\';
protected ESCESC : ESC ESC;
protected ESCSHARP : ESC SHARP;
protected HEX: DIGIT | 'a'..'f' ;

HEXVALUE_OR_SHARP
    : (SHARP ( HEX HEX )+) => HEXVALUE { $setType(HEXVALUE); }
    | SHARP { $setType(SHARP); }
    ;
protected HEXVALUE : SHARP! ( HEX HEX )+ ;
protected SHARP: '#' ;

UTFMB : '\u0080'..'\uFFFE' ;

/**
 * RFC 4514, Section 3:
 * LUTF1 = %x01-1F / %x21 / %x24-2A / %x2D-3A /
 *    %x3D / %x3F-5B / %x5D-7F
 *
 * To avoid nondeterminism the following 
 * rules are excluded. These rules are 
 * explicitly added in the productions.
 *   EQUALS (0x3D)
 *   HYPHEN (0x2D)
 *   UNDERSCORE (0x5F)
 *   DIGIT (0x30-0x39)
 *   ALPHA (0x41-0x5A and 0x61-0x7A)
 */
CHAR_REST : 
    '\u0001'..'\u001F' |
    '\u0021' |
    '\u0024'..'\u002A' |
    '\u002E'..'\u002F' |
    '\u003A' |
    '\u003F'..'\u0040' |
    '\u005B' |
    '\u005D'..'\u005E' | 
    '\u0060' | 
    '\u007B'..'\u007F' 
    ;


/**
 * An antlr generated Dn parser.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class AntlrDnParser extends Parser;
options    {
    k = 3 ;
    defaultErrorHandler = false ;
    //buildAST=true ;
}

{
    private ParserMonitor monitor = null;
    
    public void setParserMonitor( ParserMonitor monitor )
    {
        this.monitor = monitor;
    }
    
    private void matchedProduction( String msg )
    {
        if ( null != monitor )
        {
            monitor.matchedProduction( msg );
        }
    }

    /**
     * This class is used to store the decoded value
     */
    private static class UpAndNormValue
    {
        // The value as a byte array
        ExpansibleByteBuffer bytes = new ExpansibleByteBuffer();

        // The user provided value
        StringBuilder upValue = new StringBuilder();

        // The normalized value
        StringBuilder normValue = new StringBuilder();

        // A flag set to false if we have a binary value
        boolean isHR = true;
    }
}


/**
 * Parses a Dn string.
 *
 * RFC 4514, Section 3
 * distinguishedName = [ relativeDistinguishedName
 *     *( COMMA relativeDistinguishedName ) ]
 *
 * RFC 2253, Section 3
 * distinguishedName = [name] 
 * name       = name-component *("," name-component)
 *
 * RFC 1779, Section 2.3
 * &lt;name&gt; ::= &lt;name-component&gt; ( &lt;spaced-separator&gt; )
 *        | &lt;name-component&gt; &lt;spaced-separator&gt; &lt;name&gt;
 * &lt;spaced-separator&gt; ::= &lt;optional-space&gt;
 *             &lt;separator&gt;
 *             &lt;optional-space&gt;
 * &lt;separator&gt; ::=  "," | ";"
 * &lt;optional-space&gt; ::= ( &lt;CR&gt; ) *( " " )
 */
distinguishedName [SchemaManager schemaManager, Dn dn]
    {
        matchedProduction( "distinguishedName()" );
        Rdn rdn = new Rdn( schemaManager );
    }
    :
    (
        relativeDistinguishedName[schemaManager, rdn] 
        { 
            try
            { 
                dn.add( rdn );
                
            }
            catch ( LdapInvalidDnException lide )
            {
                // Do nothing, can't get an exception here
            } 
        }
        (
            ( COMMA | SEMI )
            {
                rdn = new Rdn( schemaManager );
            }
            relativeDistinguishedName[schemaManager, rdn] 
            { 
                try
                { 
                    dn.add( rdn ); 
                }
                catch ( LdapInvalidDnException lide )
                {
                    // Do nothing, can't get an exception here
                } 
            }
        )*
        EOF
    )?
    ;


/**
 * Parses a Dn string.
 *
 * RFC 4514, Section 3
 * distinguishedName = [ relativeDistinguishedName
 *     *( COMMA relativeDistinguishedName ) ]
 *
 * RFC 2253, Section 3
 * distinguishedName = [name] 
 * name       = name-component *("," name-component)
 *
 * RFC 1779, Section 2.3
 * &lt;name&gt; ::= &lt;name-component&gt; ( &lt;spaced-separator&gt; )
 *        | &lt;name-component&gt; &lt;spaced-separator&gt; &lt;name&gt;
 * &lt;spaced-separator&gt; ::= &lt;optional-space&gt;
 *             &lt;separator&gt;
 *             &lt;optional-space&gt;
 * &lt;separator&gt; ::=  "," | ";"
 * &lt;optional-space&gt; ::= ( &lt;CR&gt; ) *( " " )
 *
 */
relativeDistinguishedNames [SchemaManager schemaManager, List<Rdn> rdns] returns [String normNameStr]
    {
        matchedProduction( "relativeDistinguishedNames()" );
        Rdn rdn = new Rdn( schemaManager );
        StringBuilder dnNormSb = new StringBuilder();
    }
    :
    (
        relativeDistinguishedName[ schemaManager, rdn] 
        { 
            rdns.add( rdn );
            dnNormSb.append( rdn.getNormName() );
            rdn = new Rdn( schemaManager );
        }
        (
            ( COMMA | SEMI )
            relativeDistinguishedName[schemaManager, rdn] 
            { 
                rdns.add( rdn ); 
	            dnNormSb.append( ',' );
	            dnNormSb.append( rdn.getNormName() );
                rdn = new Rdn( schemaManager );
				}
        )*
        EOF
    )?
    {
        normNameStr = dnNormSb.toString();
    }
    ;

/**
 * Parses a Rdn string.
 *
 * RFC 4514, Section 3
 * relativeDistinguishedName = attributeTypeAndValue
 *     *( PLUS attributeTypeAndValue )
 *
 * RFC 2253, Section 3
 * name-component = attributeTypeAndValue *("+" attributeTypeAndValue)
 *
 * RFC 1779, Section 2.3
 * &lt;name-component&gt; ::= &lt;attribute&gt;
 *     | &lt;attribute&gt; &lt;optional-space&gt; "+"
 *       &lt;optional-space&gt; &lt;name-component&gt;
 *
 */
relativeDistinguishedName [SchemaManager schemaManager, Rdn rdn]
    {
        matchedProduction( "relativeDistinguishedName()" );
        String tmp;

        // The rdnStr variable is used to gather the full RDN string
        // as provided
        StringBuilder rdnStr = new StringBuilder();
        StringBuilder rdnNormStr = new StringBuilder();
        int avaPos = 0;
        Ava currentAva;
        AttributeType attributeType;
        Value val;
    }
    :
    (
        tmp = attributeTypeAndValue[schemaManager, rdn] 
        {
            rdnStr.append( tmp );
            currentAva = rdn.getAva( avaPos );
            
            attributeType = currentAva.getAttributeType();
            
            if ( schemaManager == null )
            {
                rdnNormStr.append( currentAva.getNormType() );
                rdnNormStr.append( '=' );
            }
            
            val = currentAva.getValue();
            
            if ( ( schemaManager == null ) && ( val != null ) && ( val.getNormalized() != null ) )
            {
                rdnNormStr.append( val.getNormalized() );
            }
        }
        (
            PLUS 
            { 
                rdnStr.append( '+' ); 
                
                if ( schemaManager == null )
                {
                    rdnNormStr.append( '+' );
                }
                
                avaPos++;
            }

            tmp = attributeTypeAndValue[schemaManager, rdn] 
            {
                rdnStr.append( tmp );
                currentAva = rdn.getAva( avaPos );
                attributeType = currentAva.getAttributeType();
            
                if ( schemaManager == null )
                {
                    rdnNormStr.append( tmp );
                    rdnNormStr.append( '=' );
                }
            
                val = currentAva.getValue();
            
                if ( ( schemaManager == null ) &&( val != null ) && ( val.getNormalized() != null ) )
                {
                    rdnNormStr.append( val.getNormalized() );
                }
            }
        )*
    )
    {
        rdn.hashCode();
        rdn.setUpName( rdnStr.toString() );
        
        if ( schemaManager != null )
        {
            // process the multi-value RDN, ordering them by attributes
            boolean isFirst = true;
            
            for ( Ava ava : rdn )
            {
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    rdnNormStr.append( '+' );
                }
                
                rdnNormStr.append( ava.getAttributeType().getOid() );
                rdnNormStr.append( '=' );
                
                val = ava.getValue();

                if ( ( val != null ) && ( val.getNormalized() != null ) )
                {
                    rdnNormStr.append( val.getNormalized() );
                }
            }
        }
        
        rdn.setNormName( rdnNormStr.toString() );
    }
    ;
    

/**
 * RFC 4514, Section 3
 * attributeTypeAndValue = attributeType EQUALS attributeValue
 *
 * RFC 2253, Section 3
 * attributeTypeAndValue = attributeType "=" attributeValue
 *
 */
attributeTypeAndValue [SchemaManager schemaManager, Rdn rdn] returns [String upNameStr]
    {
        matchedProduction( "attributeTypeAndValue()" );
        String type = null;
        UpAndNormValue value = new UpAndNormValue();
        StringBuilder rdnUpName = new StringBuilder();
    }
    :
    (
        ( SPACE { rdnUpName.append( ' ' ); } )*
        type = attributeType { rdnUpName.append( type ); }
        ( SPACE { rdnUpName.append( ' ' ); } )*
        EQUALS { rdnUpName.append( '=' ); }
        ( SPACE  { rdnUpName.append( ' ' ); } )*
        attributeValue[value] 
        {
            try
            {
                // We have to remove the ending spaces that may have been added, as the tutf1 rule
                // cannot be processed
                rdnUpName.append( value.upValue );
                AttributeType attributeType = null;
                Ava ava = null;

                if ( schemaManager != null )
                {
                    if ( ( type.startsWith( "oid." ) ) || ( type.startsWith( "OID." ) ) )
                    {
                        type = type.substring( 4 );
                    }

                    attributeType = schemaManager.getAttributeType( type );
                }

                if ( ( ( attributeType != null ) && attributeType.isHR() ) || value.isHR )
                {
                    int valueLength = value.upValue.length();
                    int pos = value.bytes.position();
                    
                    for ( int i = valueLength - 1; i >= 0; i-- )
                    {
                        if ( value.upValue.charAt( i ) == ' ' ) 
                        {
                            if ( i == 0 )
                            {
                                // The value is empty
                                ava = new Ava( schemaManager, type, rdnUpName.toString(), ( String ) null );
                                break;
                            }
                            else if ( value.upValue.charAt( i - 1 ) != '\\' )
                            {
                                // This is a trailing space, get rid of it
                                value.upValue.deleteCharAt( i );
                                pos--;
                                value.bytes.position( pos );
                            }
                            else
                            {
                                // This is an escaped space, get out
                                break;
                            }
                        }
                        else
                        {
                            break;
                        }
                    }

                    if ( ava == null )
                    {
                        ava = new Ava( schemaManager, type, rdnUpName.toString(), Strings.utf8ToString( value.bytes.copyOfUsedBytes() ) );
                    }
                }
                else
                {
                    ava = new Ava( schemaManager, type, rdnUpName.toString(), value.bytes.copyOfUsedBytes() );
                }
           
                rdn.addAVA( schemaManager, ava );
            }
            catch ( LdapInvalidDnException e )
            {
                throw new SemanticException( e.getMessage() );
            } 
        }
        ( SPACE { rdnUpName.append( ' ' ); } )*
    )
    {
        upNameStr = rdnUpName.toString();
    }
    ;
    

/**
 * RFC 4514 Section 3
 *
 * attributeType = descr / numericoid
 *
 */    
attributeType returns [String attributeType]
    {
        matchedProduction( "attributeType()" );
    }
    :
    (
        attributeType = descr
        |
        attributeType = numericoid
    )
    ;


/**
 * RFC 4512 Section 1.4
 *
 * descr = keystring
 * keystring = leadkeychar *keychar
 * leadkeychar = ALPHA
 * keychar = ALPHA / DIGIT / HYPHEN
 *
 * We additionally add UNDERSCORE because some servers allow them.
 *
 */    
descr returns [String descr]
    {
        matchedProduction( "descr()" );
        StringBuilder descrSb = new StringBuilder();
    }
    :
    leadkeychar:ALPHA { descrSb.append( leadkeychar.getText() ); }
    (
        alpha:ALPHA { descrSb.append( alpha.getText() ); }
        |
        digit:DIGIT { descrSb.append( digit.getText() ); }
        |
        HYPHEN { descrSb.append( '-' ); }
        |
        UNDERSCORE { descrSb.append( '_' ); }
    )*
    {
        descr = descrSb.toString();
    }
    ;


/**
 * RFC 4512 Section 1.4
 *
 * numericoid = number 1*( DOT number )
 * number  = DIGIT / ( LDIGIT 1*DIGIT )
 * DIGIT   = %x30 / LDIGIT       ; "0"-"9"
 * LDIGIT  = %x31-39             ; "1"-"9"
 *
 */   
numericoid returns [String numericoid = ""]
    {
        matchedProduction( "numericoid()" );
    }
    :
    noid:NUMERICOID { numericoid = noid.getText(); }
    ;


/**
 * RFC 4514, Section 3
 * attributeValue = string / hexstring
 *
 * RFC 2253, Section 3
 * attributeValue = string
 * string     = *( stringchar / pair )
 *              / "#" hexstring
 *              / QUOTATION *( quotechar / pair ) QUOTATION ; only from v2
 *
 * We still accept both forms, which means we can have a value surrounded by '"'
 */
attributeValue [UpAndNormValue value] 
    {
        matchedProduction( "attributeValue()" );
    }
    :
    (
        // Special for RFC 2253
        quotestring [value]
        |
        string [value]
        |
        hexstring [value]
    )?
    ;


/**
 * RFC 2253, Section 3
 *              / QUOTATION *( quotechar / pair ) QUOTATION ; only from v2
 * quotechar     = &lt;any character except "\" or QUOTATION &gt;
 *
 */
quotestring [UpAndNormValue value] 
    {
        matchedProduction( "quotestring()" );
    }
    :
    (
        DQUOTE { value.upValue.append( '"' ); }
        (
            (
                s:~(DQUOTE|ESC|ESCESC|ESCSHARP|HEXPAIR) 
                {
                    value.upValue.append( s.getText() );
                    value.bytes.append( Strings.getBytesUtf8( s.getText() ) );
                }
            )
            |
            pair [value] 
        )*
        DQUOTE { value.upValue.append( '"' ); }
    )
    ;


/**
 * RFC 4514 Section 3
 *
 * hexstring = SHARP 1*hexpair
 *
 * If in <hexstring> form, a BER representation can be obtained from
 * converting each <hexpair> of the <hexstring> to the octet indicated
 * by the <hexpair>.
 *
 */ 
hexstring [UpAndNormValue value]
    {
        matchedProduction( "hexstring()" );
    }
    :
    hexValue:HEXVALUE
    {
        String hexStr = hexValue.getText();
        value.upValue.append( '#' ).append( hexStr );
        value.bytes.append( Strings.toByteArray( hexStr ) );
        value.isHR = false; 
    }
    ;


/**
 * RFC 4514 Section 3
 *
 * ; The following characters are to be escaped when they appear
 * ; in the value to be encoded: ESC, one of <escaped>, leading
 * ; SHARP or SPACE, trailing SPACE, and NULL.
 * string =   [ ( leadchar / pair ) [ *( stringchar / pair ) ( trailchar / pair ) ] ]
 * leadchar = LUTF1 | UTFMB
 * stringchar = SUTF1 / UTFMB
 * trailchar = TUTF1 / UTFMB
 */ 
string [UpAndNormValue value]
    {
        matchedProduction( "string()" );
    }
    :
    (
        // Note that we don't distinguish between sutf1 and tutf1, as it would be ambiguous.
        // The final spaces will be handled later.
        ( lutf1 [value] | utfmb [value] | pair [value] ) ( sutf1 [value] | utfmb [value] | pair [value] )*
    )
    ;


/**
 * RFC 4514, Section 3:
 * LUTF1 = %x01-1F / %x21 / %x24-2A / %x2D-3A /
 *    %x3D / %x3F-5B / %x5D-7F
 *
 * The rule CHAR_REST doesn't contain the following charcters,
 * so we must check them additionally
 *   EQUALS (0x3D)
 *   HYPHEN (0x2D)
 *   UNDERSCORE (0x5F)
 *   DIGIT (0x30-0x39)
 *   ALPHA (0x41-0x5A and 0x61-0x7A)
 */
lutf1 [UpAndNormValue value]
    {
        matchedProduction( "lutf1()" );
    }
    :
    rest:CHAR_REST 
    { 
        char c = rest.getText().charAt( 0 );
        value.upValue.append( c );
        value.bytes.append( ( byte ) c );
    }
    |
    EQUALS
    { 
        value.upValue.append( '=' );
        value.bytes.append( '=' );
    }
    |
    HYPHEN
    { 
        value.upValue.append( '-' );
        value.bytes.append( '-' );
    }
    |
    UNDERSCORE
    { 
        value.upValue.append( '_' );
        value.bytes.append( '_' );
    }
    |
    digit:DIGIT
    { 
        char c = digit.getText().charAt( 0 );
        value.upValue.append( c );
        value.bytes.append( ( byte ) c );
    }
    |
    alpha:ALPHA
    { 
        char c = alpha.getText().charAt( 0 );
        value.upValue.append( c );
        value.bytes.append( ( byte ) c  );
    }
    | 
    // Another hack : having a String like 127.0.0.1 in the value
    // will not match a DIGIT, because it's swallowed by the NUMERICOID
    // token
    numericoid:NUMERICOID  
    {
        String number = numericoid.getText();
        value.upValue.append( number );
        value.bytes.append( Strings.getBytesUtf8( number ) );
    }
    ;


/**
 * RFC 4514, Section 3:
 * SUTF1 = %x01-21 / %x23-2A / %x2D-3A /
 *    %x3D / %x3F-5B / %x5D-7F
 *
 * The rule CHAR_REST doesn't contain the following charcters,
 * so we must check them additionally
 *   EQUALS (0x3D)
 *   HYPHEN (0x2D)
 *   UNDERSCORE (0x5F)
 *   DIGIT (0x30-0x39)
 *   ALPHA (0x41-0x5A and 0x61-0x7A)
 *   SHARP (0x23)
 *   SPACE (0x20)
 */
sutf1 [UpAndNormValue value]
    {
        matchedProduction( "sutf1()" );
    }
    :
    rest:CHAR_REST
    { 
        char c = rest.getText().charAt( 0 );
        value.upValue.append( c );
        value.bytes.append( ( byte ) c );
    }
    |
    EQUALS
    { 
        value.upValue.append( '=' );
        value.bytes.append( '=' );
    }
    |
    HYPHEN
    { 
        value.upValue.append( '-' );
        value.bytes.append( '-' );
    }
    |
    UNDERSCORE
    { 
        value.upValue.append( '_' );
        value.bytes.append( '_' );
    }
    |
    digit:DIGIT
    { 
        char c = digit.getText().charAt( 0 );
        value.upValue.append( c );
        value.bytes.append( ( byte ) c );
    }
    |
    alpha:ALPHA
    { 
        char c = alpha.getText().charAt( 0 );
        value.upValue.append( c );
        value.bytes.append( ( byte ) c );
    }
    |
    SHARP
    { 
        value.upValue.append( '#' );
        value.bytes.append( '#' );
    }
    | 
    SPACE
    { 
        value.upValue.append( ' ' );
        value.bytes.append( ' ' );
    }
    | 
    // This is a hack to deal with #NN included into the value, due to 
    // some collision with the HEXVALUE token. In this case, we should
    // consider that a hex value is in fact a String
    hex:HEXVALUE
    {
        String hexStr = hex.getText();
        value.upValue.append( '#' ).append( hexStr );
        value.bytes.append( '#' );
        value.bytes.append( Strings.getBytesUtf8( hexStr ) );
    }
    | 
    // Another hack : having a String like 127.0.0.1 in the value
    // will not match a DIGIT, because it's swallowed by the NUMERICOID
    // token
    numericoid:NUMERICOID  
    {
        String number = numericoid.getText();
        value.upValue.append( number );
        value.bytes.append( Strings.getBytesUtf8( number ) );
    }
    ;


utfmb [UpAndNormValue value]
    {
        matchedProduction( "utfmb()" );
    }
    :
    s:UTFMB
    { 
        char c = s.getText().charAt( 0 );
        value.upValue.append( c );
        value.bytes.append( Unicode.charToBytes( c ) );
    }
    ;


/**
 * RFC 4514, Section 3
 * pair = ESC ( ESC / special / hexpair )
 * special = escaped / SPACE / SHARP / EQUALS
 * escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
 * hexpair = HEX HEX
 *
 * If in <string> form, a LDAP string representation asserted value can
 * be obtained by replacing (left to right, non-recursively) each <pair>
 * appearing in the <string> as follows:
 *   replace <ESC><ESC> with <ESC>;
 *   replace <ESC><special> with <special>;
 *   replace <ESC><hexpair> with the octet indicated by the <hexpair>.
 * 
 * RFC 2253, Section 3
 * pair       = "\" ( special / "\" / QUOTATION / hexpair )
 * special    = "," / "=" / "+" / "<" /  ">" / "#" / ";"
 * 
 * RFC 1779, Section 2.3
 * &lt;pair&gt; ::= "\" ( &lt;special&gt; | "\" | '"')
 * &lt;special&gt; ::= "," | "=" | &lt;CR&gt; | "+" | "&lt;" |  ">"
 *           | "#" | ";"
 * 
 */ 
pair [UpAndNormValue value]
    {
        matchedProduction( "pair()" );
        char specialChar;
    }
    :
    (
        ESCESC 
        { 
            value.upValue.append( "\\\\" );
            value.bytes.append( '\\' );
        } 
    )
    |
    (
        ESCSHARP 
        { 
            value.upValue.append( "\\#" );
            value.bytes.append( '#' );
        } 
    )
    |
    ( 
        ESC
        specialChar = special 
        { 
            value.upValue.append( '\\' ).append( specialChar );
            value.bytes.append( specialChar );
        }
    )
    |
    (
        // A String like "\C4", corresponding to the hex value 0xC4. 
        hexpair:HEXPAIR
        {
            value.upValue.append( '\\' ).append( hexpair.getText() );
            value.bytes.append( Strings.toByteArray( hexpair.getText() ) );
        }
    )
    ;


/**
 * RFC 4514 Section 3
 * 
 * special = escaped / SPACE / SHARP / EQUALS
 * escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
 *
 */
special returns [char special]
    {
        matchedProduction( "special()" );
    }
    :
    (
        DQUOTE { special = '"'; }
        |
        PLUS { special = '+'; }
        |
        COMMA { special = ','; }
        |
        SEMI { special = ';'; }
        |
        LANGLE { special = '<'; }
        |
        RANGLE { special = '>'; }
        |
        SPACE { special = ' '; }
        |
        SHARP { special = '#'; }
        |
        EQUALS { special = '='; }
    )
    ;

