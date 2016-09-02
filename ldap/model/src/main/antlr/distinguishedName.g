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
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.BinaryValue;
import org.apache.directory.api.ldap.model.schema.parsers.ParserMonitor;
import org.apache.directory.api.util.Strings;

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
LUTF1_REST : 
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
    static class UpAndNormValue
    {
        Object value = "";
        String rawValue = "";
		int lastEscapedSpace = -1;
    }
}

    /**
     * Parses an Dn string.
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
distinguishedName [Dn dn]
    {
        matchedProduction( "distinguishedName()" );
        Rdn rdn = null;
    }
    :
    (
        rdn = relativeDistinguishedName[new Rdn()] 
        { 
            try
            { 
                dn.add( rdn ); 
            }
            catch ( LdapInvalidDnException lide )
            {
                // Do nothing, can't get an exception here
            } 
                
            rdn=null; 
        }
        (
            ( COMMA | SEMI )
            rdn = relativeDistinguishedName[new Rdn()] 
            { 
                try
                { 
                    dn.add( rdn ); 
                }
                catch ( LdapInvalidDnException lide )
                {
                    // Do nothing, can't get an exception here
                } 

                rdn=null;
            }
        )*
        EOF
    )?
    ;


    /**
     * Parses an Dn string.
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
relativeDistinguishedNames [List<Rdn> rdns]
    {
        matchedProduction( "relativeDistinguishedNames()" );
        Rdn rdn = null;
    }
    :
    (
        rdn = relativeDistinguishedName[new Rdn()] 
        { 
            rdns.add( rdn );
        }
        (
            ( COMMA | SEMI )
            rdn = relativeDistinguishedName[new Rdn()] 
            { 
                rdns.add( rdn ); 
            }
        )*
        EOF
    )?
    ;

    /**
     * Parses an Rdn string.
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
relativeDistinguishedName [Rdn initialRdn] returns [Rdn rdn]
    {
        matchedProduction( "relativeDistinguishedName()" );
        rdn = initialRdn;
        String tmp;
        String upName = "";
    }
    :
    (
        tmp = attributeTypeAndValue[rdn] 
        { 
            upName += tmp;
        }
        (
            PLUS { upName += "+"; }
            tmp = attributeTypeAndValue[rdn] 
            { 
                upName += tmp;
            }
        )*
    )
    {
        rdn.normalize();
        rdn.setUpName( upName );
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
attributeTypeAndValue [Rdn rdn] returns [String upName = ""]
    {
        matchedProduction( "attributeTypeAndValue()" );
        String type = null;
        UpAndNormValue value = new UpAndNormValue();
        String upValue = null;
    }
    :
    (
        ( SPACE { upName += " "; } )*
        type = attributeType { upName += type; }
        ( SPACE { upName += " "; } )*
        EQUALS { upName += "="; }
        ( SPACE 
        { 
            upName += " "; 
            
            if ( upValue == null )
            {
                upValue = " ";
            }
            else
            {
                upValue += " "; 
            } 
        } )*
        attributeValue[value] 
        {
            try
            {
                upName += value.rawValue;
                Ava ava = null;
            
                if ( value.value instanceof String )
                {
                    if ( upValue != null )
                    {
                        value.rawValue = upValue + value.rawValue;
                    }
                    
					int start = 0;
		
					for ( int pos = 0; pos < value.rawValue.length(); pos++ )
					{
					    if ( value.rawValue.charAt( pos ) == ' ' )
					    {
					        start++;
					    }
					    else
					    {
					        break;
					    }
					}
		
					boolean escape = false;
					int lastEscapedSpace = -1;
					
					for ( int pos = start; pos< value.rawValue.length(); pos++ )
					{
					    if ( escape )
					    {
					        escape = false;
		        
					        if ( value.rawValue.charAt( pos ) == ' ' )
					        {
					            lastEscapedSpace = pos;
					        }
					    }
					    else if ( value.rawValue.charAt( pos ) == '\\' )
					    {
					        escape = true;
					    }
					}
		
					// Remove spaces from the right if needed
					int pos = value.rawValue.length() - 1;
		
					while ( ( value.rawValue.charAt( pos ) == ' ' ) && ( pos > lastEscapedSpace ) )
					{
					    pos--;
					}
					
					String trimmedValue = value.rawValue;
					
					if ( ( start > 0 ) || ( pos + 1 < value.rawValue.length() ) )
					{
						trimmedValue = value.rawValue.substring( start, pos + 1 );
					}
					
					Object unescapedValue = Rdn.unescapeValue( trimmedValue );
                    
                    if ( unescapedValue instanceof String )
                    {
                        ava = new Ava(
                            type,
                            type,
                            new StringValue( trimmedValue, (String)unescapedValue ),
                            upName
                        );
                    }
                    else
                    {
                        ava = new Ava(
                            type,
                            type,
                            new BinaryValue( (byte[])unescapedValue ),
                            upName
                        );
                    }
                }
                else
                {
                    ava = new Ava(
                        type,
                        type,
                        new BinaryValue( (byte[])value.value ), 
                        upName
                    );
                }
           
                rdn.addAVA( null, ava );
            }
            catch ( LdapInvalidDnException e )
            {
                throw new SemanticException( e.getMessage() );
            } 
        }
    )
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
    }
    :
    leadkeychar:ALPHA { descr = leadkeychar.getText(); }
    (
        alpha:ALPHA { descr += alpha.getText(); }
        |
        digit:DIGIT { descr += digit.getText(); }
        |
        hyphen:HYPHEN { descr += hyphen.getText(); }
        |
        underscore:UNDERSCORE { descr += underscore.getText(); }
    )*
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
    noid:NUMERICOID { numericoid += noid.getText(); }
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
     */    
attributeValue [UpAndNormValue value]
    {
        matchedProduction( "attributeValue()" );
    }
    :
    (
        (
            quotestring [value]
            ( SPACE { value.rawValue += " "; } )*
        )
        |
        string [value]
        |
        (
            hexstring [value]
            ( SPACE { value.rawValue += " "; } )*
        )
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
        org.apache.directory.api.util.ByteBuffer bb = new org.apache.directory.api.util.ByteBuffer();
        byte[] bytes;
    }
    :
    (
        dq1:DQUOTE { value.rawValue += dq1.getText(); }
        (
            (
                s:~(DQUOTE|ESC|ESCESC|ESCSHARP|HEXPAIR) 
                {
                    value.rawValue += s.getText();
                    bb.append( Strings.getBytesUtf8( s.getText() ) );
                }
            )
            |
            bytes = pair[value] { bb.append( bytes ); }
        )*
        dq2:DQUOTE { value.rawValue += dq2.getText(); }
    )
    {
        String string = Strings.utf8ToString( bb.copyOfUsedBytes() );
        value.value = string;
    }
    ;


    /**
     * RFC 4514 Section 3
     *
     * hexstring = SHARP 1*hexpair
     *
     * If in &lt;hexstring&gt; form, a BER representation can be obtained from
     * converting each &lt;hexpair&gt; of the &lt;hexstring&gt; to the octet indicated
     * by the &lt;hexpair&gt;.
     *
     */ 
hexstring [UpAndNormValue value]
    {
        matchedProduction( "hexstring()" );
    }
    :
    hexValue:HEXVALUE
    {
        // convert to byte[]
        value.rawValue = "#" + hexValue.getText();
        value.value = Strings.toByteArray( hexValue.getText() ); 
    }
    ;


    /**
     * RFC 4514 Section 3
     *
     * ; The following characters are to be escaped when they appear
     * ; in the value to be encoded: ESC, one of &lt;escaped&gt;, leading
     * ; SHARP or SPACE, trailing SPACE, and NULL.
     * string =   [ ( leadchar / pair ) [ *( stringchar / pair )
     *    ( trailchar / pair ) ] ]
     *
     */ 
string [UpAndNormValue value]
    {
        matchedProduction( "string()" );
        org.apache.directory.api.util.ByteBuffer bb = new org.apache.directory.api.util.ByteBuffer();
        String tmp;
        byte[] bytes;
    }
    :
    (
        (
            tmp = lutf1 
            { 
                value.rawValue += tmp;
                bb.append( Strings.getBytesUtf8( tmp ) );
            }
            |
            tmp = utfmb 
            {
                value.rawValue += tmp;
                bb.append( Strings.getBytesUtf8( tmp ) );
            }
            |
            bytes = pair [value] 
			{ 
				bb.append( bytes );
			}
        )
        ( 
            tmp = sutf1
            {
                value.rawValue += tmp;
                bb.append( Strings.getBytesUtf8( tmp ) );
            }
            |
            tmp = utfmb 
            {
                value.rawValue += tmp;
                bb.append( Strings.getBytesUtf8( tmp ) );
            }
            |
            bytes = pair [value] 
			{ 
				bb.append( bytes ); 
			}
        )*
    )
    {
		/*
        String string = Strings.utf8ToString( bb.copyOfUsedBytes() );
        
        // trim trailing space characters manually
        // don't know how to tell antlr that the last char mustn't be a space.
        int rawIndex = value.rawValue.length();
        while ( string.length() > 0 && rawIndex > 1 
            && value.rawValue.charAt( rawIndex - 1 ) == ' ' 
            && value.rawValue.charAt( rawIndex - 2 ) != '\\' )
        {
            string = string.substring( 0, string.length() - 1 );
            rawIndex--;
        }
        
        value.value = string;
		*/
    }
    ;


/**
 * RFC 4514, Section 3:
 * LUTF1 = %x01-1F / %x21 / %x24-2A / %x2D-3A /
 *    %x3D / %x3F-5B / %x5D-7F
 *
 * The rule LUTF1_REST doesn't contain the following charcters,
 * so we must check them additionally
 *   EQUALS (0x3D)
 *   HYPHEN (0x2D)
 *   UNDERSCORE (0x5F)
 *   DIGIT (0x30-0x39)
 *   ALPHA (0x41-0x5A and 0x61-0x7A)
 */
lutf1 returns [String lutf1=""]
    {
        matchedProduction( "lutf1()" );
    }
    :
    rest:LUTF1_REST { lutf1 = rest.getText(); }
    |
    equals:EQUALS { lutf1 = equals.getText(); }
    |
    hyphen:HYPHEN { lutf1 = hyphen.getText(); }
    |
    underscore:UNDERSCORE { lutf1 = underscore.getText(); }
    |
    digit:DIGIT { lutf1 = digit.getText(); }
    |
    alpha:ALPHA { lutf1 = alpha.getText(); }
    | 
    numericoid:NUMERICOID  { lutf1 = numericoid.getText(); }    
    ;
    
/**
 * RFC 4514, Section 3:
 * SUTF1 = %x01-21 / %x23-2A / %x2D-3A /
 *    %x3D / %x3F-5B / %x5D-7F
 *
 * The rule LUTF1_REST doesn't contain the following charcters,
 * so we must check them additionally
 *   EQUALS (0x3D)
 *   HYPHEN (0x2D)
 *   UNDERSCORE (0x5F)
 *   DIGIT (0x30-0x39)
 *   ALPHA (0x41-0x5A and 0x61-0x7A)
 *   SHARP
 *   SPACE
 */
sutf1 returns [String sutf1=""]
    {
        matchedProduction( "sutf1()" );
    }
    :
    rest:LUTF1_REST { sutf1 = rest.getText(); }
    |
    equals:EQUALS { sutf1 = equals.getText(); }
    |
    hyphen:HYPHEN { sutf1 = hyphen.getText(); }
    |
    underscore:UNDERSCORE { sutf1 = underscore.getText(); }
    |
    digit:DIGIT { sutf1 = digit.getText(); }
    |
    alpha:ALPHA { sutf1 = alpha.getText(); }
    |
    sharp:SHARP { sutf1 = sharp.getText(); }
    | 
    space:SPACE  { sutf1 = space.getText(); }
    | 
    // This is a hack to deal with #NN included into the value, due to 
    // some collision with the HEXVALUE token. In this case, we should
    // consider that a hex value is in fact a String
    hex:HEXVALUE { sutf1 = "#" + hex.getText(); }
    |
    numericoid:NUMERICOID  { sutf1 = numericoid.getText(); }    
    ;    


utfmb returns [String utfmb]
    {
        matchedProduction( "utfmb()" );
    }
    :
    s:UTFMB { utfmb = s.getText(); }
    ;


    /**
     * RFC 4514, Section 3
     * pair = ESC ( ESC / special / hexpair )
     * special = escaped / SPACE / SHARP / EQUALS
     * escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
     * hexpair = HEX HEX
     *
     * If in &lt;string&gt; form, a LDAP string representation asserted value can
     * be obtained by replacing (left to right, non-recursively) each &lt;pair&gt;
     * appearing in the &lt;string&gt; as follows:
     *   replace &lt;ESC&gt;&lt;ESC&gt; with &lt;ESC&gt;;
     *   replace &lt;ESC&gt;&lt;special&gt; with &lt;special&gt;;
     *   replace &lt;ESC&gt;&lt;hexpair&gt; with the octet indicated by the &lt;hexpair&gt;.
     * 
     * RFC 2253, Section 3
     * pair       = "\" ( special / "\" / QUOTATION / hexpair )
     * special    = "," / "=" / "+" / "&lt;" /  "&gt;" / "#" / ";"
     * 
     * RFC 1779, Section 2.3
     * &lt;pair&gt; ::= "\" ( &lt;special&gt; | "\" | '"')
     * &lt;special&gt; ::= "," | "=" | &lt;CR&gt; | "+" | "&lt;" |  "&gt;"
     *           | "#" | ";"
     * 
     */ 
pair [UpAndNormValue value] returns [byte[] pair]
    {
        matchedProduction( "pair()" );
        String tmp;
    }
    :
    (
        ESCESC 
        { 
            value.rawValue += "\\\\";
            pair = Strings.getBytesUtf8( "\\" );
        } 
    )
    |
    (
        ESCSHARP 
        { 
            value.rawValue += "\\#";
            pair = Strings.getBytesUtf8( "#" );
        } 
    )
    |
    ( 
        ESC
        tmp = special 
        { 
            value.rawValue += "\\" + tmp;
            pair = Strings.getBytesUtf8( tmp );
        }
    )
    |
    ( 
        hexpair:HEXPAIR 
        { 
            value.rawValue += "\\" + hexpair.getText();
            pair = Strings.toByteArray( hexpair.getText() ); 
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
special returns [String special]
    {
        matchedProduction( "special()" );
    }
    :
    (
        dquote:DQUOTE { special = dquote.getText(); }
        |
        plus:PLUS { special = plus.getText(); }
        |
        comma:COMMA { special = comma.getText(); }
        |
        semi:SEMI { special = semi.getText(); }
        |
        langle:LANGLE { special = langle.getText(); }
        |
        rangle:RANGLE { special = rangle.getText(); }
        |
        space:SPACE { special = space.getText(); }
        |
        sharp:SHARP { special = sharp.getText(); }
        |
        equals:EQUALS { special = equals.getText(); }
    )
    ;

