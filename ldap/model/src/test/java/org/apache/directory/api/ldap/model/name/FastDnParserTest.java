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


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the fast Dn parser.
 * 
 * The test cases are copied from DnParserTest and adjusted when an
 * TooComplexDnException is expected.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class FastDnParserTest
{

    /**
     * test an empty Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNEmpty() throws LdapException
    {
        assertEquals( "", FastDnParser.parse( "" ).getName() );
    }


    /**
     * Tests incomplete DNs, used to check that the parser does not
     * run into infinite loops.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNIncomplete() throws LdapException
    {
        // empty Dn is ok
        FastDnParser.parse( " " );

        // test DNs starting with an descr
        try
        {
            FastDnParser.parse( " a" );
            fail();
        }
        catch ( LdapException ine )
        {
            // expected
        }
        try
        {
            FastDnParser.parse( " a " );
            fail();
        }
        catch ( LdapException ine )
        {
            // expected
        }
        try
        {
            FastDnParser.parse( " a- " );
            fail();
        }
        catch ( LdapException ine )
        {
            // expected
        }
        FastDnParser.parse( " a =" );
        FastDnParser.parse( " a = " );
        FastDnParser.parse( " a = b" );

        // test DNs starting with an OID
        try
        {
            FastDnParser.parse( " 1 = b " );
            fail( "OID must contain at least on dot." );
        }
        catch ( LdapException ine )
        {
            // expected
        }
        try
        {
            FastDnParser.parse( " 0" );
            fail();
        }
        catch ( LdapException ine )
        {
            // expected
        }
        try
        {
            FastDnParser.parse( " 0." );
            fail();
        }
        catch ( LdapException ine )
        {
            // expected
        }
        try
        {
            FastDnParser.parse( " 0.5" );
            fail();
        }
        catch ( LdapException ine )
        {
            // expected
        }
        try
        {
            FastDnParser.parse( " 0.5 " );
            fail();
        }
        catch ( LdapException ine )
        {
            // expected
        }

        FastDnParser.parse( " 0.5=" );
        FastDnParser.parse( " 0.5 = " );
        FastDnParser.parse( " 0.5 = b" );
    }


    /**
     * test a simple Dn : a = b
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNSimple() throws LdapException
    {
        Dn dn = FastDnParser.parse( "a = b" );

        assertEquals( "a = b", dn.getName() );
        assertEquals( "a=b", dn.getEscaped() );
        assertEquals( "a = b", dn.toString() );

        assertEquals( "a = b", dn.getRdn().getName() );
        assertEquals( "a=b", dn.getRdn().getEscaped() );

        assertEquals( "a=b", dn.getRdn().getAva().getName() );
        assertEquals( "a=b", dn.getRdn().getAva().getEscaped() );

        assertEquals( "a", dn.getRdn().getAva().getType() );
        assertEquals( "a", dn.getRdn().getAva().getNormType() );
        assertEquals( "b", dn.getRdn().getAva().getValue().getString() );
        assertEquals( "b", dn.getRdn().getAva().getValue().getString() );
    }


    /**
     * test a composite Dn : a = b, d = e
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNComposite() throws LdapException
    {
        Dn dn = FastDnParser.parse( "a = b, c = d" );
        assertEquals( "a=b,c=d", dn.getEscaped() );
        assertEquals( "a = b, c = d", dn.getName() );
    }


    /**
     * test a composite Dn with or without spaces: a=b, a =b, a= b, a = b, a = b
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNCompositeWithSpace() throws LdapException
    {
        Dn dn = FastDnParser.parse( "a=b, a =b, a= b, a = b, a  =  b" );
        assertEquals( "a=b,a=b,a=b,a=b,a=b", dn.getEscaped() );
        assertEquals( "a=b, a =b, a= b, a = b, a  =  b", dn.getName() );
    }


    /**
     * test a composite Dn with differents separators : a=b;c=d,e=f It should
     * return a=b,c=d,e=f (the ';' is replaced by a ',')
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNCompositeSepators() throws LdapException
    {
        Dn dn = FastDnParser.parse( "a=b;c=d,e=f" );
        assertEquals( "a=b,c=d,e=f", dn.getEscaped() );
        assertEquals( "a=b;c=d,e=f", dn.getName() );
    }

    /**
     * Test an attributeType with '_' (Microsoft morons support...)
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testAttributeTypeWithUnderscore() throws LdapException
    {
        Dn dn = FastDnParser.parse( "microsoft_developpers=morons" );
        assertEquals( "microsoft_developpers=morons", dn.getEscaped() );
    }

    
    /**
     * test a simple Dn with multiple NameComponents : a = b + c = d
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNSimpleMultivaluedAttribute() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "a = b + c = d" );
        } );
    }


    /**
     * test a composite Dn with multiple NC and separators : a=b+c=d, e=f + g=h +
     * i=j
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNCompositeMultivaluedAttribute() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "a=b+c=d, e=f + g=h + i=j" );
        } );
    }


    /**
     * test a simple Dn with an oid prefix (uppercase) : OID.12.34.56 = azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNOidUpper() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "OID.12.34.56 = azerty" );
        } );
    }


    /**
     * test a simple Dn with an oid prefix (lowercase) : oid.12.34.56 = azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNOidLower() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "oid.12.34.56 = azerty" );
        } );
    }


    /**
     * test a simple Dn with an oid attribut without oid prefix : 12.34.56 =
     * azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNOidWithoutPrefix() throws LdapException
    {
        Dn dn = FastDnParser.parse( "12.34.56 = azerty" );
        assertEquals( "12.34.56=azerty", dn.getEscaped() );
        assertEquals( "12.34.56 = azerty", dn.getName() );
    }


    /**
     * test a composite Dn with an oid attribut wiithout oid prefix : 12.34.56 =
     * azerty; 7.8 = test
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNCompositeOidWithoutPrefix() throws LdapException
    {
        Dn dn = FastDnParser.parse( "12.34.56 = azerty; 7.8 = test" );
        assertEquals( "12.34.56=azerty,7.8=test", dn.getEscaped() );
        assertEquals( "12.34.56 = azerty; 7.8 = test", dn.getName() );
    }


    /**
     * test a simple Dn with pair char attribute value : a = \,\=\+\&lt;\&gt;\#\;\\\"\C3\A9"
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNPairCharAttributeValue() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "a = \\,\\=\\+\\<\\>\\#\\;\\\\\\\"\\C3\\A9" );
        } );
    }


    /**
     * test a simple Dn with hexString attribute value : a = #0010A0AAFF
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNHexStringAttributeValue() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "a = #0010A0AAFF" );
        } );
    }


    /**
     * test exception from illegal hexString attribute value : a=#zz.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testBadLdapDNHexStringAttributeValue() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "a=#zz" );
        } );
    }


    /**
     * test a simple Dn with quoted attribute value : a = "quoted \"value"
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNQuotedAttributeValue() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "a = quoted \\\"value" );
        } );
    }


    @Test
    public void testStringParser() throws LdapException
    {
        String dn = Strings.utf8ToString( new byte[]
            { 'C', 'N', ' ', '=', ' ', 'E', 'm', 'm', 'a', 'n', 'u', 'e', 'l', ' ', ' ', 'L', ( byte ) 0xc3,
                ( byte ) 0xa9, 'c', 'h', 'a', 'r', 'n', 'y' } );

        Dn name = FastDnParser.parse( dn );

        assertEquals( "CN = Emmanuel  L\u00e9charny", name.getName() );
        assertEquals( "CN=Emmanuel  L\u00e9charny", name.getEscaped() );
    }


    @Test
    public void testStringParserShort() throws LdapException
    {
        String dn = Strings.utf8ToString( new byte[]
            { 'C', '=', ' ', 'E', ( byte ) 0xc3, ( byte ) 0xa9, 'c' } );

        Dn name = FastDnParser.parse( dn );

        assertEquals( "C= E\u00e9c", name.getName() );
        assertEquals( "C=E\u00e9c", name.getEscaped() );
    }


    @Test
    public void testVsldapExtras() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser
                .parse( "cn=Billy Bakers, OID.2.5.4.11=Corporate Tax, ou=Fin-Accounting, ou=Americas, ou=Search, o=IMC, c=US" );
        } );
    }


    /**
     * Class under test for Name parse(String)
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public final void testParseStringEmpty() throws LdapException
    {
        Dn nameEmpty = FastDnParser.parse( "" );

        assertNotNull( nameEmpty );
    }


    /**
     * Class under test for Name parse(String)
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public final void testParseStringNull() throws LdapException
    {
        Dn nameNull = FastDnParser.parse( null );

        assertEquals( "", nameNull.toString(), "Null Dn are legal : " );
    }


    /**
     * Class under test for Name parse(String)
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public final void testParseStringRFC1779_1() throws LdapException
    {
        Dn nameRFC1779_1 = FastDnParser
            .parse( "CN=Marshall T. Rose, O=Dover Beach Consulting, L=Santa Clara, ST=California, C=US" );

        assertEquals( 
            "CN=Marshall T. Rose, O=Dover Beach Consulting, L=Santa Clara, ST=California, C=US",
            nameRFC1779_1.getName(), "RFC1779_1 : " );
        assertEquals( "CN=Marshall T. Rose,O=Dover Beach Consulting,L=Santa Clara,ST=California,C=US",
            nameRFC1779_1.getEscaped(), "RFC1779_1 : " );
    }


    /**
     * Class under test for Name parse(String)
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public final void testParseStringRFC2253_1() throws LdapException
    {
        Dn nameRFC2253_1 = FastDnParser.parse( "CN=Steve Kille,O=Isode limited,C=GB" );

        assertEquals( "CN=Steve Kille,O=Isode limited,C=GB", nameRFC2253_1.getName(), "RFC2253_1 : " );
    }


    /**
     * Class under test for Name parse(String)
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public final void testParseStringRFC2253_2() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "CN = Sales + CN =   J. Smith , O = Widget Inc. , C = US" );
        } );
    }


    /**
     * Class under test for Name parse(String)
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public final void testParseStringRFC2253_3() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "CN=L. Eagle,   O=Sue\\, Grabbit and Runn, C=GB" );
        } );
    }


    /**
     * Class under test for Name parse(String)
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public final void testParseStringRFC2253_4() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "CN=Before\\0DAfter,O=Test,C=GB" );
        } );
    }


    /**
     * Class under test for Name parse(String)
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public final void testParseStringRFC2253_5() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB" );
        } );
    }


    /**
     * Class under test for Name parse(String)
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public final void testParseStringRFC2253_6() throws LdapException
    {
        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( "SN=Lu\\C4\\8Di\\C4\\87" );
        } );
    }


    /**
     * Class under test for Name parse(String)
     */
    @Test
    public final void testParseInvalidString()
    {
        try
        {
            FastDnParser.parse( "&#347;=&#347;rasulu,dc=example,dc=com" );
            fail( "the invalid name should never succeed in a parse" );
        }
        catch ( LdapException e )
        {
            assertNotNull( e );
        }
    }


    /**
     * Tests to see if inner whitespace is preserved after an escaped ',' in a
     * value of a name component. This test was added to try to reproduce the
     * bug encountered in DIRSERVER-297 <a
     * href="https://issues.apache.org/jira/browse/DIRSERVER-297"> here</a>.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public final void testPreserveSpaceAfterEscape() throws LdapException
    {
        String input = "ou=some test\\,  something else";

        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( input ).toString();
        } );
    }


    @Test
    public void testWindowsFilePath() throws Exception
    {
        // '\' should be escaped as stated in RFC 2253
        String path = "windowsFilePath=C:\\\\cygwin";

        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( path );
        } );
    }


    @Test
    public void testNameFrenchChars() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', 0x4A, ( byte ) 0xC3, ( byte ) 0xA9, 0x72, ( byte ) 0xC3, ( byte ) 0xB4, 0x6D, 0x65 },
            StandardCharsets.UTF_8 );

        String result = FastDnParser.parse( cn ).toString();

        assertEquals( "cn=J\u00e9r\u00f4me", result );
    }


    @Test
    public void testNameGermanChars() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC3, ( byte ) 0x84, ( byte ) 0xC3, ( byte ) 0x96, ( byte ) 0xC3, ( byte ) 0x9C,
                ( byte ) 0xC3, ( byte ) 0x9F, ( byte ) 0xC3, ( byte ) 0xA4, ( byte ) 0xC3, ( byte ) 0xB6,
                ( byte ) 0xC3, ( byte ) 0xBC }, StandardCharsets.UTF_8 );

        String result = FastDnParser.parse( cn ).toString();

        assertEquals( "cn=\u00C4\u00D6\u00DC\u00DF\u00E4\u00F6\u00FC", result );
    }


    /**
     * Test that we can have non-ascii characters in a DN when we use the 
     * fast DN parser
     * 
     * @throws Exception If the test failed
     */
    @Test
    public void testNameTurkishChars() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC4, ( byte ) 0xB0, ( byte ) 0xC4, ( byte ) 0xB1, ( byte ) 0xC5, ( byte ) 0x9E,
                ( byte ) 0xC5, ( byte ) 0x9F, ( byte ) 0xC3, ( byte ) 0x96, ( byte ) 0xC3, ( byte ) 0xB6,
                ( byte ) 0xC3, ( byte ) 0x9C, ( byte ) 0xC3, ( byte ) 0xBC, ( byte ) 0xC4, ( byte ) 0x9E,
                ( byte ) 0xC4, ( byte ) 0x9F }, StandardCharsets.UTF_8 );

        String result = FastDnParser.parse( cn ).toString();

        assertEquals( "cn=\u0130\u0131\u015E\u015F\u00D6\u00F6\u00DC\u00FC\u011E\u011F", result );

    }


    /**
     * Test that we can have non-ascii characters in a DN when we use the 
     * fast DN parser, but not followded by bytes
     */
    @Test
    public void testAUmlautPlusBytes()
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC3, ( byte ) 0x84, 0x5C, 0x32, 0x42 }, StandardCharsets.UTF_8 );

        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( cn ).toString();
        } );
    }


    /**
     * Test that we can't have escaped characters in a DN when we use the 
     * fast DN parser
     */
    @Test
    public void testAUmlautPlusChar()
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC3, ( byte ) 0x84, '\\', '+' }, StandardCharsets.UTF_8 );

        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( cn ).toString();
        } );
    }


    /**
     * Test to check that even with a non escaped char, the Dn is parsed ok
     * or at least an error is generated.
     */
    @Test
    public final void testNonEscapedChars()
    {
        String input = "ou=ou+test";

        assertThrows( TooComplexDnException.class, () -> 
        {
            FastDnParser.parse( input ).toString();
        } );
    }
}
