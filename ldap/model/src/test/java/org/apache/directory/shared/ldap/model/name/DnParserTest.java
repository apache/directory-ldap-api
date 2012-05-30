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
package org.apache.directory.shared.ldap.model.name;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.shared.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the class Dn
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class DnParserTest
{
    /**
     * test an empty Dn
     */
    @Test
    public void testLdapDNEmpty() throws LdapException
    {
        Dn dn = new Dn( "" );

        assertEquals( "", dn.getName() );
    }


    /**
     * test a simple Dn : a = b
     */
    @Test
    public void testLdapDNSimple() throws LdapException
    {
        Dn dn = new Dn( "a = b" );

        assertEquals( "a = b", dn.getName() );
        assertEquals( "a=b", dn.getNormName() );
    }


    /**
     * test a composite Dn : a = b, d = e
     */
    @Test
    public void testLdapDNComposite() throws LdapException
    {
        Dn dn = new Dn( "a = b, c = d" );

        assertEquals( "a=b,c=d", dn.getNormName() );
        assertEquals( "a = b, c = d", dn.getName() );
    }


    /**
     * test a composite Dn with or without spaces: a=b, a =b, a= b, a = b, a = b
     */
    @Test
    public void testLdapDNCompositeWithSpace() throws LdapException
    {
        Dn dn = new Dn( "a=b, a =b, a= b, a = b, a  =  b" );
        assertEquals( "a=b,a=b,a=b,a=b,a=b", dn.getNormName() );
        assertEquals( "a=b, a =b, a= b, a = b, a  =  b", dn.getName() );
    }


    /**
     * test a composite Dn with differents separators : a=b;c=d,e=f It should
     * return a=b,c=d,e=f (the ';' is replaced by a ',')
     */
    @Test
    public void testLdapDNCompositeSepators() throws LdapException
    {
        Dn dn = new Dn( "a=b;c=d,e=f" );
        assertEquals( "a=b,c=d,e=f", dn.getNormName() );
        assertEquals( "a=b;c=d,e=f", dn.getName() );
    }


    /**
     * test a simple Dn with multiple NameComponents : a = b + c = d
     */
    @Test
    public void testLdapDNSimpleMultivaluedAttribute() throws LdapException
    {
        Dn dn = new Dn( "a = b + c = d" );
        assertEquals( "a=b+c=d", dn.getNormName() );
        assertEquals( "a = b + c = d", dn.getName() );
    }


    /**
     * test a composite Dn with multiple NC and separators : a=b+c=d, e=f + g=h +
     * i=j
     */
    @Test
    public void testLdapDNCompositeMultivaluedAttribute() throws LdapException
    {
        Dn dn = new Dn( "a=b+c=d, e=f + g=h + i=j" );
        assertEquals( "a=b+c=d,e=f+g=h+i=j", dn.getNormName() );
        assertEquals( "a=b+c=d, e=f + g=h + i=j", dn.getName() );
    }


    /**
     * test a simple Dn with an oid prefix (uppercase) : OID.12.34.56 = azerty
     */
    @Test
    public void testLdapDNOidUpper() throws LdapException
    {
        Dn dn = new Dn( "OID.12.34.56 = azerty" );
        assertEquals( "oid.12.34.56=azerty", dn.getNormName() );
        assertEquals( "OID.12.34.56 = azerty", dn.getName() );
    }


    /**
     * test a simple Dn with an oid prefix (lowercase) : oid.12.34.56 = azerty
     */
    @Test
    public void testLdapDNOidLower() throws LdapException
    {
        Dn dn = new Dn( "oid.12.34.56 = azerty" );
        assertEquals( "oid.12.34.56=azerty", dn.getNormName() );
        assertEquals( "oid.12.34.56 = azerty", dn.getName() );
    }


    /**
     * test a simple Dn with an oid attribut without oid prefix : 12.34.56 =
     * azerty
     */
    @Test
    public void testLdapDNOidWithoutPrefix() throws LdapException
    {
        Dn dn = new Dn( "12.34.56 = azerty" );
        assertEquals( "12.34.56=azerty", dn.getNormName() );
        assertEquals( "12.34.56 = azerty", dn.getName() );
    }


    /**
     * test a composite Dn with an oid attribut wiithout oid prefix : 12.34.56 =
     * azerty; 7.8 = test
     */
    @Test
    public void testLdapDNCompositeOidWithoutPrefix() throws LdapException
    {
        Dn dn = new Dn( "12.34.56 = azerty; 7.8 = test" );
        assertEquals( "12.34.56=azerty,7.8=test", dn.getNormName() );
        assertEquals( "12.34.56 = azerty; 7.8 = test", dn.getName() );
    }


    /**
     * test a simple Dn with pair char attribute value : a = \,\=\+\<\>\#\;\\\"\C3\A9"
     */
    @Test
    public void testLdapDNPairCharAttributeValue() throws LdapException
    {
        Dn dn = new Dn( "a = \\,\\=\\+\\<\\>\\#\\;\\\\\\\"\\C3\\A9" );
        assertEquals( "a=\\,\\=\\+\\<\\>#\\;\\\\\\\"\\C3\\A9", dn.getNormName() );
        assertEquals( "a = \\,\\=\\+\\<\\>\\#\\;\\\\\\\"\\C3\\A9", dn.getName() );

        dn = new Dn( "a = \\,\\=\\+\\<\\>\\#\\;\\\\\\\"\u00e9" );
        assertEquals( "a=\\,\\=\\+\\<\\>#\\;\\\\\\\"\\C3\\A9", dn.getNormName() );
        assertEquals( "a = \\,\\=\\+\\<\\>\\#\\;\\\\\\\"\u00e9", dn.getName() );
    }


    /**
     * test a simple Dn with hexString attribute value : a = #0010A0AAFF
     */
    @Test
    public void testLdapDNHexStringAttributeValue() throws LdapException
    {
        Dn dn = new Dn( "a = #0010A0AAFF" );
        assertEquals( "a=#0010A0AAFF", dn.getNormName() );
        assertEquals( "a = #0010A0AAFF", dn.getName() );
    }


    /**
     * test exception from illegal hexString attribute value : a=#zz.
     */
    @Test
    public void testBadLdapDNHexStringAttributeValue() throws LdapException
    {
        try
        {
            new Dn( "a=#zz" );
            fail();
        }
        catch ( LdapInvalidDnException ine )
        {
            assertTrue( true );
        }
    }


    /**
     * test a simple Dn with quoted attribute value : a = "quoted \"value"
     */
    @Test
    public void testLdapDNQuotedAttributeValue() throws LdapException
    {
        Dn dn = new Dn( "a = quoted \\\"value" );
        assertEquals( "a=quoted \\\"value", dn.getNormName() );
        assertEquals( "a = quoted \\\"value", dn.getName() );

        dn = new Dn( "cn=Mackie \\\"The Knife\\\" Messer" );
        assertEquals( "cn=Mackie \\\"The Knife\\\" Messer", dn.getNormName() );
        assertEquals( "cn=Mackie \\\"The Knife\\\" Messer", dn.getName() );
    }


    /**
     * Tests a corner case of the parser because the sequence "\DC" is also a valid hex pair
     */
    @Test
    public void testLdapDNBackslashInAttributeValue() throws LdapException
    {
        Dn dn = new Dn( "a = AC\\\\DC" );
        assertEquals( "a=AC\\\\DC", dn.getNormName() );
        assertEquals( "a = AC\\\\DC", dn.getName() );
    }


    /**
     * Test the encoding of a LdanDN
     */
    @Test
    public void testNameToBytes() throws LdapException
    {
        Dn dn = new Dn( "cn = John, ou = People, OU = Marketing" );

        byte[] bytes = Dn.getBytes( dn );

        assertEquals( 30, bytes.length );
        assertEquals( "cn=John,ou=People,ou=Marketing", Strings.utf8ToString( bytes ) );
    }


    @Test
    public void testStringParser() throws LdapException
    {
        String dn = Strings.utf8ToString( new byte[]
            { 'C', 'N', ' ', '=', ' ', 'E', 'm', 'm', 'a', 'n', 'u', 'e', 'l', ' ', ' ', 'L', ( byte ) 0xc3,
                ( byte ) 0xa9, 'c', 'h', 'a', 'r', 'n', 'y' } );

        Dn name = new Dn( dn );

        assertEquals( dn, name.getName() );
        assertEquals( "cn=Emmanuel  L\\C3\\A9charny", name.getNormName() );
    }


    @Test
    public void testStringParserShort() throws LdapException
    {
        String dn = Strings.utf8ToString( new byte[]
            { 'C', '=', ' ', 'E', ( byte ) 0xc3, ( byte ) 0xa9, 'c' } );

        Dn name = new Dn( dn );

        assertEquals( dn, name.getName() );
        assertEquals( "c=E\\C3\\A9c", name.getNormName() );
    }


    @Test
    public void testVsldapExtras() throws LdapException
    {
        Dn name = new Dn(
            "cn=Billy Bakers, OID.2.5.4.11=Corporate Tax, ou=Fin-Accounting, ou=Americas, ou=Search, o=IMC, c=US" );

        assertEquals(
            "cn=Billy Bakers, OID.2.5.4.11=Corporate Tax, ou=Fin-Accounting, ou=Americas, ou=Search, o=IMC, c=US", name
                .getName() );
        assertEquals(
            "cn=Billy Bakers,oid.2.5.4.11=Corporate Tax,ou=Fin-Accounting,ou=Americas,ou=Search,o=IMC,c=US", name
                .getNormName() );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException
     *             if anything goes wrong
     */
    @Test
    public final void testParseStringEmpty() throws LdapException
    {

        Dn nameEmpty = new Dn( "" );

        assertNotNull( nameEmpty );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException
     *             if anything goes wrong
     */
    @Test
    public final void testParseStringNull() throws LdapException
    {
        Dn nameNull = new Dn( ( String ) null );

        assertEquals( "Null Dn are legal : ", "", nameNull.toString() );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException
     *             if anything goes wrong
     */
    @Test
    public final void testParseStringRFC1779_1() throws LdapException
    {
        Dn nameRFC1779_1 = new Dn( "CN=Marshall T. Rose, O=Dover Beach Consulting, L=Santa Clara, ST=California, C=US" );

        assertEquals( "RFC1779_1 : ",
            "CN=Marshall T. Rose, O=Dover Beach Consulting, L=Santa Clara, ST=California, C=US",
            nameRFC1779_1.getName() );
        assertEquals( "RFC1779_1 : ", "cn=Marshall T. Rose,o=Dover Beach Consulting,l=Santa Clara,st=California,c=US",
            nameRFC1779_1.getNormName() );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException
     *             if anything goes wrong
     */
    @Test
    public final void testParseStringRFC2253_1() throws LdapException
    {
        Dn nameRFC2253_1 = new Dn( "CN=Steve Kille,O=Isode limited,C=GB" );

        assertEquals( "RFC2253_1 : ", "CN=Steve Kille,O=Isode limited,C=GB", nameRFC2253_1.getName() );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException
     *             if anything goes wrong
     */
    @Test
    public final void testParseStringRFC2253_2() throws LdapException
    {
        Dn nameRFC2253_2 = new Dn( "OU = Sales + CN =   J. Smith , O = Widget Inc. , C = US" );

        assertEquals( "RFC2253_2 : ", "OU = Sales + CN =   J. Smith , O = Widget Inc. , C = US",
            nameRFC2253_2.getName() );
        assertEquals( "RFC2253_2 : ", "ou=Sales+cn=J. Smith,o=Widget Inc.,c=US", nameRFC2253_2.getNormName() );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException
     *             if anything goes wrong
     */
    @Test
    public final void testParseStringRFC2253_3() throws LdapException
    {
        Dn nameRFC2253_3 = new Dn( "CN=L. Eagle,   O=Sue\\, Grabbit and Runn, C=GB" );

        assertEquals( "RFC2253_3 : ", "CN=L. Eagle,   O=Sue\\, Grabbit and Runn, C=GB", nameRFC2253_3
            .getName() );
        assertEquals( "RFC2253_3 : ", "cn=L. Eagle,o=Sue\\, Grabbit and Runn,c=GB", nameRFC2253_3.getNormName() );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException
     *             if anything goes wrong
     */
    @Test
    public final void testParseStringRFC2253_4() throws LdapException
    {
        Dn nameRFC2253_4 = new Dn( "CN=Before\\0DAfter,O=Test,C=GB" );
        assertEquals( "RFC2253_4 : ", "CN=Before\\0DAfter,O=Test,C=GB", nameRFC2253_4.getName() );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException
     *             if anything goes wrong
     */
    @Test
    public final void testParseStringRFC2253_5() throws LdapException
    {
        Dn nameRFC2253_5 = new Dn( "1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB" );

        assertEquals( "RFC2253_5 : ", "1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB", nameRFC2253_5
            .getName() );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException
     *             if anything goes wrong
     */
    @Test
    public final void testParseStringRFC2253_6() throws LdapException
    {
        Dn nameRFC2253_6 = new Dn( "SN=Lu\\C4\\8Di\\C4\\87" );

        assertEquals( "RFC2253_6 : ", "SN=Lu\\C4\\8Di\\C4\\87", nameRFC2253_6.getName() );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException
     *             if anything goes wrong
     */
    @Test
    public final void testParseInvalidString()
    {
        try
        {
            new Dn( "&#347;=&#347;rasulu,dc=example,dc=com" );
            fail( "the invalid name should never succeed in a parse" );
        }
        catch ( Exception e )
        {
            assertNotNull( e );
        }
    }


    /**
     * Tests to see if inner whitespace is preserved after an escaped ',' in a
     * value of a name component. This test was added to try to reproduce the
     * bug encountered in DIREVE-179 <a
     * href="http://issues.apache.org/jira/browse/DIREVE-179"> here</a>.
     *
     * @throws LdapException
     *             if anything goes wrong on parse()
     */
    @Test
    public final void testPreserveSpaceAfterEscape() throws LdapException
    {
        String input = "ou=some test\\,  something else";
        String result = new Dn( input ).toString();
        assertEquals( "ou=some test\\,  something else", result );
    }


    @Test
    public void testWindowsFilePath() throws Exception
    {
        // '\' should be escaped as stated in RFC 2253
        String path = "windowsFilePath=C:\\\\cygwin";
        Dn result = new Dn( path );
        assertEquals( path, result.getName() );
        assertEquals( "windowsfilepath=C:\\\\cygwin", result.getNormName() );
    }


    @Test
    public void testNameFrenchChars() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', 0x4A, ( byte ) 0xC3, ( byte ) 0xA9, 0x72, ( byte ) 0xC3, ( byte ) 0xB4, 0x6D, 0x65 },
            "UTF-8" );

        String result = new Dn( cn ).toString();

        assertEquals( "cn=J\u00e9r\u00f4me", result.toString() );
    }


    @Test
    public void testNameGermanChars() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC3, ( byte ) 0x84, ( byte ) 0xC3, ( byte ) 0x96, ( byte ) 0xC3, ( byte ) 0x9C,
                ( byte ) 0xC3, ( byte ) 0x9F, ( byte ) 0xC3, ( byte ) 0xA4, ( byte ) 0xC3, ( byte ) 0xB6,
                ( byte ) 0xC3, ( byte ) 0xBC }, "UTF-8" );

        String result = new Dn( cn ).toString();

        assertEquals( "cn=\u00C4\u00D6\u00DC\u00DF\u00E4\u00F6\u00FC", result.toString() );
    }


    @Test
    public void testNameTurkishChars() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC4, ( byte ) 0xB0, ( byte ) 0xC4, ( byte ) 0xB1, ( byte ) 0xC5, ( byte ) 0x9E,
                ( byte ) 0xC5, ( byte ) 0x9F, ( byte ) 0xC3, ( byte ) 0x96, ( byte ) 0xC3, ( byte ) 0xB6,
                ( byte ) 0xC3, ( byte ) 0x9C, ( byte ) 0xC3, ( byte ) 0xBC, ( byte ) 0xC4, ( byte ) 0x9E,
                ( byte ) 0xC4, ( byte ) 0x9F }, "UTF-8" );

        String result = new Dn( cn ).toString();

        assertEquals( "cn=\u0130\u0131\u015E\u015F\u00D6\u00F6\u00DC\u00FC\u011E\u011F", result.toString() );
    }


    @Test
    public void testAUmlautPlusBytes() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC3, ( byte ) 0x84, 0x5C, 0x32, 0x42 }, "UTF-8" );

        String result = new Dn( cn ).getNormName();

        assertEquals( "cn=\\C3\\84\\+", result );
    }


    @Test
    public void testAUmlautPlusChar() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC3, ( byte ) 0xA4, '\\', '+' }, "UTF-8" );

        String result = new Dn( cn ).toString();

        assertEquals( "cn=\u00E4\\+", result );
    }


    /**
     * Test to check that even with a non escaped char, the Dn is parsed ok
     * or at least an error is generated.
     *
     * @throws LdapException
     *             if anything goes wrong on parse()
     */
    @Test
    public final void testNonEscapedChars()
    {
        String input = "ou=ou+test";

        try
        {
            new Dn( input ).toString();
            fail( "Should never reach this point" );
        }
        catch ( LdapException ne )
        {
            assertTrue( true );
            return;
        }
    }


    /**
     * Test the Dn.get( int ) method
     */
    @Test
    public void testGetRdnN() throws Exception
    {
        Dn dn = new Dn( "cn=test,dc=example,dc=org" );

        assertEquals( "cn=test", dn.getRdn( 0 ).getName() );
        assertEquals( "dc=example", dn.getRdn( 1 ).getName() );
        assertEquals( "dc=org", dn.getRdn( 2 ).getName() );
    }


    /**
     * Test case for DIRAPI-88 (RDN parsing fails with values containing a # character followed by other characters)
     */
    @Test
    public final void testDIRAPI88()
    {
        assertTrue( Dn.isValid( "workforceID=2#28" ) );
        assertTrue( Dn.isValid( "workforceID=2# + a=b" ) );
        assertTrue( Dn.isValid( "workforceID=2#2Z" ) );
        assertTrue( Dn.isValid( "workforceID=2#2" ) );
        assertTrue( Dn.isValid( "workforceID=2#ZZ" ) );
    }
}
