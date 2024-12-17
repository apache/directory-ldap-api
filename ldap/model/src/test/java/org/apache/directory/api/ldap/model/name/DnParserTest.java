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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Test the class Dn
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class DnParserTest
{
    /**
     * test an empty Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNEmpty() throws LdapException
    {
        Dn dn = new Dn( "" );

        assertEquals( "", dn.getName() );
    }


    /**
     * test a simple Dn : a = b
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNSimple() throws LdapException
    {
        Dn dn = new Dn( "a = b" );

        assertEquals( "a = b", dn.getName() );
    }


    /**
     * test a composite Dn : a = b, d = e
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNComposite() throws LdapException
    {
        Dn dn = new Dn( "a = b, c = d" );

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
        Dn dn = new Dn( "a=b, a =b, a= b, a = b, a  =  b" );
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
        Dn dn = new Dn( "a=b;c=d,e=f" );
        assertEquals( "a=b,c=d,e=f", dn.getEscaped() );
        assertEquals( "a=b;c=d,e=f", dn.getName() );
    }


    /**
     * Test an attributeType with '_' (some vendors allow that)
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testAttributeTypeWithUnderscore() throws LdapException
    {
        Dn dn = new Dn( "a_a = b + c_c = d" );
        assertEquals( "a_a=b+c_c=d", dn.getEscaped() );
        assertEquals( "a_a = b + c_c = d", dn.getName() );
    }


    /**
     * Test DN with '_' in value, because of special handling in Antlr grammar.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testAttributeValueWithUnderscore() throws LdapException
    {
        Dn dn = new Dn( "cn=\\#ACL_AD-Projects_Author,ou=Notes_Group,o=Contacts,c=DE" );
        assertEquals( "cn=\\#ACL_AD-Projects_Author,ou=Notes_Group,o=Contacts,c=DE", dn.getEscaped() );
        assertEquals( "cn=\\#ACL_AD-Projects_Author,ou=Notes_Group,o=Contacts,c=DE", dn.getName() );
    }


    /**
     * test a simple Dn with multiple NameComponents : a = b + c = d
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNSimpleMultivaluedAttribute() throws LdapException
    {
        Dn dn = new Dn( "a = b + c = d" );
        assertEquals( "a=b+c=d", dn.getEscaped() );
        assertEquals( "a = b + c = d", dn.getName() );
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
        Dn dn = new Dn( "a=b+c=d, e=f + g=h + i=j" );
        assertEquals( "a=b+c=d,e=f+g=h+i=j", dn.getEscaped() );
        assertEquals( "a=b+c=d, e=f + g=h + i=j", dn.getName() );
    }


    /**
     * test a simple Dn with an oid prefix (uppercase) : OID.12.34.56 = azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNOidUpper() throws LdapException
    {
        Dn dn = new Dn( "OID.12.34.56 = azerty" );
        assertEquals( "OID.12.34.56=azerty", dn.getEscaped() );
        assertEquals( "OID.12.34.56 = azerty", dn.getName() );
    }


    /**
     * test a simple Dn with an oid prefix (lowercase) : oid.12.34.56 = azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNOidLower() throws LdapException
    {
        Dn dn = new Dn( "oid.12.34.56 = azerty" );
        assertEquals( "oid.12.34.56=azerty", dn.getEscaped() );
        assertEquals( "oid.12.34.56 = azerty", dn.getName() );
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
        Dn dn = new Dn( "12.34.56 = azerty" );
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
        Dn dn = new Dn( "12.34.56 = azerty; 7.8 = test" );
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
        Dn dn = new Dn( "a = \\,\\=\\+\\<\\>\\#\\;\\\\\\\"\\C3\\A9" );
        assertEquals( "a=\\,=\\+\\<\\>#\\;\\\\\\\"\u00e9", dn.getEscaped() );
        assertEquals( "a = \\,\\=\\+\\<\\>\\#\\;\\\\\\\"\\C3\\A9", dn.getName() );

        dn = new Dn( "a = \\,\\=\\+\\<\\>\\#\\;\\\\\\\"\u00e9" );
        assertEquals( "a=\\,=\\+\\<\\>#\\;\\\\\\\"\u00e9", dn.getEscaped() );
        assertEquals( "a = \\,\\=\\+\\<\\>\\#\\;\\\\\\\"\u00e9", dn.getName() );
    }


    /**
     * test a simple Dn with hexString attribute value : a = #0010A0AAFF
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNHexStringAttributeValue() throws LdapException
    {
        Dn dn = new Dn( "a = #0010A0AAFF" );
        assertEquals( "a=\\00\u0010\\A0\\AA\\FF", dn.getEscaped() );
        assertEquals( "a = #0010A0AAFF", dn.getName() );
    }


    /**
     * test exception from illegal hexString attribute value : a=#zz.
     * 
     * @throws LdapException If the test failed
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
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNQuotedAttributeValue() throws LdapException
    {
        Dn dn = new Dn( "a = quoted \\\"value" );
        assertEquals( "a=quoted \\\"value", dn.getEscaped() );
        assertEquals( "a = quoted \\\"value", dn.getName() );

        dn = new Dn( "cn=Mackie \\\"The Knife\\\" Messer" );
        assertEquals( "cn=Mackie \\\"The Knife\\\" Messer", dn.getEscaped() );
        assertEquals( "cn=Mackie \\\"The Knife\\\" Messer", dn.getName() );
    }


    /**
     * Tests a corner case of the parser because the sequence "\DC" is also a valid hex pair
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapDNBackslashInAttributeValue() throws LdapException
    {
        Dn dn = new Dn( "a = AC\\\\DC" );
        assertEquals( "a=AC\\\\DC", dn.getEscaped() );
        assertEquals( "a = AC\\\\DC", dn.getName() );
    }


    @Test
    public void testStringParser() throws LdapException
    {
        String dn = Strings.utf8ToString( new byte[]
            { 'C', 'N', ' ', '=', ' ', 'E', 'm', 'm', 'a', 'n', 'u', 'e', 'l', ' ', ' ', 'L', ( byte ) 0xc3,
                ( byte ) 0xa9, 'c', 'h', 'a', 'r', 'n', 'y' } );

        Dn name = new Dn( dn );

        assertEquals( "CN = Emmanuel  L\u00e9charny", name.getName() );
        assertEquals( "CN=Emmanuel  L\u00e9charny", name.getEscaped() );
    }


    @Test
    public void testStringParserShort() throws LdapException
    {
        String dn = Strings.utf8ToString( new byte[]
            { 'C', '=', ' ', 'E', ( byte ) 0xc3, ( byte ) 0xa9, 'c' } );

        Dn name = new Dn( dn );

        assertEquals( "C= E\u00e9c", name.getName() );
        assertEquals( "C=E\u00e9c", name.getEscaped() );
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
            "cn=Billy Bakers,OID.2.5.4.11=Corporate Tax,ou=Fin-Accounting,ou=Americas,ou=Search,o=IMC,c=US", name
                .getEscaped() );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException if anything goes wrong
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
     * @throws LdapException if anything goes wrong
     */
    @Test
    public final void testParseStringNull() throws LdapException
    {
        Dn nameNull = new Dn( ( String ) null );

        assertEquals( "", nameNull.toString(), "Null Dn are legal : " );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException if anything goes wrong
     */
    @Test
    public final void testParseStringRFC1779_1() throws LdapException
    {
        Dn nameRFC1779_1 = new Dn( "CN=Marshall T. Rose, O=Dover Beach Consulting, L=Santa Clara, ST=California, C=US" );

        assertEquals( 
            "CN=Marshall T. Rose, O=Dover Beach Consulting, L=Santa Clara, ST=California, C=US",
            nameRFC1779_1.getName(), "RFC1779_1 : " );
        assertEquals( "CN=Marshall T. Rose,O=Dover Beach Consulting,L=Santa Clara,ST=California,C=US",
            nameRFC1779_1.getEscaped(), "RFC1779_1 : " );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException if anything goes wrong
     */
    @Test
    public final void testParseStringRFC2253_1() throws LdapException
    {
        Dn nameRFC2253_1 = new Dn( "CN=Steve Kille,O=Isode limited,C=GB" );

        assertEquals( "CN=Steve Kille,O=Isode limited,C=GB", nameRFC2253_1.getName(), "RFC2253_1 : " );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException if anything goes wrong
     */
    @Test
    public final void testParseStringRFC2253_2() throws LdapException
    {
        Dn nameRFC2253_2 = new Dn( "OU = Sales + CN =   J. Smith , O = Widget Inc. , C = US" );

        assertEquals( "OU = Sales + CN =   J. Smith , O = Widget Inc. , C = US",
            nameRFC2253_2.getName(), "RFC2253_2 : " );
        assertEquals( "CN=J. Smith+OU=Sales,O=Widget Inc.,C=US", nameRFC2253_2.getEscaped(), "RFC2253_2 : " );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException if anything goes wrong
     */
    @Test
    public final void testParseStringRFC2253_3() throws LdapException
    {
        Dn nameRFC2253_3 = new Dn( "CN=L. Eagle,   O=Sue\\, Grabbit and Runn, C=GB" );

        assertEquals( "CN=L. Eagle,   O=Sue\\, Grabbit and Runn, C=GB", nameRFC2253_3
            .getName(), "RFC2253_3 : " );
        assertEquals( "CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB", nameRFC2253_3.getEscaped(), "RFC2253_3 : " );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException if anything goes wrong
     */
    @Test
    public final void testParseStringRFC2253_4() throws LdapException
    {
        Dn nameRFC2253_4 = new Dn( "CN=Before\\0DAfter,O=Test,C=GB" );
        assertEquals( "CN=Before\\0DAfter,O=Test,C=GB", nameRFC2253_4.getName(), "RFC2253_4 : " );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException if anything goes wrong
     */
    @Test
    public final void testParseStringRFC2253_5() throws LdapException
    {
        Dn nameRFC2253_5 = new Dn( "1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB" );

        assertEquals( "1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB", nameRFC2253_5
            .getName(), "RFC2253_5 : " );
    }


    /**
     * Class under test for Name parse(String)
     *
     * @throws LdapException if anything goes wrong
     */
    @Test
    public final void testParseStringRFC2253_6() throws LdapException
    {
        Dn nameRFC2253_6 = new Dn( "SN=Lu\\C4\\8Di\\C4\\87" );

        assertEquals( "SN=Lu\\C4\\8Di\\C4\\87", nameRFC2253_6.getName(), "RFC2253_6 : " );
    }


    /**
     * Class under test for Name parse(String)
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
     * bug encountered in DIRSERVER-297 <a
     * href="https://issues.apache.org/jira/browse/DIRSERVER-297"> here</a>.
     *
     * @throws LdapException if anything goes wrong on parse()
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
        assertEquals( "windowsFilePath=C:\\\\cygwin", result.getEscaped() );
    }


    @Test
    public void testNameFrenchChars() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', 0x4A, ( byte ) 0xC3, ( byte ) 0xA9, 0x72, ( byte ) 0xC3, ( byte ) 0xB4, 0x6D, 0x65 },
            StandardCharsets.UTF_8 );

        String result = new Dn( cn ).toString();

        assertEquals( "cn=J\u00e9r\u00f4me", result.toString() );
    }


    @Test
    public void testNameGermanChars() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC3, ( byte ) 0x84, ( byte ) 0xC3, ( byte ) 0x96, ( byte ) 0xC3, ( byte ) 0x9C,
                ( byte ) 0xC3, ( byte ) 0x9F, ( byte ) 0xC3, ( byte ) 0xA4, ( byte ) 0xC3, ( byte ) 0xB6,
                ( byte ) 0xC3, ( byte ) 0xBC }, StandardCharsets.UTF_8 );

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
                ( byte ) 0xC4, ( byte ) 0x9F }, StandardCharsets.UTF_8 );

        String result = new Dn( cn ).toString();

        assertEquals( "cn=\u0130\u0131\u015E\u015F\u00D6\u00F6\u00DC\u00FC\u011E\u011F", result );
    }


    @Test
    public void testAUmlautPlusBytes() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC3, ( byte ) 0x84, '\\', '2', 'B' }, StandardCharsets.UTF_8 );

        Dn dn = new Dn( cn );

        assertEquals( "cn=\u00c4\\2B", dn.getName() );
        assertEquals( "cn=\u00c4\\+", dn.getEscaped() );
    }


    @Test
    public void testAUmlautPlusChar() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC3, ( byte ) 0xA4, '\\', '+' }, StandardCharsets.UTF_8 );

        Dn dn = new Dn( cn );

        assertEquals( "cn=\u00E4\\+", dn.getName() );
        assertEquals( "cn=\u00E4\\+", dn.getEscaped() );
    }


    /**
     * Test to check that even with a non escaped char, the Dn is parsed ok
     * or at least an error is generated.
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
     * 
     * @throws Exception If the test failed
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
        String[] values = new String[]
            {
                "200511230101#38SA",
                "2#28",
                "2#2Z",
                "2#2",
                "2#ZZ"
            };
        
        for ( String value : values )
        {
            try
            {
                String dnStr = "workforceID=" + value;
                assertTrue( Dn.isValid( dnStr ) );
                
                Dn dn = new Dn( dnStr );
                Rdn rdn = dn.getRdn();
                assertEquals( value, rdn.getValue() );
            }
            catch ( Exception e )
            {
                fail();
            }
        }
        
        try
        {
            String dnStr = "workforceID=2# + z=b";
            assertTrue( Dn.isValid( dnStr ) );
            
            Dn dn = new Dn( dnStr );
            Rdn rdn = dn.getRdn();
            assertEquals( "2#", rdn.getValue() );
        }
        catch ( Exception e )
        {
            fail();
        }
    }

    
    @Test
    public void testEqualInRdn() throws LdapInvalidDnException
    {
        new Dn( "uid=nghZwwtHgxgyvVbTQCYyeY\\+O4cc=,dc=example,dc=com" );
    }
    
    
    @Test
    @Disabled
    public void testDnParsingPerf() throws LdapInvalidDnException
    {
        long[] deltas = new long[10];
        
        for ( int j = 0; j < 10; j++ )
        {
            long t0 = System.currentTimeMillis();
            
            for ( int i = 0; i < 10000000; i++ )
            {
                new Dn( "dc=example" + i );
            }
            
            long t1 = System.currentTimeMillis();
            
            deltas[j] = t1 - t0;
            System.out.println( "Iteration[" + j + "] : " + deltas[j] );
        }
        
        long allDeltas = 0L;
        
        for ( int i = 0; i < 10; i++ )
        {
            allDeltas += deltas[i];
        }
        
        System.out.println( "delta new 1 RDN : " + ( allDeltas / 10 ) );

        for ( int j = 0; j < 10; j++ )
        {
            long t0 = System.currentTimeMillis();
            
            for ( int i = 0; i < 10000000; i++ )
            {
                new Dn( "dc=example" + i + ",dc=com" );
            }
            
            long t1 = System.currentTimeMillis();
            
            deltas[j] = t1 - t0;
            System.out.println( "Iteration[" + j + "] : " + deltas[j] );
        }
        
        allDeltas = 0L;
        
        for ( int i = 0; i < 10; i++ )
        {
            allDeltas += deltas[i];
        }
        
        System.out.println( "delta new 2 RDNs : " + ( allDeltas / 10 ) );

        for ( int j = 0; j < 10; j++ )
        {
            long t0 = System.currentTimeMillis();
            
            for ( int i = 0; i < 10000000; i++ )
            {
                new Dn( "uid=" + i + ",dc=example,dc=com" );
            }
            
            long t1 = System.currentTimeMillis();
            
            deltas[j] = t1 - t0;
            System.out.println( "Iteration[" + j + "] : " + deltas[j] );
        }
        
        allDeltas = 0L;
        
        for ( int i = 0; i < 10; i++ )
        {
            allDeltas += deltas[i];
        }
        
        System.out.println( "delta new 3 RDNs : " + ( allDeltas / 10 ) );

        for ( int j = 0; j < 10; j++ )
        {
            long t0 = System.currentTimeMillis();
            
            for ( int i = 0; i < 10000000; i++ )
            {
                new Dn( "uid=" + i + ",ou=people,dc=example,dc=com" );
            }
            
            long t1 = System.currentTimeMillis();
            
            deltas[j] = t1 - t0;
            System.out.println( "Iteration[" + j + "] : " + deltas[j] );
        }
        
        allDeltas = 0L;
        
        for ( int i = 0; i < 10; i++ )
        {
            allDeltas += deltas[i];
        }
        
        System.out.println( "delta new 4 RDNs : " + ( allDeltas / 10 ) );
    }
    
    
    @Test
    @Disabled
    public void testDnParsingOneRdnPerf() throws LdapInvalidDnException
    {
        long t0 = System.currentTimeMillis();
        
        for ( int i = 0; i < 1000000; i++ )
        {
            new Dn( "dc=example" + i );
        }
        
        long t1 = System.currentTimeMillis();
        System.out.println( "delta new 1 RDN : " + ( t1 - t0 ) );
    }
}
