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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the class Dn
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class DnTest
{
    private static SchemaManager schemaManager;


    /**
     * Initialize OIDs maps for normalization
     * 
     * @throws Exception If the setup failed
     */
    @BeforeAll
    public static void setup() throws Exception
    {
        schemaManager = new DefaultSchemaManager();
    }


    // ------------------------------------------------------------------------------------
    // CONSTRUCTOR functions --------------------------------------------------

    /**
     * Test a null Dn
     */
    @Test
    public void testDnNull()
    {
        Dn dn = new Dn();
        assertEquals( "", dn.getName() );
        assertEquals( "", dn.getEscaped() );
        assertTrue( dn.isEmpty() );
    }


    /**
     * test an empty Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnEmpty() throws LdapException
    {
        Dn dn = new Dn( "" );
        assertEquals( "", dn.getName() );
        assertTrue( dn.isEmpty() );
    }


    /**
     * test a simple Dn : a = b
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnSimple() throws LdapException
    {
        Dn dn = new Dn( "a = b" );

        assertTrue( Dn.isValid( "a = b" ) );
        assertEquals( "a = b", dn.getName() );
        assertEquals( "a=b", dn.getEscaped() );
    }


    /**
     * test a simple Dn with some spaces : "a = b  "
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnSimpleWithSpaces() throws LdapException
    {
        Dn dn = new Dn( "a = b  " );

        assertTrue( Dn.isValid( "a = b  " ) );
        assertEquals( "a = b  ", dn.getName() );
        assertEquals( "a=b", dn.getEscaped() );
    }


    /**
     * test a composite Dn : a = b, d = e
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnComposite() throws LdapException
    {
        Dn dn = new Dn( "a = b, c = d" );

        assertTrue( Dn.isValid( "a = b, c = d" ) );
        assertEquals( "a=b,c=d", dn.getEscaped() );
        assertEquals( "a = b, c = d", dn.getName() );
    }


    /**
     * test a composite Dn with spaces : a = b  , d = e
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnCompositeWithSpaces() throws LdapException
    {
        Dn dn = new Dn( "a = b  , c = d" );

        assertTrue( Dn.isValid( "a = b  , c = d" ) );
        assertEquals( "a=b,c=d", dn.getEscaped() );
        assertEquals( "a = b  , c = d", dn.getName() );
    }


    /**
     * test a composite Dn with or without spaces: a=b, a =b, a= b, a = b, a = b
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnCompositeWithSpace() throws LdapException
    {
        Dn dn = new Dn( "a=b, a =b, a= b, a = b, a  =  b" );

        assertTrue( Dn.isValid( "a=b, a =b, a= b, a = b, a  =  b" ) );
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
    public void testDnCompositeSepators() throws LdapException
    {
        Dn dn = new Dn( "a=b;c=d,e=f" );

        assertTrue( Dn.isValid( "a=b;c=d,e=f" ) );
        assertEquals( "a=b,c=d,e=f", dn.getEscaped() );
        assertEquals( "a=b;c=d,e=f", dn.getName() );
    }


    /**
     * test a simple Dn with multiple NameComponents : a = b + c = d
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnSimpleMultivaluedAttribute() throws LdapException
    {
        Dn dn = new Dn( "a = b + c = d" );

        assertTrue( Dn.isValid( "a = b + c = d" ) );
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
    public void testDnCompositeMultivaluedAttribute() throws LdapException
    {
        Dn dn = new Dn( "a=b+c=d, e=f + g=h + i=j" );

        assertTrue( Dn.isValid( "a=b+c=d, e=f + g=h + i=j" ) );
        assertEquals( "a=b+c=d,e=f+g=h+i=j", dn.getEscaped() );
        assertEquals( "a=b+c=d, e=f + g=h + i=j", dn.getName() );
    }


    /**
    * Test to see if a Dn with multiRdn values is preserved after an addAll.
     * 
     * @throws LdapException If the test failed
    */
    @Test
    public void testAddAllWithMultivaluedAttribute() throws LdapException
    {
        Dn dn = new Dn( "cn=Kate Bush+sn=Bush,ou=system" );
        Dn target = new Dn();

        assertTrue( Dn.isValid( "cn=Kate Bush+sn=Bush,ou=system" ) );
        target = target.add( dn );
        assertEquals( "cn=Kate Bush+sn=Bush,ou=system", target.toString() );
        assertEquals( "cn=Kate Bush+sn=Bush,ou=system", target.getName() );
    }


    /**
     * test a simple Dn with an oid prefix (uppercase) : OID.12.34.56 = azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnOidUpper() throws LdapException
    {
        Dn dn = new Dn( "OID.12.34.56 = azerty" );

        assertTrue( Dn.isValid( "OID.12.34.56 = azerty" ) );
        assertEquals( "OID.12.34.56=azerty", dn.getEscaped() );
        assertEquals( "OID.12.34.56 = azerty", dn.getName() );
    }


    /**
     * test a simple Dn with an oid prefix (lowercase) : oid.12.34.56 = azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnOidLower() throws LdapException
    {
        Dn dn = new Dn( "oid.12.34.56 = azerty" );

        assertTrue( Dn.isValid( "oid.12.34.56 = azerty" ) );
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
    public void testDnOidWithoutPrefix() throws LdapException
    {
        Dn dn = new Dn( "12.34.56 = azerty" );

        assertTrue( Dn.isValid( "12.34.56 = azerty" ) );
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
    public void testDnCompositeOidWithoutPrefix() throws LdapException
    {
        Dn dn = new Dn( "12.34.56 = azerty; 7.8 = test" );

        assertTrue( Dn.isValid( "12.34.56 = azerty; 7.8 = test" ) );
        assertEquals( "12.34.56=azerty,7.8=test", dn.getEscaped() );
        assertEquals( "12.34.56 = azerty; 7.8 = test", dn.getName() );
    }


    /**
     * test a simple Dn with pair char attribute value : a = \,\=\+\&lt;\&gt;\#\;\\\"\C4\8D"
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnPairCharAttributeValue() throws LdapException
    {
        Dn dn = new Dn( "a = \\,\\=\\+\\<\\>\\#\\;\\\\\\\"\\C4\\8D" );

        assertTrue( Dn.isValid( "a = \\,\\=\\+\\<\\>\\#\\;\\\\\\\"\\C4\\8D" ) );
        assertEquals( "a=\\,=\\+\\<\\>#\\;\\\\\\\"\u010d", dn.getEscaped() );
        assertEquals( "a = \\,\\=\\+\\<\\>\\#\\;\\\\\\\"\\C4\\8D", dn.getName() );
    }


    /**
     * test a simple Dn with pair char attribute value : "SN=Lu\C4\8Di\C4\87"
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnRFC253_Lucic() throws LdapException
    {
        Dn dn = new Dn( "SN=Lu\\C4\\8Di\\C4\\87" );

        assertTrue( Dn.isValid( "SN=Lu\\C4\\8Di\\C4\\87" ) );
        assertEquals( "SN=Lu\u010di\u0107", dn.getEscaped() );
        assertEquals( "SN=Lu\\C4\\8Di\\C4\\87", dn.getName() );
    }


    /**
     * test a simple Dn with hexString attribute value : a = #0010A0AAFF
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnHexStringAttributeValue() throws LdapException
    {
        Dn dn = new Dn( "a = #0010A0AAFF" );

        assertTrue( Dn.isValid( "a = #0010A0AAFF" ) );
        assertEquals( "a=\\00\u0010\\A0\\AA\\FF", dn.getEscaped() );
        assertEquals( "a = #0010A0AAFF", dn.getName() );
    }


    /**
     * Test for DIRSTUDIO-589, DIRSTUDIO-591, DIRSHARED-38
     *
     * Check escaped sharp followed by a hex sequence
     * (without the ESC it would be a valid hexstring).
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnEscSharpNumber() throws LdapException, LdapException
    {
        Dn dn = new Dn( "a = \\#123456" );

        assertTrue( Dn.isValid( "a = \\#123456" ) );
        assertEquals( "a=\\#123456", dn.getEscaped() );
        assertEquals( "a = \\#123456", dn.getName() );

        Rdn rdn = dn.getRdn();
        assertEquals( "a = \\#123456", rdn.getName() );

        assertTrue( Dn.isValid( "a = \\#00" ) );
        assertTrue( Dn.isValid( "a = \\#11" ) );
        assertTrue( Dn.isValid( "a = \\#99" ) );
        assertTrue( Dn.isValid( "a = \\#AA" ) );
        assertTrue( Dn.isValid( "a = \\#FF" ) );

        assertTrue( Dn.isValid( "uid=\\#123456" ) );
        assertTrue( Dn.isValid( "cn=\\#ACL_AD-Projects_Author,ou=Notes_Group,o=Contacts,c=DE" ) );
        assertTrue( Dn.isValid( "cn=\\#Abraham" ) );
    }


    /**
     * Test for DIRSTUDIO-589, DIRSTUDIO-591, DIRSHARED-38
     *
     * Check escaped sharp followed by a hex sequence
     * (without the ESC it would be a valid hexstring).
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnEscValue() throws LdapException
    {
        Dn dn = new Dn( "cn = Exa\\+mple  one " );

        assertTrue( Dn.isValid( "cn = Exa\\+mple  one " ) );
        assertEquals( "cn=Exa\\+mple  one", dn.getEscaped() );
        assertEquals( "cn = Exa\\+mple  one ", dn.getName() );

        Dn dn2 = new Dn( schemaManager, "cn = Exa\\+mple  one " );

        assertEquals( "cn=Exa\\+mple  one", dn2.getEscaped() );
        assertEquals( "cn = Exa\\+mple  one ", dn2.getName() );
        assertEquals( "2.5.4.3= exa+mple  one ", dn2.getNormName() );
    }


    /**
     * test a simple Dn with a # on first position
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnSharpFirst() throws LdapException, LdapException
    {
        Dn dn = new Dn( "a = \\#this is a sharp" );

        assertTrue( Dn.isValid( "a = \\#this is a sharp" ) );
        assertEquals( "a=\\#this is a sharp", dn.getEscaped() );
        assertEquals( "a = \\#this is a sharp", dn.getName() );

        Rdn rdn = dn.getRdn();
        assertEquals( "a = \\#this is a sharp", rdn.getName() );
    }


    /**
     * Normalize a simple Dn with a # on first position
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testNormalizeDnSharpFirst() throws LdapException
    {
        Dn dn = new Dn( "ou = \\#this is a sharp" );

        assertTrue( Dn.isValid( "ou = \\#this is a sharp" ) );
        assertEquals( "ou=\\#this is a sharp", dn.getEscaped() );
        assertEquals( "ou = \\#this is a sharp", dn.getName() );

        // Check the normalization now
        Dn ndn = new Dn( schemaManager, dn );

        assertEquals( "ou = \\#this is a sharp", ndn.getName() );
        assertEquals( "ou=\\#this is a sharp", ndn.getEscaped() );
    }


    /**
     * Normalize a Dn with sequence ESC ESC HEX HEX (\\C3\\A4).
     * This is a corner case for the parser and normalizer.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testNormalizeDnEscEscHexHexEscSpecial() throws LdapException
    {
        Dn dn = new Dn( "ou = AC\\\\C3\\2B" );
        assertTrue( Dn.isValid( "ou = AC\\\\C3\\2B" ) );
        assertEquals( "ou=AC\\\\C3\\+", dn.getEscaped() );
        assertEquals( "ou = AC\\\\C3\\2B", dn.getName() );

        // Check the normalization now
        Dn ndn = new Dn( schemaManager, dn );
        assertEquals( "ou = AC\\\\C3\\2B", ndn.getName() );
        assertEquals( "ou=AC\\\\C3\\+", ndn.getEscaped() );
    }

    /**
     * Normalize a Dn with sequence ESC ESC HEX HEX (\\DC).
     * This is a corner case for the parser and normalizer.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testNormalizeDnEscEscHexHex() throws LdapException
    {
        Dn dn = new Dn( "ou = AC\\\\DC" );
        assertTrue( Dn.isValid( "ou = AC\\\\DC" ) );
        assertEquals( "ou=AC\\\\DC", dn.getEscaped() );
        assertEquals( "ou = AC\\\\DC", dn.getName() );

        // Check the normalization now
        Dn ndn = new Dn( schemaManager, dn );
        assertEquals( "ou = AC\\\\DC", ndn.getName() );
        assertEquals( "ou=AC\\\\DC", ndn.getEscaped() );
    }


    /**
     * test a simple Dn with a wrong hexString attribute value : a = #0010Z0AAFF
     */
    @Test
    public void testDnWrongHexStringAttributeValue()
    {
        try
        {
            new Dn( "a = #0010Z0AAFF" );
            fail();
        }
        catch ( LdapException ine )
        {

            assertFalse( Dn.isValid( "a = #0010Z0AAFF" ) );
            assertTrue( true );
        }
    }


    /**
     * test a simple Dn with a wrong hexString attribute value : a = #AABBCCDD3
     */
    @Test
    public void testDnWrongHexStringAttributeValue2()
    {
        try
        {
            new Dn( "a = #AABBCCDD3" );
            fail();
        }
        catch ( LdapException ine )
        {
            assertFalse( Dn.isValid( "a = #AABBCCDD3" ) );
            assertTrue( true );
        }
    }


    /**
     * test a simple Dn with a quote in attribute value : a = quoted \"value\"
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnQuoteInAttributeValue() throws LdapException
    {
        Dn dn = new Dn( "a = quoted \\\"value\\\"" );

        assertTrue( Dn.isValid( "a = quoted \\\"value\\\"" ) );
        assertEquals( "a=quoted \\\"value\\\"", dn.getEscaped() );
        assertEquals( "a = quoted \\\"value\\\"", dn.getName() );
    }


    /**
     * test a simple Dn with quoted attribute value : a = \" quoted value \"
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnQuotedAttributeValue() throws LdapException
    {
        Dn dn = new Dn( "a = \\\" quoted value \\\"" );

        assertTrue( Dn.isValid( "a = \\\" quoted value \\\"" ) );
        assertEquals( "a=\\\" quoted value \\\"", dn.getEscaped() );
        assertEquals( "a = \\\" quoted value \\\"", dn.getName() );
    }


    /**
     * test a simple Dn with a comma at the end
     */
    @Test
    public void testDnComaAtEnd()
    {
        assertFalse( Dn.isValid( "a = b," ) );
        assertFalse( Dn.isValid( "a = b, " ) );

        try
        {
            new Dn( "a = b," );
            fail();
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }
    }


    // SIZE operations
    /**
     * test a 0 size
     */
    @Test
    public void testDnSize0()
    {
        Dn dn = new Dn();

        assertTrue( Dn.isValid( "" ) );
        assertEquals( 0, dn.size() );
    }


    /**
     * test a 1 size
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnSize1() throws LdapException
    {
        Dn dn = new Dn( "a=b" );

        assertTrue( Dn.isValid( "a=b" ) );
        assertEquals( 1, dn.size() );
    }


    /**
     * test a 3 size
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnSize3() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d, e=f" );

        assertTrue( Dn.isValid( "a=b, c=d, e=f" ) );
        assertEquals( 3, dn.size() );
    }


    /**
     * test a 3 size with NameComponents
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnSize3NC() throws LdapException
    {
        Dn dn = new Dn( "a=b+c=d, c=d, e=f" );

        assertTrue( Dn.isValid( "a=b+c=d, c=d, e=f" ) );
        assertEquals( 3, dn.size() );
    }


    /**
     * test size after operations
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapResizing() throws LdapException
    {
        Dn dn = new Dn();
        assertEquals( 0, dn.size() );

        dn = dn.add( "e = f" );
        assertEquals( 1, dn.size() );

        dn = dn.add( "c = d" );
        assertEquals( 2, dn.size() );

        dn = dn.getParent();
        assertEquals( 1, dn.size() );

        dn = dn.getParent();
        assertEquals( 0, dn.size() );
    }


    // ADD Operations
    /**
     * test Add on a new Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testLdapEmptyAdd() throws LdapException
    {
        Dn dn = new Dn();

        dn = dn.add( "e = f" );
        assertEquals( "e=f", dn.getEscaped() );
        assertEquals( "e = f", dn.getName() );
        assertEquals( 1, dn.size() );
    }


    /**
     * test Add to an existing Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnAdd() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d" );

        dn = dn.add( "e = f" );
        assertEquals( "e=f,a=b,c=d", dn.getEscaped() );
        assertEquals( "e = f,a=b, c=d", dn.getName() );
        assertEquals( 3, dn.size() );
    }


    /**
     * test Add a composite Rdn to an existing Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnAddComposite() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d" );

        dn = dn.add( "e = f + g = h" );

        // Warning ! The order of AVAs has changed during the parsing
        // This has no impact on the correctness of the Dn, but the
        // String used to do the comparizon should be inverted.
        assertEquals( "e=f+g=h,a=b,c=d", dn.getEscaped() );
        assertEquals( 3, dn.size() );
    }


    /**
     * test Add at the end of an existing Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnAddEnd() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d" );

        dn = dn.add( "e = f" );
        assertEquals( "e = f,a=b, c=d", dn.getName() );
        assertEquals( 3, dn.size() );
    }


    // ADD ALL Operations
    /**
     * Test AddAll
     *
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnAddAll() throws LdapException
    {
        Dn dn = new Dn( "a = b" );
        Dn dn2 = new Dn( "c = d" );
        dn = dn.add( dn2 );
        assertEquals( "c = d,a = b", dn.getName() );
    }


    /**
     * Test AddAll with an empty added name
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnAddAllAddedNameEmpty() throws LdapException
    {
        Dn dn = new Dn( "a = b" );
        Dn dn2 = new Dn();
        dn = dn.add( dn2 );
        assertEquals( "a=b", dn.getEscaped() );
        assertEquals( "a = b", dn.getName() );
    }


    /**
     * Test AddAll to an empty name
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnAddAllNameEmpty() throws LdapException
    {
        Dn dn = new Dn();
        Dn dn2 = new Dn( "a = b" );
        dn = dn.add( dn2 );
        assertEquals( "a = b", dn.getName() );
    }


    /**
     * Test AddAll at position 0
     *
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnAt0AddAll() throws LdapException
    {
        Dn dn = new Dn( "a = b" );
        Dn dn2 = new Dn( "c = d" );
        dn = dn2.add( dn );
        assertEquals( "a = b,c = d", dn.getName() );
    }


    /**
     * Test AddAll at position 1
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnAt1AddAll() throws LdapException
    {
        Dn dn = new Dn( "a = b" );
        Dn dn2 = new Dn( "c = d" );
        dn = dn.add( dn2 );
        assertEquals( "c = d,a = b", dn.getName() );
    }


    /**
     * Test AddAll with an empty added name at position 0
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnAddAllAt0AddedNameEmpty() throws LdapException
    {
        Dn dn = new Dn( "a = b" );
        Dn dn2 = new Dn();
        dn = dn.add( dn2 );
        assertEquals( "a=b", dn.getEscaped() );
        assertEquals( "a = b", dn.getName() );
    }


    /**
     * Test AddAll to an empty name at position 0
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnAddAllAt0NameEmpty() throws LdapException
    {
        Dn dn = new Dn();
        Dn dn2 = new Dn( "a = b" );
        dn = dn.add( dn2 );
        assertEquals( "a = b", dn.getName() );
    }


    // GET PREFIX actions
    /**
     * Get the prefix at pos 0
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnGetPrefixPos0() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        Dn newDn = ( dn.getAncestorOf( "" ) );
        assertEquals( "a=b, c=d,e = f", newDn.getName() );
    }


    /**
     * Get the prefix at pos 1
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnGetPrefixPos1() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        Dn newDn = ( dn.getAncestorOf( "a=b" ) );
        assertEquals( " c=d,e = f", newDn.getName() );
    }


    /**
     * Get the prefix at pos 2
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnGetPrefixPos2() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        Dn newDn = ( dn.getAncestorOf( "a=b, c=d" ) );
        assertEquals( "e = f", newDn.getName() );
    }


    /**
     * Get the prefix at pos 3
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnGetPrefixPos3() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        Dn newDn = ( dn.getAncestorOf( "a=b, c=d,e = f" ) );
        assertEquals( "", newDn.getName() );
    }


    /**
     * Get the prefix out of bound
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnGetPrefixPos4() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );

        assertThrows( LdapInvalidDnException.class, () ->
        {
            dn.getAncestorOf( "a=z" );
        } );
    }


    /**
     * Get the prefix of an empty LdapName
     * 
     * @throws LdapInvalidDnException If the test failed
     */
    @Test
    public void testDnGetPrefixEmptyDN() throws LdapInvalidDnException
    {
        Dn dn = new Dn();
        Dn newDn = ( dn.getAncestorOf( "" ) );
        assertEquals( "", newDn.getName() );
    }


    // GET SUFFIX operations
    /**
     * Get the suffix at pos 0
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnGetSuffixPos0() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        Dn newDn = ( dn.getDescendantOf( "" ) );
        assertEquals( "a=b, c=d,e = f", newDn.getName() );
    }


    /**
     * Get the suffix at pos 1
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnGetSuffixPos1() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        Dn newDn = ( dn.getDescendantOf( "e=f" ) );
        assertEquals( "a=b, c=d", newDn.getName() );
    }


    /**
     * Get the suffix at pos 2
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnGetSuffixPos2() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        Dn newDn = ( dn.getDescendantOf( "c=d,e=f" ) );
        assertEquals( "a=b", newDn.getName() );
    }


    /**
     * Get the suffix at pos 3
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnGetSuffixPos3() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        Dn newDn = ( dn.getDescendantOf( "a=b, c=d, e=f" ) );
        assertEquals( "", newDn.getName() );
    }


    /**
     * Get the suffix out of bound
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnGetSuffixPos4() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );

        try
        {
            dn.getDescendantOf( "i=j, a=b, c=d, e=f" );
            // We should not reach this point.
            fail();
        }
        catch ( ArrayIndexOutOfBoundsException aoobe )
        {
            assertTrue( true );
        }
    }


    // IS EMPTY operations
    /**
     * Test that a Dn is empty
     */
    @Test
    public void testDnIsEmpty()
    {
        Dn dn = new Dn();
        assertEquals( true, dn.isEmpty() );
    }


    /**
     * Test that a Dn is empty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnNotEmpty() throws LdapException
    {
        Dn dn = new Dn( "a=b" );
        assertEquals( false, dn.isEmpty() );
    }


    // STARTS WITH operations
    /**
     * Test a startsWith a null Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnStartsWithNull() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        assertEquals( true, dn.isDescendantOf( ( Dn ) null ) );
    }


    /**
     * Test a startsWith an empty Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnStartsWithEmpty() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        assertEquals( true, dn.isDescendantOf( new Dn() ) );
    }


    /**
     * Test a startsWith an simple Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnStartsWithSimple() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        assertEquals( true, dn.isDescendantOf( new Dn( "e=f" ) ) );
    }


    /**
     * Test a startsWith a complex Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnStartsWithComplex() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        assertEquals( true, dn.isDescendantOf( new Dn( "c =  d, e =  f" ) ) );
    }


    /**
     * Test a startsWith a complex Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnStartsWithComplexMixedCase() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        assertEquals( false, dn.isDescendantOf( new Dn( "c =  D, E =  f" ) ) );
    }


    /**
     * Test a startsWith a full Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnStartsWithFull() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        assertEquals( true, dn.isDescendantOf( new Dn( "a=  b; c =  d, e =  f" ) ) );
    }


    /**
     * Test a startsWith which returns false
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnStartsWithWrong() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        assertEquals( false, dn.isDescendantOf( new Dn( "c =  t, e =  f" ) ) );
    }


    // ENDS WITH operations
    /**
     * Test a endsWith a null Dn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testDnEndsWithNull() throws LdapException
    {
        Dn dn = new Dn( "a=b, c=d,e = f" );
        assertEquals( true, dn.isDescendantOf( ( Dn ) null ) );
    }


    @Test
    public void testAttributeEqualsIsCaseInSensitive() throws Exception
    {
        Dn name1 = new Dn( "cn=HomeDir" );
        Dn name2 = new Dn( "CN=HomeDir" );

        assertTrue( name1.equals( name2 ) );
    }


    @Test
    public void testAttributeTypeEqualsIsCaseInsensitive() throws Exception
    {
        Dn name1 = new Dn( "cn=HomeDir+Sn=WorkDir" );
        Dn name2 = new Dn( "cn=HomeDir+SN=WorkDir" );

        assertTrue( name1.equals( name2 ) );
    }


    @Test
    public void testNameEqualsIsInsensitiveToAttributesOrder() throws Exception
    {

        Dn name1 = new Dn( "cn=HomeDir+sn=WorkDir" );
        Dn name2 = new Dn( "sn=WorkDir+cn=HomeDir" );

        assertTrue( name1.equals( name2 ) );
    }


    @Test
    public void testAttributeComparisonIsCaseInSensitive() throws Exception
    {
        Dn name1 = new Dn( "cn=HomeDir" );
        Dn name2 = new Dn( "CN=HomeDir" );

        assertEquals( name1, name2 );
    }


    @Test
    public void testAttributeTypeComparisonIsCaseInsensitive() throws Exception
    {
        Dn name1 = new Dn( "cn=HomeDir+sn=WorkDir" );
        Dn name2 = new Dn( "cn=HomeDir+SN=WorkDir" );

        assertEquals( name1, name2 );
    }


    @Test
    public void testNameComparisonIsInsensitiveToAttributesOrder() throws Exception
    {

        Dn name1 = new Dn( "cn=HomeDir+sn=WorkDir" );
        Dn name2 = new Dn( "sn=WorkDir+cn=HomeDir" );

        assertEquals( name1, name2 );
    }


    @Test
    public void testNameComparisonIsInsensitiveToAttributesOrderFailure() throws Exception
    {

        Dn name1 = new Dn( "cn= HomeDir+sn=Workdir" );
        Dn name2 = new Dn( "sn = Work+cn=HomeDir" );

        assertNotSame( name1, name2 );
    }


    @Test
    public void testStringParser() throws Exception
    {
        String dn = Strings.utf8ToString( new byte[]
            { 'C', 'N', ' ', '=', ' ', 'E', 'm', 'm', 'a', 'n', 'u', 'e', 'l', ' ', ' ', 'L', ( byte ) 0xc3,
                ( byte ) 0xa9, 'c', 'h', 'a', 'r', 'n', 'y' } );

        Dn name = new Dn( dn );

        assertEquals( dn, ( name ).getName() );
        assertEquals( "CN=Emmanuel  L\u00e9charny", ( name ).getEscaped() );
    }


    /**
     * Class to test for Dn(String)
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testDnString() throws Exception
    {
        Dn name = new Dn( "" );
        Dn name50 = new Dn();
        assertEquals( name50, name );

        Dn name0 = new Dn( "ou=Marketing,ou=East" );
        Dn copy = new Dn( "ou=Marketing,ou=East" );
        Dn name1 = new Dn( "cn=John,ou=Marketing,ou=East" );
        Dn name2 = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );
        Dn name3 = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=West" );
        Dn name4 = new Dn( "cn=Website,cn=John,ou=Marketing,ou=West" );
        Dn name5 = new Dn( "cn=Airline,cn=John,ou=Marketing,ou=West" );

        assertEquals( name0, copy );
        assertTrue( name0.isAncestorOf( name1 ) );
        assertTrue( name0.isAncestorOf( name2 ) );
        assertTrue( name1.isAncestorOf( name2 ) );
        assertTrue( name2.isDescendantOf( name1 ) );
        assertTrue( name2.isDescendantOf( name0 ) );
        assertNotSame( name2, name3 );
        assertNotSame( name2, name4 );
        assertNotSame( name3, name4 );
        assertNotSame( name3, name5 );
        assertNotSame( name4, name5 );
        assertNotSame( name2, name5 );
    }

    /**
     * Class to test for Dn(SchemaManager, String)
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testDnStringSchemaAware() throws Exception
    {

        Dn dnPeople = new Dn( schemaManager, "ou=People,dc=example,dc=com" );
        Dn dnPeopleCase = new Dn( schemaManager, "ou=people,dc=ExAmPLE,dc=COM" );
        Dn dnJack = new Dn( schemaManager, "uid=jack,ou=People,dc=example,dc=com" );

        assertEquals( dnPeople, dnPeopleCase );
        assertTrue( dnPeople.isAncestorOf( dnJack ) );
        assertTrue( dnPeopleCase.isAncestorOf( dnJack ) );
        assertTrue( dnJack.isDescendantOf( dnPeople ) );
        assertTrue( dnJack.isDescendantOf( dnPeopleCase ) );
        assertNotSame( dnPeople, dnJack );
    }


    /**
     * Class to test for Dn()
     */
    @Test
    public void testDn()
    {
        Dn name = new Dn();
        assertTrue( name.toString().equals( "" ) );
    }


    /**
     * Class to test for size
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testSize() throws Exception
    {
        Dn name0 = new Dn( "" );
        Dn name1 = new Dn( "ou=East" );
        Dn name2 = new Dn( "ou=Marketing,ou=East" );
        Dn name3 = new Dn( "cn=John,ou=Marketing,ou=East" );
        Dn name4 = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );
        Dn name5 = new Dn( "cn=Website,cn=HomeDir,cn=John,ou=Marketing,ou=West" );
        Dn name6 = new Dn( "cn=Airline,cn=Website,cn=HomeDir,cn=John,ou=Marketing,ou=West" );

        assertEquals( 0, name0.size() );
        assertEquals( 1, name1.size() );
        assertEquals( 2, name2.size() );
        assertEquals( 3, name3.size() );
        assertEquals( 4, name4.size() );
        assertEquals( 5, name5.size() );
        assertEquals( 6, name6.size() );
    }


    /**
     * Class to test for isEmpty
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testIsEmpty() throws Exception
    {
        Dn name0 = new Dn( "" );
        Dn name1 = new Dn( "ou=East" );
        Dn name2 = new Dn( "ou=Marketing,ou=East" );
        Dn name3 = new Dn( "cn=John,ou=Marketing,ou=East" );
        Dn name4 = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );
        Dn name5 = new Dn( "cn=Website,cn=HomeDir,cn=John,ou=Marketing,ou=West" );
        Dn name6 = new Dn( "cn=Airline,cn=Website,cn=HomeDir,cn=John,ou=Marketing,ou=West" );

        assertEquals( true, name0.isEmpty() );
        assertEquals( false, name1.isEmpty() );
        assertEquals( false, name2.isEmpty() );
        assertEquals( false, name3.isEmpty() );
        assertEquals( false, name4.isEmpty() );
        assertEquals( false, name5.isEmpty() );
        assertEquals( false, name6.isEmpty() );
    }


    /**
     * Class to test for getAllRdn
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testIterator() throws Exception
    {
        Dn dn = new Dn( "cn=Airline,cn=Website,cn=HomeDir,cn=John,ou=Marketing,ou=West" );
        String[] expected = new String[]
            { "ou=West", "ou=Marketing", "cn=John", "cn=HomeDir", "cn=Website", "cn=Airline" };
        int count = 0;

        for ( Rdn rdn : dn )
        {
            assertEquals( expected[count], rdn.toString() );
            count++;
        }
    }


    /**
     * Test the getRdn( int ) method
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testGetRdn() throws Exception
    {
        Dn name = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );
        assertEquals( "cn=HomeDir", name.getRdn( 0 ).getName() );
        assertEquals( "cn=John", name.getRdn( 1 ).getName() );
        assertEquals( "ou=Marketing", name.getRdn( 2 ).getName() );
        assertEquals( "ou=East", name.getRdn( 3 ).getName() );
    }


    /**
     * Test the getRdns() method
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testGetRdns() throws Exception
    {
        Dn dn = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );

        String[] expected = new String[]
            { "cn=HomeDir", "cn=John", "ou=Marketing", "ou=East" };

        int i = 0;

        for ( Rdn rdn : dn.getRdns() )
        {
            assertEquals( expected[i], rdn.getName() );
            i++;
        }
    }


    /**
     * Class to test for getSuffix
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testGetXSuffix() throws Exception
    {
        Dn name = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );
        assertEquals( "", name.getDescendantOf( "cn=HomeDir,cn=John,ou=Marketing,ou=East" ).toString() );
        assertEquals( "cn=HomeDir", name.getDescendantOf( "cn=John,ou=Marketing,ou=East" ).toString() );
        assertEquals( "cn=HomeDir,cn=John", name.getDescendantOf( "ou=Marketing,ou=East" ).toString() );
        assertEquals( "cn=HomeDir,cn=John,ou=Marketing", name.getDescendantOf( "ou=East" ).toString() );
        assertEquals( "cn=HomeDir,cn=John,ou=Marketing,ou=East", name.getDescendantOf( "" ).toString() );
    }


    /**
     * Class to test for getPrefix
     *
     * @throws Exception if anything goes wrong
     */
    @Test
    public void testGetPrefix() throws Exception
    {
        Dn name = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );

        assertEquals( "cn=HomeDir,cn=John,ou=Marketing,ou=East", name.getAncestorOf( "" ).toString() );
        assertEquals( "cn=John,ou=Marketing,ou=East", name.getAncestorOf( "cn=HomeDir" ).toString() );
        assertEquals( "ou=Marketing,ou=East", name.getAncestorOf( "cn=HomeDir,cn=John" ).toString() );
        assertEquals( "ou=East", name.getAncestorOf( "cn=HomeDir,cn=John,ou=Marketing" ).toString() );
        assertEquals( "", name.getAncestorOf( "cn=HomeDir,cn=John,ou=Marketing,ou=East" ).toString() );
    }


    /**
     * Class to test for startsWith
     *
     * @throws Exception if anything goes wrong
     */
    @Test
    public void testStartsWith() throws Exception
    {
        Dn n0 = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );
        Dn n1 = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );
        Dn n2 = new Dn( "cn=John,ou=Marketing,ou=East" );
        Dn n3 = new Dn( "ou=Marketing,ou=East" );
        Dn n4 = new Dn( "ou=East" );
        Dn n5 = new Dn( "" );

        Dn n6 = new Dn( "cn=HomeDir" );
        Dn n7 = new Dn( "cn=HomeDir,cn=John" );
        Dn n8 = new Dn( "cn=HomeDir,cn=John,ou=Marketing" );

        // Check with Dn
        assertTrue( n0.isDescendantOf( n1 ) );
        assertTrue( n0.isDescendantOf( n2 ) );
        assertTrue( n0.isDescendantOf( n3 ) );
        assertTrue( n0.isDescendantOf( n4 ) );
        assertTrue( n0.isDescendantOf( n5 ) );

        assertTrue( !n0.isDescendantOf( n6 ) );
        assertTrue( !n0.isDescendantOf( n7 ) );
        assertTrue( !n0.isDescendantOf( n8 ) );

        Dn nn0 = new Dn( "cn=zero" );
        Dn nn10 = new Dn( "cn=one,cn=zero" );
        Dn nn210 = new Dn( "cn=two,cn=one,cn=zero" );
        Dn nn3210 = new Dn( "cn=three,cn=two,cn=one,cn=zero" );

        assertTrue( nn0.isDescendantOf( nn0 ) );
        assertTrue( nn10.isDescendantOf( nn0 ) );
        assertTrue( nn210.isDescendantOf( nn0 ) );
        assertTrue( nn3210.isDescendantOf( nn0 ) );

        assertTrue( nn10.isDescendantOf( nn10 ) );
        assertTrue( nn210.isDescendantOf( nn10 ) );
        assertTrue( nn3210.isDescendantOf( nn10 ) );

        assertTrue( nn210.isDescendantOf( nn210 ) );
        assertTrue( nn3210.isDescendantOf( nn210 ) );

        assertTrue( nn3210.isDescendantOf( nn3210 ) );

        assertTrue( new Dn( "ou=foo,dc=apache,dc=org" ).isDescendantOf( new Dn( "dc=apache,dc=org" ) ),
            "Starting Dn fails with ADS Dn" );

        assertTrue( new Dn( "ou=foo,dc=apache,dc=org" ).isDescendantOf( new Dn( "dc=apache,dc=org" ) ),
            "Starting Dn fails with Java LdapName" );

        assertTrue( new Dn( "dc=apache,dc=org" ).isDescendantOf( new Dn( "dc=apache,dc=org" ) ),
            "Starting Dn fails with Java LdapName" );
    }


    /**
     * Class to test for Dn addAll(Dn)
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testAddAllName0() throws Exception
    {
        Dn name = new Dn();
        Dn name0 = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );
        assertTrue( name0.equals( name.add( name0 ) ) );
    }


    /**
     * Class to test for Dn addAll(Dn)
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testAddAllNameExisting0() throws Exception
    {
        Dn name1 = new Dn( "ou=Marketing,ou=East" );
        Dn name2 = new Dn( "cn=HomeDir,cn=John" );
        Dn nameAdded = new Dn( "cn=HomeDir,cn=John, ou=Marketing,ou=East" );
        assertTrue( nameAdded.equals( name1.add( name2 ) ) );
    }


    /**
     * Class to test for Dn addAll(Dn)
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testAddAllName1() throws Exception
    {
        Dn name = new Dn();
        Dn name0 = new Dn( "ou=Marketing,ou=East" );
        Dn name1 = new Dn( "cn=HomeDir,cn=John" );
        Dn name2 = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );

        name = name.add( name0 );
        assertTrue( name0.equals( name ) );
        assertTrue( name2.equals( name.add( name1 ) ) );
    }


    /**
     * Class to test for Dn addAll(int, Dn)
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testAddAllintName0() throws Exception
    {
        Dn name = new Dn();
        Dn name0 = new Dn( "ou=Marketing,ou=East" );
        Dn name1 = new Dn( "cn=HomeDir,cn=John" );
        Dn name2 = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );

        name = name.add( name0 );
        assertTrue( name0.equals( name ) );
        assertTrue( name2.equals( name.add( name1 ) ) );
    }


    /**
     * Class to test for Dn add(String)
     *
     * @throws Exception when something goes wrong
     */
    @Test
    public void testAddString() throws Exception
    {
        Dn name = new Dn( schemaManager );
        assertEquals( name, new Dn( "" ) );

        Dn name4 = new Dn( schemaManager, "ou=East" );

        assertTrue( name.isSchemaAware() );

        name = name.add( "ou=East" );

        assertTrue( name.isSchemaAware() );

        assertEquals( name4, name );

        Dn name3 = new Dn( schemaManager, "ou=Marketing,ou=East" );
        name = name.add( "ou=Marketing" );
        assertEquals( name3, name );

        Dn name2 = new Dn( schemaManager, "cn=John,ou=Marketing,ou=East" );
        name = name.add( "cn=John" );
        assertEquals( name2, name );

        Dn name0 = new Dn( schemaManager, "cn=HomeDir,cn=John,ou=Marketing,ou=East" );
        name = name.add( "cn=HomeDir" );
        assertEquals( name0, name );
    }


    /**
     * Class to test for Name add(int, String)
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testAddintString() throws Exception
    {
        Dn name = new Dn();
        assertEquals( name, new Dn( "" ) );

        Dn name4 = new Dn( "ou=East" );
        name = name.add( "ou=East" );
        assertEquals( name4, name );

        Dn name3 = new Dn( "ou=Marketing,ou=East" );
        name = name.add( "ou=Marketing" );
        assertEquals( name3, name );

        Dn name2 = new Dn( "cn=John,ou=Marketing,ou=East" );
        name = name.add( "cn=John" );
        assertEquals( name2, name );

        Dn name0 = new Dn( "cn=HomeDir,cn=John,ou=Marketing,ou=East" );
        name = name.add( "cn=HomeDir" );
        assertEquals( name0, name );
    }


    /**
     * Class to test for String toString()
     *
     * @throws Exception if anything goes wrong
     */
    @Test
    public void testToString() throws Exception
    {
        Dn name = new Dn();
        assertEquals( "", name.toString() );

        name = name.add( "ou=East" );
        assertEquals( "ou=East", name.toString() );

        name = name.add( "ou=Marketing" );
        assertEquals( "ou=Marketing,ou=East", name.toString() );

        name = name.add( "cn=John" );
        assertEquals( "cn=John,ou=Marketing,ou=East", name.toString() );

        name = name.add( "cn=HomeDir" );
        assertEquals( "cn=HomeDir,cn=John,ou=Marketing,ou=East", name.toString() );
    }


    /**
     * Tests getParent().
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testGetParent() throws Exception
    {
        Dn empty = new Dn();
        assertEquals( Dn.EMPTY_DN, empty.getParent() );

        Dn one = new Dn( "cn=test" );
        assertNotNull( one.getParent() );
        assertTrue( one.getParent().isEmpty() );

        Dn two = new Dn( "cn=test,o=acme" );
        assertNotNull( two.getParent() );
        assertFalse( two.getParent().isSchemaAware() );
        assertFalse( two.getParent().isEmpty() );
        assertEquals( "o=acme", two.getParent().getName() );

        Dn three = new Dn( schemaManager, "cn=test,dc=example,dc=com" );
        Dn threeParent = three.getParent();
        assertNotNull( threeParent );
        assertTrue( threeParent.isSchemaAware() );
        assertFalse( threeParent.isEmpty() );
        assertEquals( "dc=example,dc=com", threeParent.getName() );
        assertEquals( 2, threeParent.getRdns().size() );

        Dn five = new Dn( "uid=user1,ou=sales,ou=users,dc=example,dc=com" );
        Dn fiveParent = five.getParent();
        assertNotNull( fiveParent );
        assertFalse( fiveParent.isSchemaAware() );
        assertFalse( fiveParent.isEmpty() );
        assertEquals( "ou=sales,ou=users,dc=example,dc=com", fiveParent.getName() );
        assertEquals( 4, fiveParent.getRdns().size() );
    }


    /**
     * Class to test for boolean equals(Object)
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testEqualsObject() throws Exception
    {
        assertTrue( new Dn( "ou=People" ).equals( new Dn( "ou=People" ) ) );

        assertTrue( !new Dn( "ou=People,dc=example,dc=com" ).equals( new Dn( "ou=People" ) ) );
        assertTrue( !new Dn( "ou=people" ).equals( new Dn( "ou=People" ) ) );
        assertTrue( !new Dn( "ou=Groups" ).equals( new Dn( "ou=People" ) ) );
    }


    @Test
    public void testNameFrenchChars() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', 0x4A, ( byte ) 0xC3, ( byte ) 0xA9, 0x72, ( byte ) 0xC3, ( byte ) 0xB4, 0x6D, 0x65 },
            StandardCharsets.UTF_8 );

        Dn name = new Dn( cn );

        assertEquals( "cn=J\u00e9r\u00f4me", name.toString() );
    }


    @Test
    public void testNameGermanChars() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC3, ( byte ) 0x84, ( byte ) 0xC3, ( byte ) 0x96, ( byte ) 0xC3, ( byte ) 0x9C,
                ( byte ) 0xC3, ( byte ) 0x9F, ( byte ) 0xC3, ( byte ) 0xA4, ( byte ) 0xC3, ( byte ) 0xB6,
                ( byte ) 0xC3, ( byte ) 0xBC }, StandardCharsets.UTF_8 );

        Dn name = new Dn( cn );

        assertEquals( "cn=\u00C4\u00D6\u00DC\u00DF\u00E4\u00F6\u00FC", name.toString() );
    }


    @Test
    public void testNameTurkishChars() throws Exception
    {
        String cn = new String( new byte[]
            { 'c', 'n', '=', ( byte ) 0xC4, ( byte ) 0xB0, ( byte ) 0xC4, ( byte ) 0xB1, ( byte ) 0xC5, ( byte ) 0x9E,
                ( byte ) 0xC5, ( byte ) 0x9F, ( byte ) 0xC3, ( byte ) 0x96, ( byte ) 0xC3, ( byte ) 0xB6,
                ( byte ) 0xC3, ( byte ) 0x9C, ( byte ) 0xC3, ( byte ) 0xBC, ( byte ) 0xC4, ( byte ) 0x9E,
                ( byte ) 0xC4, ( byte ) 0x9F }, StandardCharsets.UTF_8 );

        Dn name = new Dn( cn );

        assertEquals( "cn=\u0130\u0131\u015E\u015F\u00D6\u00F6\u00DC\u00FC\u011E\u011F", name.toString() );
    }


    /**
     * Class to test for toOid( Dn, Map)
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testLdapNameToName() throws Exception
    {
        Dn name = new Dn( "ou= Some   People   ", "dc = eXample", "dc= cOm" );

        assertEquals( "ou= Some   People   ,dc = eXample,dc= cOm", name.getName() );

        Dn result = new Dn( schemaManager, name );

        assertEquals( "ou=Some   People,dc=eXample,dc=cOm",
            result.getEscaped() );
        assertEquals( "2.5.4.11= some  people ,0.9.2342.19200300.100.1.25= example ,0.9.2342.19200300.100.1.25= com ", 
            result.getNormName() );
    }


    @Test
    public void testRdnGetTypeUpName() throws Exception
    {
        Dn name = new Dn( "ou= Some   People   ", "dc = eXample", "dc= cOm" );

        assertTrue( name.getName().equals( "ou= Some   People   ,dc = eXample,dc= cOm" ) );

        Rdn rdn = name.getRdn();

        assertEquals( "ou= Some   People   ", rdn.getName() );
        assertEquals( "ou", rdn.getNormType() );
        assertEquals( "ou", rdn.getType() );

        Dn result = new Dn( schemaManager, name );

        assertTrue( result.equals(
            "ou=some people,dc=example,dc=com" ) );
        assertTrue( name.getName().equals( "ou= Some   People   ,dc = eXample,dc= cOm" ) );

        Rdn rdn2 = result.getRdn();

        assertEquals( "ou= Some   People   ", rdn2.getName() );
        assertEquals( "2.5.4.11", rdn2.getNormType() );
        assertEquals( "ou", rdn2.getType() );
    }


    /**
     * Class to test for toOid( Dn, Map) with a NULL dn
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testLdapNameToNameEmpty() throws Exception
    {
        Dn name = new Dn();

        Dn result = new Dn( schemaManager, name );
        assertTrue( result.toString().equals( "" ) );
    }


    /**
     * Class to test for toOid( Dn, Map) with a multiple NameComponent
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testLdapNameToNameMultiNC() throws Exception
    {
        Dn name = new Dn(
            "ou= Some   People   + 0.9.2342.19200300.100.1.25=  And   Some anImAls,0.9.2342.19200300.100.1.25 = eXample,dc= cOm" );

        Dn result = new Dn( schemaManager, name );

        assertEquals( result,
                "0.9.2342.19200300.100.1.25=and some animals+ou=some people,0.9.2342.19200300.100.1.25=eXample,dc=cOm" );
        assertEquals(
                "ou= Some   People   + 0.9.2342.19200300.100.1.25=  And   Some anImAls,0.9.2342.19200300.100.1.25 = eXample,dc= cOm",
                result.getName() );
    }


    /**
     * Class to test for toOid( Dn, Map) with a multiple NameComponent
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testLdapNameToNameAliasMultiNC() throws Exception
    {
        Dn name = new Dn(
            "ou= Some   People   + domainComponent=  And   Some anImAls,DomainComponent = eXample,0.9.2342.19200300.100.1.25= cOm" );

        Dn result = new Dn( schemaManager, name );

        assertEquals( "domainComponent=And   Some anImAls+ou=Some   People,DomainComponent=eXample,0.9.2342.19200300.100.1.25=cOm",
            result.getEscaped() );
        assertEquals( "ou= Some   People   + domainComponent=  And   Some anImAls,DomainComponent = eXample,0.9.2342.19200300.100.1.25= cOm",
            result.getName() );
    }


    /**
     * Class to test for hashCode().
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testLdapNameHashCode() throws Exception
    {
        Dn name1 = new Dn(
            schemaManager,
            "ou= Some   People   + domainComponent=  And   Some anImAls,DomainComponent = eXample,0.9.2342.19200300.100.1.25= cOm" );

        Dn name2 = new Dn( schemaManager,
            "ou=some people+domainComponent=and some animals,DomainComponent=example,0.9.2342.19200300.100.1.25=com" );

        assertEquals( name1.hashCode(), name2.hashCode() );
    }


    /**
     * Test for DIRSERVER-191
     *
     * @throws LdapException if anything goes wrong.
     * @throws InvalidNameException if anything goes wrong.
     */
    @Test
    public void testName() throws LdapException, InvalidNameException
    {
        LdapName jName = new javax.naming.ldap.LdapName( "cn=four,cn=three,cn=two,cn=one" );
        Dn aName = new Dn( "cn=four,cn=three,cn=two,cn=one" );
        assertEquals( jName.toString(), "cn=four,cn=three,cn=two,cn=one" );
        assertEquals( aName.toString(), "cn=four,cn=three,cn=two,cn=one" );
        assertEquals( jName.toString(), aName.toString() );
    }


    /**
     * Test for DIRSERVER-191
     *
     * @throws LdapException if anything goes wrong.
     * @throws InvalidNameException if anything goes wrong.
     */
    @Test
    public void testGetPrefixName() throws LdapException, InvalidNameException
    {
        LdapName jName = new LdapName( "cn=four,cn=three,cn=two,cn=one" );
        Dn aName = new Dn( "cn=four,cn=three,cn=two,cn=one" );

        assertEquals( jName.getPrefix( 0 ).toString(), aName.getAncestorOf( "cn=four,cn=three,cn=two,cn=one" )
            .toString() );
        assertEquals( jName.getPrefix( 1 ).toString(), aName.getAncestorOf( "cn=four,cn=three,cn=two" ).toString() );
        assertEquals( jName.getPrefix( 2 ).toString(), aName.getAncestorOf( "cn=four,cn=three" ).toString() );
        assertEquals( jName.getPrefix( 3 ).toString(), aName.getAncestorOf( "cn=four" ).toString() );
        assertEquals( jName.getPrefix( 4 ).toString(), aName.getAncestorOf( "" ).toString() );
    }


    /**
     * Test for DIRSERVER-191
     *
     * @throws LdapException if anything goes wrong.
     * @throws InvalidNameException if anything goes wrong.
     */
    @Test
    public void testGetSuffix() throws LdapException, InvalidNameException
    {
        LdapName jName = new LdapName( "cn=four,cn=three,cn=two,cn=one" );
        Dn aName = new Dn( "cn=four,cn=three,cn=two,cn=one" );

        assertEquals( jName.getSuffix( 0 ).toString(), aName.getDescendantOf( "" ).toString() );
        assertEquals( jName.getSuffix( 1 ).toString(), aName.getDescendantOf( "cn=one" ).toString() );
        assertEquals( jName.getSuffix( 2 ).toString(), aName.getDescendantOf( "cn=two,cn=one" ).toString() );
        assertEquals( jName.getSuffix( 3 ).toString(), aName.getDescendantOf( "cn=three,cn=two,cn=one" ).toString() );
        assertEquals( jName.getSuffix( 4 ).toString(), aName.getDescendantOf( "cn=four,cn=three,cn=two,cn=one" )
            .toString() );
    }


    /**
     * Test for DIRSERVER-191. The Dn is immutable, thus we can't add a new Rdn
     * to a Dn, it simply creates a new one.
     *
     * @throws LdapException if anything goes wrong.
     * @throws InvalidNameException if anything goes wrong.
     */
    @Test
    public void testAddStringName() throws LdapException, InvalidNameException
    {
        LdapName jName = new LdapName( "cn=four,cn=three,cn=two,cn=one" );
        Dn aName = new Dn( "cn=four,cn=three,cn=two,cn=one" );

        assertSame( jName, jName.add( "cn=five" ) );
        assertNotSame( aName, aName.add( "cn=five" ) );
        assertNotSame( jName.toString(), aName.toString() );
    }


    /**
     * Test for DIRSERVER-191
     *
     * @throws LdapException if anything goes wrong.
     * @throws InvalidNameException if anything goes wrong.
     */
    @Test
    public void testAddAllName() throws LdapException, InvalidNameException
    {
        LdapName jName = new LdapName( "cn=four,cn=three,cn=two,cn=one" );
        Dn aName = new Dn( "cn=four,cn=three,cn=two,cn=one" );

        assertSame( jName, jName.addAll( new LdapName( "cn=seven,cn=six" ) ) );
        assertNotSame( aName, aName.add( new Dn( "cn=seven,cn=six" ) ) );
        assertNotSame( jName.toString(), aName.toString() );
    }


    /**
     * Test for DIRSERVER-191
     *
     * @throws LdapException if anything goes wrong.
     * @throws InvalidNameException if anything goes wrong.
     */
    @Test
    public void testAddAllIntName() throws LdapException, InvalidNameException
    {
        LdapName jName = new LdapName( "cn=four,cn=three,cn=two,cn=one" );
        Dn aName = new Dn( "cn=four,cn=three,cn=two,cn=one" );

        assertSame( jName, jName.addAll( 0, new LdapName( "cn=zero,cn=zero.5" ) ) );
        assertNotSame( aName, aName.add( new Dn( "cn=zero,cn=zero.5" ) ) );
        assertNotSame( jName.toString(), aName.toString() );

        assertSame( jName, jName.addAll( 2, new LdapName( "cn=zero,cn=zero.5" ) ) );
        assertNotSame( aName, aName.add( new Dn( "cn=zero,cn=zero.5" ) ) );
        assertNotSame( jName.toString(), aName.toString() );

        assertSame( jName, jName.addAll( jName.size(), new LdapName( "cn=zero,cn=zero.5" ) ) );
        assertNotSame( aName, aName.add( new Dn( "cn=zero,cn=zero.5" ) ) );
        assertNotSame( jName.toString(), aName.toString() );
    }


    /**
     * Test for DIRSERVER-191
     *
     * @throws LdapException if anything goes wrong.
     * @throws InvalidNameException if anything goes wrong.
     */
    @Test
    public void testStartsWithName() throws LdapException, InvalidNameException
    {
        LdapName jName = new LdapName( "cn=four,cn=three,cn=two,cn=one" );
        Dn aName = new Dn( "cn=four,cn=three,cn=two,cn=one" );

        assertEquals( jName.startsWith( new LdapName( "cn=seven,cn=six,cn=five" ) ),
            aName.isDescendantOf( new Dn( "cn=seven,cn=six,cn=five" ) ) );
        assertEquals( jName.startsWith( new LdapName( "cn=three,cn=two,cn=one" ) ),
            aName.isDescendantOf( new Dn( "cn=three,cn=two,cn=one" ) ) );
    }


    /**
     * Test for DIRSERVER-642
     *
     * @throws LdapException if anything goes wrong.
     */
    @Test
    public void testDoubleQuoteInNameDIRSERVER_642() throws LdapException
    {
        Dn name1 = new Dn( "cn=\"Kylie Minogue\",dc=example,dc=com" );

        String[] expected = new String[]
            { "cn=\"Kylie Minogue\"", "dc=example", "dc=com" };

        List<Rdn> j = name1.getRdns();
        int count = 0;

        for ( Rdn rdn : j )
        {
            assertEquals( expected[count], rdn.getName() );
            count++;
        }
    }


    /**
     * Test for DIRSERVER-642
     *
     * @throws LdapException if anything goes wrong.
     */
    @Test
    public void testDoubleQuoteInNameDIRSERVER_642_1() throws LdapException
    {
        Dn dn = new Dn( "cn=\" Kylie Minogue \",dc=example,dc=com" );

        assertEquals( "cn=\" Kylie Minogue \",dc=example,dc=com", dn.getName() );
        assertEquals( "cn=\\ Kylie Minogue\\ ,dc=example,dc=com", dn.getEscaped() );
    }


    /**
     * Test for DIRSTUDIO-250
     *
     * @throws LdapException if anything goes wrong.
     */
    @Test
    public void testDoubleQuoteWithSpecialCharsInNameDIRSERVER_250() throws LdapException
    {
        Dn dn = new Dn( "a=\"b,c\"" );

        assertEquals( "a=\"b,c\"", dn.getName() );
        assertEquals( "a=b\\,c", dn.getEscaped() );
    }


    /**
     * Test for DIRSERVER-184
     *
     * @throws LdapException if anything goes wrong.
     */
    @Test
    public void testLeadingAndTrailingSpacesDIRSERVER_184() throws LdapException
    {
        Dn name = new Dn( "dn= \\ four spaces leading and 3 trailing \\  " );

        assertEquals( "dn=\\ four spaces leading and 3 trailing \\ ", name.getEscaped() );
        assertEquals( "dn= \\ four spaces leading and 3 trailing \\  ", name.getName() );
    }


    /**
     * Test for DIRSERVER-184
     */
    @Test
    public void testDIRSERVER_184_1()
    {
        try
        {
            new Dn( "dn=middle\\ spaces" );
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }
    }


    /**
     * Test for DIRSERVER-184
     */
    @Test
    public void testDIRSERVER_184_2()
    {
        try
        {
            new Dn( "dn=# a leading pound" );
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }
    }


    /**
     * Test for DIRSERVER-184
     *
     * @throws LdapException if anything goes wrong.
     */
    @Test
    public void testDIRSERVER_184_3() throws LdapException
    {
        Dn name = new Dn( "dn=\\# a leading pound" );

        assertEquals( "dn=\\# a leading pound", name.toString() );
        assertEquals( "dn=\\# a leading pound", name.getName() );
    }


    /**
     * Test for DIRSERVER-184
     *
     * @throws LdapException if anything goes wrong.
     */
    @Test
    public void testDIRSERVER_184_4() throws LdapException
    {
        Dn name = new Dn( "dn=a middle \\# pound" );

        assertEquals( "dn=a middle # pound", name.getEscaped() );
        assertEquals( "dn=a middle \\# pound", name.getName() );
    }


    /**
     * Test for DIRSERVER-184
     *
     * @throws LdapException if anything goes wrong.
     */
    @Test
    public void testDIRSERVER_184_5() throws LdapException
    {
        Dn name = new Dn( "dn=a trailing pound \\#" );

        assertEquals( "dn=a trailing pound #", name.getEscaped() );
        assertEquals( "dn=a trailing pound \\#", name.getName() );
    }


    /**
     * Test for DIRSERVER-184
     */
    @Test
    public void testDIRSERVER_184_6()
    {
        try
        {
            new Dn( "dn=a middle # pound" );
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }
    }


    /**
     * Test for DIRSERVER-184
     */
    @Test
    public void testDIRSERVER_184_7()
    {
        try
        {
            new Dn( "dn=a trailing pound #" );
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }
    }


    @Test
    public void testDIRSERVER_631_1() throws LdapException
    {
        Dn name = new Dn( "cn=Bush\\, Kate,dc=example,dc=com" );

        assertEquals( "cn=Bush\\, Kate,dc=example,dc=com", name.toString() );
        assertEquals( "cn=Bush\\, Kate,dc=example,dc=com", name.getName() );

    }


    /**
     * Added a test to check the parsing of a Dn with more than one Rdn
     * which are OIDs, and with one Rdn which has more than one atav.
     *
     * @throws LdapException if anything goes wrong.
     */
    @Test
    public void testDNWithMultiOidsRDN() throws LdapException
    {
        Dn name = new Dn(
            "0.9.2342.19200300.100.1.1=00123456789+2.5.4.3=pablo picasso,ou=search,2.5.4.10=imc,2.5.4.6=us" );
        assertEquals(
            "0.9.2342.19200300.100.1.1=00123456789+2.5.4.3=pablo picasso,ou=search,2.5.4.10=imc,2.5.4.6=us",
            name.toString() );
        assertEquals(
            "0.9.2342.19200300.100.1.1=00123456789+2.5.4.3=pablo picasso,ou=search,2.5.4.10=imc,2.5.4.6=us",
            name.getName() );
    }


    @Test
    public void testDNEquals() throws LdapException
    {
        Dn dn1 = new Dn( "a=b,c=d,e=f" );
        Dn dn2 = new Dn( "a=b\\,c\\=d,e=f" );

        assertFalse( dn1.getEscaped().equals( dn2.getEscaped() ) );
    }


    @Test
    public void testDNAddEmptyString() throws LdapException
    {
        Dn dn = new Dn();
        assertTrue( dn.size() == 0 );
        assertTrue( dn.add( "" ).size() == 0 );
    }


    /**
     * This leads to the bug in DIRSERVER-832.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testPreserveAttributeIdCase() throws LdapException
    {
        Dn dn = new Dn( "uID=kevin" );
        assertEquals( "uID", dn.getRdn().getType() );
    }


    /**
     * Tests the Dn.isValid() method.
     */
    @Test
    public void testIsValid()
    {
        assertTrue( Dn.isValid( "" ) );

        assertFalse( Dn.isValid( "a" ) );
        assertFalse( Dn.isValid( "a " ) );

        assertTrue( Dn.isValid( "a=" ) );
        assertTrue( Dn.isValid( "a= " ) );

        assertFalse( Dn.isValid( "=" ) );
        assertFalse( Dn.isValid( " = " ) );
        assertFalse( Dn.isValid( " = a" ) );
    }


    @Test
    public void testCompositeRDN() throws LdapException
    {
        assertTrue( Dn.isValid( "a=b+c=d+e=f,g=h" ) );

        Dn dn = new Dn( "a=b+c=d+e=f,g=h" );

        assertEquals( "a=b+c=d+e=f,g=h", dn.toString() );
    }


    @Test
    public void testCompositeRDNShemaAware() throws LdapException
    {
        Dn dn1 = new Dn( schemaManager, "cn=abc + cn=def + cn=ghi, ou=system" );
        Dn dn2 = new Dn( schemaManager, "cn=def + cn=abc + cn=ghi, ou=system" );
        Dn dn3 = new Dn( schemaManager, "cn=ghi + cn=def + cn=abc, ou=system" );

        assertEquals( dn1, dn2 );
        assertEquals( dn1, dn3 );
        assertEquals( dn2, dn3 );
    }


    @Test
    public void testCompositeRDNOids() throws LdapException
    {
        assertTrue( Dn
            .isValid( "1.2.3.4.5=0+1.2.3.4.6=0+1.2.3.4.7=omnischmomni,2.5.4.3=subtree,0.9.2342.19200300.100.1.25=example,0.9.2342.19200300.100.1.25=com" ) );

        Dn dn = new Dn(
            "1.2.3.4.5=0+1.2.3.4.6=0+1.2.3.4.7=omnischmomni,2.5.4.3=subtree,0.9.2342.19200300.100.1.25=example,0.9.2342.19200300.100.1.25=com" );

        assertEquals(
            "1.2.3.4.5=0+1.2.3.4.6=0+1.2.3.4.7=omnischmomni,2.5.4.3=subtree,0.9.2342.19200300.100.1.25=example,0.9.2342.19200300.100.1.25=com",
            dn.toString() );
    }


    /**
     * Tests that AttributeTypeAndValues are correctly trimmed.
     *
     * @throws LdapException if anything goes wrong.
     */
    @Test
    public void testTrimAtavs() throws LdapException
    {
        // antlr parser: string value with trailing spaces
        Dn dn1 = new Dn( " cn = Amos\\,Tori , ou=system " );
        assertEquals( " cn = Amos\\,Tori ", dn1.getRdn().getName() );
        Ava atav1 = dn1.getRdn().getAva();
        assertEquals( "cn", atav1.getType() );
        assertEquals( "Amos,Tori", atav1.getValue().getString() );

        // antlr parser: hexstring with trailing spaces
        Dn dn3 = new Dn( " cn = #414243 , ou=system " );
        assertEquals( " cn = #414243 ", dn3.getRdn().getName() );
        Ava atav3 = dn3.getRdn().getAva();
        assertEquals( "cn", atav3.getType() );
        assertTrue( Arrays.equals( Strings.getBytesUtf8( "ABC" ), atav3.getValue().getBytes() ) );
        assertTrue( Arrays.equals( Strings.getBytesUtf8( "ABC" ), atav3.getValue().getBytes() ) );

        // antlr parser:
        Dn dn4 = new Dn( " cn = \\41\\42\\43 , ou=system " );
        assertEquals( " cn = \\41\\42\\43 ", dn4.getRdn().getName() );
        Ava atav4 = dn4.getRdn().getAva();
        assertEquals( "cn", atav4.getType() );
        assertEquals( "ABC", atav4.getValue().getString() );

        // antlr parser: quotestring with trailing spaces
        Dn dn5 = new Dn( " cn = \"ABC\" , ou=system " );
        assertEquals( " cn = \"ABC\" ", dn5.getRdn().getName() );
        Ava atav5 = dn5.getRdn().getAva();
        assertEquals( "cn", atav5.getType() );
        assertEquals( "ABC", atav5.getValue() .getString());

        // fast parser: string value with trailing spaces
        Dn dn2 = new Dn( " cn = Amos Tori , ou=system " );
        assertEquals( " cn = Amos Tori ", dn2.getRdn().getName() );
        Ava atav2 = dn2.getRdn().getAva();
        assertEquals( "cn", atav2.getType() );
        assertEquals( "Amos Tori", atav2.getValue().getString() );
    }


    /**
     * Test for DIRSHARED-39.
     * (Trailing escaped space not parsed correctly by the Dn parser(
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testTrailingEscapedSpace() throws Exception
    {
        Dn dn1 = new Dn( schemaManager, "ou=A\\ ,ou=system" );
        assertEquals( "ou=A\\ ,ou=system", dn1.getName() );
        assertEquals( "ou=A\\ ,ou=system", dn1.getEscaped() );
        assertEquals( "ou=A\\ ", dn1.getRdn().getName() );
        assertEquals( "ou=A\\ ", dn1.getRdn().getEscaped() );

        Dn dn2 = new Dn( schemaManager, "ou=A\\20,ou=system" );
        assertEquals( "ou=A\\20,ou=system", dn2.getName() );
        assertEquals( "ou=A\\ ,ou=system", dn2.getEscaped() );
        assertEquals( "ou=A\\20", dn2.getRdn().getName() );
        assertEquals( "ou=A\\ ", dn2.getRdn().getEscaped() );

        Dn dn3 = new Dn( schemaManager, "ou=\\ ,ou=system" );
        assertEquals( "ou=\\ ,ou=system", dn3.getName() );
        assertEquals( "ou=\\ ,ou=system", dn3.getEscaped() );
        assertEquals( "ou=\\ ", dn3.getRdn().getName() );
        assertEquals( "ou=\\ ", dn3.getRdn().getEscaped() );

        Dn dn4 = new Dn( schemaManager, "ou=\\20,ou=system" );
        assertEquals( "ou=\\20,ou=system", dn4.getName() );
        assertEquals( "ou=\\ ,ou=system", dn4.getEscaped() );
        assertEquals( "ou=\\20", dn4.getRdn().getName() );
        assertEquals( "ou=\\ ", dn4.getRdn().getEscaped() );
    }


    /**
     * Test for DIRSHARED-41, DIRSTUDIO-603.
     * (Dn parser fails to parse names containing an numeric OID value)
     *
     * @throws Exception if anything goes wrong.
     */
    @Test
    public void testNumericOid() throws Exception
    {
        new Dn( "ipHostNumber=X127.0.0.1+cn=loopback,ou=Hosts,dc=mygfs,dc=com" );

        // numeric OID only
        Dn dn1 = new Dn( "cn=loopback+ipHostNumber=127.0.0.1,ou=Hosts,dc=mygfs,dc=com" );
        assertEquals( "cn=loopback+ipHostNumber=127.0.0.1,ou=Hosts,dc=mygfs,dc=com", dn1.getName() );
        assertEquals( "cn=loopback+ipHostNumber=127.0.0.1,ou=Hosts,dc=mygfs,dc=com", dn1.getEscaped() );
        assertEquals( "cn=loopback+ipHostNumber=127.0.0.1", dn1.getRdn().getName() );
        assertEquals( "cn=loopback+ipHostNumber=127.0.0.1", dn1.getRdn().getEscaped() );
        assertEquals( "127.0.0.1", dn1.getRdn().getAva( "ipHostNumber" ).getValue().getString() );

        // numeric OID with suffix
        Dn dn2 = new Dn( "cn=loopback+ipHostNumber=X127.0.0.1,ou=Hosts,dc=mygfs,dc=com" );
        assertEquals( "cn=loopback+ipHostNumber=X127.0.0.1,ou=Hosts,dc=mygfs,dc=com", dn2.getName() );
        assertEquals( "cn=loopback+ipHostNumber=X127.0.0.1,ou=Hosts,dc=mygfs,dc=com", dn2.getEscaped() );
        assertEquals( "cn=loopback+ipHostNumber=X127.0.0.1", dn2.getRdn().getName() );
        assertEquals( "cn=loopback+ipHostNumber=X127.0.0.1", dn2.getRdn().getEscaped() );

        // numeric OID with prefix
        Dn dn3 = new Dn( "cn=loopback+ipHostNumber=127.0.0.1Y,ou=Hosts,dc=mygfs,dc=com" );
        assertEquals( "cn=loopback+ipHostNumber=127.0.0.1Y,ou=Hosts,dc=mygfs,dc=com", dn3.getName() );
        assertEquals( "cn=loopback+ipHostNumber=127.0.0.1Y,ou=Hosts,dc=mygfs,dc=com", dn3.getEscaped() );
        assertEquals( "cn=loopback+ipHostNumber=127.0.0.1Y", dn3.getRdn().getName() );
        assertEquals( "cn=loopback+ipHostNumber=127.0.0.1Y", dn3.getRdn().getEscaped() );

        // numeric OID with special characters
        Dn dn4 = new Dn( "cn=loopback+ipHostNumber=\\#127.0.0.1 Z,ou=Hosts,dc=mygfs,dc=com" );
        assertEquals( "cn=loopback+ipHostNumber=\\#127.0.0.1 Z,ou=Hosts,dc=mygfs,dc=com", dn4.getName() );
        assertEquals( "cn=loopback+ipHostNumber=\\#127.0.0.1 Z,ou=Hosts,dc=mygfs,dc=com", dn4.getEscaped() );
        assertEquals( "cn=loopback+ipHostNumber=\\#127.0.0.1 Z", dn4.getRdn().getName() );
        assertEquals( "cn=loopback+ipHostNumber=\\#127.0.0.1 Z", dn4.getRdn().getEscaped() );
    }


    @Test
    public void testNormalizeAscii() throws Exception
    {
        Dn dn = new Dn( "  ou  =  Example ,  ou  =  COM " );

        new Dn( schemaManager, dn );
        assertEquals( "ou=Example,ou=COM", dn.getEscaped() );
        assertEquals( "  ou  =  Example ,  ou  =  COM ", dn.getName() );

        Rdn rdn = dn.getRdn();
        assertEquals( "ou", rdn.getNormType() );
        assertEquals( "  ou  =  Example ", rdn.getName() );
        assertEquals( "ou=Example", rdn.getEscaped() );
        assertEquals( "ou", rdn.getType() );
        assertEquals( "Example", rdn.getValue() );

        Ava atav = rdn.getAva();

        assertEquals( "ou=Example", atav.getEscaped() );
        assertEquals( "ou", atav.getNormType() );
        assertEquals( "Example", atav.getValue().getString() );

        assertEquals( "ou", atav.getType() );
        assertEquals( "Example", atav.getValue().getString() );

        assertEquals( "ou=Example", atav.getName() );
    }


    @Test
    public void testNormalizeAsciiComposite() throws Exception
    {
        Dn dn = new Dn( "  ou  =  Example + cn = TEST ,  ou  =  COM " );

        new Dn( schemaManager, dn );
        assertEquals( "cn=TEST+ou=Example,ou=COM", dn.getEscaped() );
        assertEquals( "  ou  =  Example + cn = TEST ,  ou  =  COM ", dn.getName() );

        Rdn rdn = dn.getRdn();
        assertEquals( "cn", rdn.getNormType() );
        assertEquals( "cn=TEST+ou=Example", rdn.getEscaped() );
        assertEquals( "cn", rdn.getType() );
        assertEquals( "TEST", rdn.getValue() );
        assertEquals( "  ou  =  Example + cn = TEST ", rdn.getName() );

        // The first ATAV
        Ava atav = rdn.getAva();

        assertEquals( "cn=TEST", atav.getEscaped() );
        assertEquals( "cn", atav.getNormType() );
        assertEquals( "TEST", atav.getValue().getString() );

        assertEquals( "cn", atav.getType() );
        assertEquals( "TEST", atav.getValue().getString() );

        assertEquals( " cn = TEST ", atav.getName() );

        assertEquals( 2, rdn.size() );

        // The second ATAV
        for ( Ava ava : rdn )
        {
            if ( "Example".equals( ava.getValue().getString() ) )
            {
                // Skip the first one
                continue;
            }

            assertEquals( "cn=TEST", ava.getEscaped() );
            assertEquals( "cn", ava.getNormType() );
            assertEquals( "TEST", ava.getValue().getString() );

            assertEquals( "cn", ava.getType() );
            assertEquals( "TEST", ava.getValue().getString() );
            assertEquals( " cn = TEST ", ava.getName() );
        }
    }


    @Test
    public void testNormalizeAsciiWithEscaped() throws Exception
    {
        Dn dn = new Dn( "  ou  =  Ex\\+mple " );

        new Dn( schemaManager, dn );
        assertEquals( "ou=Ex\\+mple", dn.getEscaped() );
        assertEquals( "  ou  =  Ex\\+mple ", dn.getName() );

        Rdn rdn = dn.getRdn();
        assertEquals( "ou", rdn.getNormType() );
        assertEquals( "ou=Ex\\+mple", rdn.getEscaped() );
        assertEquals( "ou", rdn.getType() );
        assertEquals( "Ex+mple", rdn.getValue() );
        assertEquals( "  ou  =  Ex\\+mple ", rdn.getName() );

        Ava atav = rdn.getAva();

        assertEquals( "ou=Ex\\+mple", atav.getEscaped() );
        assertEquals( "ou", atav.getNormType() );
        assertEquals( "Ex+mple", atav.getValue().getString() );

        assertEquals( "ou", atav.getType() );
        assertEquals( "Ex+mple", atav.getValue().getString() );

        assertEquals( "  ou  =  Ex\\+mple ", atav.getName() );
    }


    @Test
    public void testNormalizeBackSlash() throws Exception
    {
        Dn dn = new Dn( "cn=A\\,b,dc=com" );
        Dn newDn = new Dn( schemaManager, dn );
        
        // The original DN
        assertEquals( "cn=A\\,b,dc=com", dn.toString() );
        assertEquals( "cn=A\\,b,dc=com", dn.getName() );
        assertEquals( "cn=A,b,dc=com", dn.getNormName() );
        assertEquals( "cn=A\\,b,dc=com", dn.getEscaped() );

        // The new DN
        assertEquals( "cn=A\\,b,dc=com", newDn.toString() );
        assertEquals( "cn=A\\,b,dc=com", newDn.getName() );
        assertEquals( "2.5.4.3= a,b ,0.9.2342.19200300.100.1.25= com ", newDn.getNormName() );
        assertEquals( "cn=A\\,b,dc=com", newDn.getEscaped() );
    }


    @Test
    public void testNormalizeCompositeWithEscaped() throws Exception
    {
        Dn dn = new Dn( "  OU  =  Ex\\+mple + cn = T\\+ST\\  ,  ou  =  COM " );

        // ------------------------------------------------------------------
        // Before normalization
        assertEquals( "  OU  =  Ex\\+mple + cn = T\\+ST\\  ,  ou  =  COM ", dn.getName() );
        assertEquals( "cn=T\\+ST\\ +OU=Ex\\+mple,ou=COM", dn.getEscaped() );

        // Check the first Rdn
        Rdn rdn = dn.getRdn();
        assertEquals( "  OU  =  Ex\\+mple + cn = T\\+ST\\  ", rdn.getName() );
        assertEquals( "cn=T\\+ST\\ +OU=Ex\\+mple", rdn.getEscaped() );

        assertEquals( "cn", rdn.getType() );
        assertEquals( "cn", rdn.getNormType() );

        assertEquals( "T+ST ", rdn.getValue() );
        assertEquals( "T+ST ", rdn.getAva().getValue().getString() );

        // The first ATAV
        Ava atav = rdn.getAva();

        assertEquals( " cn = T\\+ST\\  ", atav.getName() );
        assertEquals( "cn=T\\+ST\\ ", atav.getEscaped() );

        assertEquals( "cn", atav.getNormType() );
        assertEquals( "cn", atav.getType() );

        assertEquals( "T+ST ", atav.getValue().getString() );

        assertEquals( 2, rdn.size() );

        // The second ATAV
        for ( Ava ava : rdn )
        {
            if ( "Ex+mple".equals( ava.getValue().getString() ) )
            {
                // Skip the first one
                continue;
            }

            assertEquals( " cn = T\\+ST\\  ", ava.getName() );
            assertEquals( "cn=T\\+ST\\ ", ava.getEscaped() );

            assertEquals( "cn", ava.getType() );
            assertEquals( "cn", ava.getNormType() );

            assertEquals( "T+ST ", ava.getValue().getString() );
        }

        // ------------------------------------------------------------------
        // Now normalize the Dn
        new Dn( schemaManager, dn );

        assertEquals( "  OU  =  Ex\\+mple + cn = T\\+ST\\  ,  ou  =  COM ", dn.getName() );
        assertEquals( "cn=T\\+ST\\ +OU=Ex\\+mple,ou=COM", dn.getEscaped() );

        // Check the first Rdn
        rdn = dn.getRdn();
        assertEquals( "  OU  =  Ex\\+mple + cn = T\\+ST\\  ", rdn.getName() );
        assertEquals( "cn=T\\+ST\\ +OU=Ex\\+mple", rdn.getEscaped() );

        assertEquals( "cn", rdn.getType() );
        assertEquals( "cn", rdn.getNormType() );

        assertEquals( "T+ST ", rdn.getValue() );

        // The first ATAV
        atav = rdn.getAva();

        assertEquals( " cn = T\\+ST\\  ", atav.getName() );
        assertEquals( "cn=T\\+ST\\ ", atav.getEscaped() );

        assertEquals( "cn", atav.getNormType() );
        assertEquals( "cn", atav.getType() );

        assertEquals( "T+ST ", atav.getValue().getString() );

        assertEquals( 2, rdn.size() );

        // The second ATAV
        for ( Ava ava : rdn )
        {
            if ( "T+ST ".equals( ava.getValue().getString() ) )
            {
                // Skip the first one
                continue;
            }

            assertEquals( "  OU  =  Ex\\+mple ", ava.getName() );
            assertEquals( "OU=Ex\\+mple", ava.getEscaped() );

            assertEquals( "OU", ava.getType() );
            assertEquals( "ou", ava.getNormType() );

            assertEquals( "Ex+mple", ava.getValue().getString() );
        }
    }


    //-------------------------------------------------------------------------
    // test the iterator
    //-------------------------------------------------------------------------
    @Test
    public void testIteratorNullDN()
    {
        Dn dn = Dn.EMPTY_DN;

        for ( Rdn rdn : dn )
        {
            fail( "Should not be there: rdn = " + rdn );
        }

        assertTrue( true );
    }


    @Test
    public void testIteratorOneRDN() throws Exception
    {
        Dn dn = new Dn( "ou=example" );
        int count = 0;

        for ( Rdn rdn : dn )
        {
            count++;
            assertEquals( "ou=example", rdn.getName() );
        }

        assertEquals( 1, count );
    }


    @Test
    public void testIteratorMultipleRDN() throws Exception
    {
        Dn dn = new Dn( "sn=joe+cn=doe,dc=apache,dc=org" );
        int count = 0;

        String[] expected = new String[]
            { "sn=joe+cn=doe", "dc=apache", "dc=org" };

        for ( Rdn rdn : dn.getRdns() )
        {
            assertEquals( expected[count], rdn.getName() );
            count++;
        }

        assertEquals( 3, count );
    }


    @Test
    public void testIsParentOfTrue() throws Exception
    {
        Dn dn = new Dn( "ou=example, dc=apache, dc=org" );
        Dn parent1 = new Dn( "ou=example,dc=apache, dc=org" );
        Dn parent2 = new Dn( "dc=apache, dc=org" );
        Dn parent3 = new Dn( "dc=org" );
        Dn notParent = new Dn( "ou=example,dc=apache, dc=com" );

        assertTrue( parent1.isAncestorOf( dn ) );
        assertTrue( parent2.isAncestorOf( dn ) );
        assertTrue( parent3.isAncestorOf( dn ) );
        assertFalse( notParent.isAncestorOf( dn ) );
    }


    @Test
    public void testIsDescendantOfTrue() throws Exception
    {
        Dn dn = new Dn( "ou=example, dc=apache, dc=org" );
        Dn parent1 = new Dn( "ou=example,dc=apache, dc=org" );
        Dn parent2 = new Dn( "dc=apache, dc=org" );
        Dn parent3 = new Dn( "dc=org" );
        Dn notParent = new Dn( "dc=apache, dc=com" );

        assertTrue( dn.isDescendantOf( parent1 ) );
        assertTrue( dn.isDescendantOf( parent2 ) );
        assertTrue( dn.isDescendantOf( parent3 ) );
        assertFalse( notParent.isDescendantOf( dn ) );
    }


    @Test
    public void testNormalize() throws Exception
    {
        Dn dn = new Dn( "ou=system" );
        assertFalse( dn.isSchemaAware() );

        dn = dn.add( "ou=users" );
        assertFalse( dn.isSchemaAware() );

        dn = new Dn( schemaManager, dn );
        assertTrue( dn.isSchemaAware() );

        dn = dn.add( "ou=x" );
        assertTrue( dn.isSchemaAware() );

        assertEquals( "ou=x,ou=users,ou=system", dn.getEscaped() );
        assertEquals( "ou=x,ou=users,ou=system", dn.getName() );

        new Dn( schemaManager, dn );
        assertEquals( "ou=x,ou=users,ou=system", dn.getEscaped() );
        assertEquals( "ou=x,ou=users,ou=system", dn.getName() );

        Rdn rdn = new Rdn( "ou=system" );
        dn = new Dn();
        assertFalse( dn.isSchemaAware() );

        dn = dn.add( rdn );
        assertFalse( dn.isSchemaAware() );

        dn = new Dn( schemaManager, dn );
        assertTrue( dn.isSchemaAware() );

        Dn anotherDn = new Dn( "ou=x,ou=users" );

        dn = dn.add( anotherDn );
        assertTrue( dn.isSchemaAware() );

        new Dn( schemaManager, dn );
        assertTrue( dn.isSchemaAware() );
    }


    @Test
    public void testParseDnWithSlash() throws Exception
    {
        String dnStr = "dc=/vehicles/v1/";

        Dn dn = new Dn( dnStr );
        new Dn( schemaManager, dn );

        assertEquals( dnStr, dn.toString() );
    }


    @Test
    public void testCreateDnFromRdnParent() throws Exception
    {
        String rdn = "cn=test";
        String parentDn = "ou=apache,ou=org";

        Dn dn = new Dn( rdn, parentDn );

        assertEquals( "cn=test,ou=apache,ou=org", dn.getName() );
    }
    
    
    @Test
    public void testRdnStudio() throws LdapInvalidDnException
    {
        new Dn( schemaManager, "cn=\\#\\\\\\+\\, \\\"\u00f6\u00e9\\\",ou=users,ou=system" );
    }

    
    @Test
    public void testSameAttributeInDn() throws LdapInvalidDnException
    {
        new Dn( "l=eu + l=de + l=Berlin + l=Brandenburger Tor,dc=example,dc=org" );
    }

    
    @Test
    @Disabled
    public void testDnParsingPerf() throws LdapInvalidDnException
    {
        long[] deltas = new long[10];
        long allDeltas = 0L;
        
        for ( int j = 0; j < 10; j++ )
        {
            long t0 = System.currentTimeMillis();
            
            for ( int i = 0; i < 10000000; i++ )
            {
                new Dn( schemaManager, "dc=example" + i );
            }
            
            long t1 = System.currentTimeMillis();
            
            deltas[j] = t1 - t0;
            System.out.println( "Iteration[" + j + "] : " + deltas[j] );
        }
        
        
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
                new Dn( schemaManager, "dc=example" + i + ",dc=com" );
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
                new Dn( schemaManager, "uid=" + i + ",dc=example,dc=com" );
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
                new Dn( schemaManager, "uid=" + i + ",ou=people,dc=example,dc=com" );
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


    /**
     * test a simple Dn with hexString attribute value, schema aware
     *
     * @throws LdapException if anything goes wrong.
     */
    @Test
    public void testDnHexStringAttributeValueDSchemaAware() throws LdapException
    {
        Dn dn = new Dn( schemaManager, "uid = #4869" );

        assertTrue( Dn.isValid( "uid = #4869" ) );
        assertEquals( "uid=Hi", dn.getEscaped() );
        assertEquals( "uid = #4869", dn.getName() );
        assertEquals( "0.9.2342.19200300.100.1.1= hi ", dn.getNormName() );
        
        // Now, create a new DN, not schema aware
        Dn dn2 = new Dn( "UID = #4869" );
        assertEquals( "UID=Hi", dn2.getEscaped() );
        assertEquals( "UID = #4869", dn2.getName() );
        assertEquals( "uid=Hi", dn2.getNormName() );
        
        // Make it schemaAware
        Dn dn3 = new Dn( schemaManager, dn2 );
        assertEquals( "UID=Hi", dn3.getEscaped() );
        assertEquals( "UID = #4869", dn3.getName() );
        assertEquals( "0.9.2342.19200300.100.1.1= hi ", dn3.getNormName() );
    }
    
    @Test
    public void ancestorCheck() throws LdapInvalidDnException
    {
        DefaultSchemaManager schemaManager = new DefaultSchemaManager();
        Dn group = new Dn( schemaManager, "ou=group,ou=base" );
        Dn base = new Dn( schemaManager, "ou=base" );

        Dn ancestor = group.getAncestorOf( "ou=group" );
        assertEquals( ancestor, base );
    }
}
