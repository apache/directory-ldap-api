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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Iterator;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the Schema aware Rdn class
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class SchemaAwareRdnTest
{
    /** A null schemaManager used in tests */
    private static SchemaManager schemaManager;


    @BeforeAll
    public static void setup() throws Exception
    {
        schemaManager = new DefaultSchemaManager();
    }


    /**
     * Test a null Rdn
     */
    @Test
    public void testRdnNull()
    {
        assertEquals( "", new Rdn( schemaManager ).toString() );
    }


    /**
     * test an empty Rdn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnEmpty() throws LdapException
    {
        assertEquals( "", new Rdn( schemaManager, "" ).toString() );
    }


    /**
     * test a simple Rdn : cn = b
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnSimple() throws LdapException
    {
        assertEquals( "cn=b", new Rdn( schemaManager, "cn = b" ).getEscaped() );
    }


    /**
     * test a composite Rdn : cn = b, sn = e
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnComposite() throws LdapException
    {
        assertEquals( "cn=b+sn=d", new Rdn( schemaManager, "cn = b + sn = d" ).getEscaped() );
    }


    /**
     * test a composite Rdn with or without spaces: cn=b, cn =b, cn= b, cn = b, cn =
     * b
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnCompositeWithSpace() throws LdapException
    {
        assertEquals( "cn=b", new Rdn( schemaManager, "cn=b" ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, " cn=b" ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, "cn =b" ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, "cn= b" ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, "cn=b " ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, " cn =b" ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, " cn= b" ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, " cn=b " ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, "cn = b" ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, "cn =b " ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, "cn= b " ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, " cn = b" ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, " cn =b " ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, " cn= b " ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, "cn = b " ).getEscaped() );
        assertEquals( "cn=b", new Rdn( schemaManager, " cn = b " ).getEscaped() );
    }


    /**
     * test a simple Rdn with differents separators : cn = b + sn = d
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnSimpleMultivaluedAttribute() throws LdapException
    {
        String result = new Rdn( schemaManager, "cn = b + sn = d" ).getEscaped();
        assertEquals( "cn=b+sn=d", result );
    }


    /**
     * test a composite Rdn with differents separators : cn=b+sn=d, gn=f + l=h +
     * c=j
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnCompositeMultivaluedAttribute() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, "cn =b+sn=d + gn=f + l  =h + c =j " );

        // NameComponent are not ordered
        assertEquals( "b", rdn.getValue( "CommonName" ) );
        assertEquals( "d", rdn.getValue( "2.5.4.4" ) );
        assertEquals( "f", rdn.getValue( "  gn  " ) );
        assertEquals( "h", rdn.getValue( "L" ) );
        assertEquals( "j", rdn.getValue( "c" ) );
    }


    /**
     * test a simple Rdn with an oid prefix (uppercase) : OID.2.5.4.3 = azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnOidUpper() throws LdapException
    {
        assertEquals( "2.5.4.3=azerty", new Rdn( schemaManager, "OID.2.5.4.3 =  azerty" ).getEscaped() );
    }


    /**
     * test a simple Rdn with an oid prefix (lowercase) : oid.12.34.56 = azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnOidLower() throws LdapException
    {
        assertTrue( new Rdn( schemaManager, "oid.2.5.4.3 = azerty" ).equals( "2.5.4.3=azerty" ) );
    }


    /**
     * test a simple Rdn with an oid attribut wiithout oid prefix : 2.5.4.3 =
     * azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnOidWithoutPrefix() throws LdapException
    {
        assertEquals( "2.5.4.3=azerty", new Rdn( schemaManager, "2.5.4.3 = azerty" ).getEscaped() );
    }


    /**
     * test a composite Rdn with an oid attribut wiithout oid prefix : 2.5.4.3 =
     * azerty; 2.5.4.4 = test
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnCompositeOidWithoutPrefix() throws LdapException
    {
        String result = new Rdn( schemaManager, "2.5.4.3 = azerty + 2.5.4.4 = test" ).getEscaped();
        assertEquals( "2.5.4.3=azerty+2.5.4.4=test", result );
    }


    /**
     * test a simple Rdn with pair char attribute value : l = \,\=\+\&lt;\&gt;\#\;\\\"\C3\A9"
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnPairCharAttributeValue() throws LdapException
    {
        String rdn = Strings.utf8ToString( new byte[]
            {
                'l',
                '=',
                '\\',
                ',',
                '\\',
                '=',
                '\\',
                '+',
                '\\',
                '<',
                '\\',
                '>',
                '#',
                '\\',
                ';',
                '\\',
                '\\',
                '\\',
                '"',
                '\\',
                'C',
                '3',
                '\\',
                'A',
                '9' } );
        assertEquals( "l=\\,=\\+\\<\\>#\\;\\\\\\\"\u00e9", new Rdn( schemaManager, rdn ).getEscaped() );
    }


    /**
     * test a simple Rdn with hexString attribute value : userCertificate = #0010A0AAFF
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnHexStringAttributeValue() throws LdapException
    {
        assertEquals( "userCertificate=\\00\u0010\\A0\\AA\\FF", new Rdn( schemaManager, "userCertificate = #0010A0AAFF" ).getEscaped() );
    }


    /**
     * test exception from illegal hexString attribute value : cn=#zz.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testBadRdnHexStringAttributeValue() throws LdapException
    {
        try
        {
            new Rdn( schemaManager, "cn=#zz" );
            fail();
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }
    }


    /**
     * test a simple Rdn with quoted attribute value : cn = "quoted \"value"
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnQuotedAttributeValue() throws LdapException
    {
        assertEquals( "cn=quoted \\\"value", new Rdn( schemaManager, "cn = quoted \\\"value" ).getEscaped() );
    }


    /**
     * Test the clone method for a Rdn.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCloningOneNameComponent() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, "CN", "B" );

        Rdn rdnClone = rdn.clone();

        rdn = new Rdn( schemaManager, "cn=d" );

        assertEquals( "B", rdnClone.getValue( "Cn" ) );
    }


    /**
     * Test the creation of a new Rdn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCreation() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, "CN", "  b  " );
        assertEquals( "CN=\\  b \\ ", rdn.getEscaped() );
        assertEquals( "CN=  b  ", rdn.getName() );
    }


    /**
     * Test the clone method for a Rdn.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCloningTwoNameComponent() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, "cn = b + sn = bb" );

        Rdn rdnClone = rdn.clone();

        rdn.clear();
        rdn = new Rdn( schemaManager, "l=d" );

        assertEquals( "b", rdnClone.getValue( "2.5.4.3" ) );
        assertEquals( "bb", rdnClone.getValue( "SN" ) );
        assertNull( rdnClone.getValue( "l" ) );
    }


    /**
     * Test the equals method for a Rdn.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCompareToNull() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = b + sn = d + l = f + gn = h " );
        Rdn rdn2 = null;
        assertFalse( rdn1.equals( rdn2 ) );
    }


    /**
     * Compares a composite NC to a single NC.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCompareToNCS2NC() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = b + sn = d + l = f + gn = h " );
        Rdn rdn2 = new Rdn( schemaManager, " cn = b " );
        assertFalse( rdn1.equals( rdn2 ) );
    }


    /**
     * Compares a single NC to a composite NC.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCompareToNC2NCS() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " sn = b " );
        Rdn rdn2 = new Rdn( schemaManager, " cn = b + sn = d + l = f + gn = h " );

        assertFalse( rdn1.equals( rdn2 ) );
    }


    /**
     * Compares a composite NCS to a composite NCS in the same order.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCompareToNCS2NCSOrdered() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = b + sn = d + gn = f + l = h " );
        Rdn rdn2 = new Rdn( schemaManager, " cn = b + sn = d + gn = f + l = h " );

        assertTrue( rdn1.equals( rdn2 ) );
    }


    /**
     * Compares a composite NCS to a composite NCS in a different order.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCompareToNCS2NCSUnordered() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = b + gn = f + l = h + sn = d " );
        Rdn rdn2 = new Rdn( schemaManager, " cn = b + sn = d + gn = f + l = h " );

        assertTrue( rdn1.equals( rdn2 ) );
    }


    /**
     * Compares a composite NCS to a different composite NCS.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCompareToNCS2NCSNotEquals() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = f + sn = h + l = d " );
        Rdn rdn2 = new Rdn( schemaManager, " l = d + cn = h + sn = h " );

        assertFalse( rdn1.equals( rdn2 ) );
        assertFalse( rdn2.equals( rdn1 ) );
    }


    /**
     * Test for DIRSHARED-2.
     * The first ATAV is equal, the second or following ATAV differs.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testCompareSecondAtav() throws LdapException
    {
        // the second ATAV differs
        Rdn rdn1 = new Rdn( schemaManager, " cn = b + sn = d " );
        Rdn rdn2 = new Rdn( schemaManager, " cn = b + sn = y " );
        assertFalse( rdn1.equals( rdn2 ) );
        assertFalse( rdn2.equals( rdn1 ) );

        // the third ATAV differs
        Rdn rdn3 = new Rdn( schemaManager, " cn = b + sn = d + l = f " );
        Rdn rdn4 = new Rdn( schemaManager, " cn = b + sn = d + l = y " );
        assertFalse( rdn3.equals( rdn4 ) );
        assertFalse( rdn4.equals( rdn3 ) );

        // the second ATAV differs in value only
        Rdn rdn5 = new Rdn( schemaManager, " cn = b + sn = c " );
        Rdn rdn6 = new Rdn( schemaManager, " cn = b + sn = y " );
        assertFalse( rdn5.equals( rdn6 ) );
        assertFalse( rdn6.equals( rdn5 ) );
    }


    /**
     * Test for DIRSHARED-2.
     * The compare operation should return a correct value (1 or -1)
     * depending on the ATAVs, not on their position.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testCompareIndependentFromOrder() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = b + sn = d " );
        Rdn rdn2 = new Rdn( schemaManager, " sn = d + cn = b " );
        assertTrue( rdn1.equals( rdn2 ) );

        rdn1 = new Rdn( schemaManager, " cn = b + sn = e " );
        rdn2 = new Rdn( schemaManager, " sn = d + cn = b " );
        assertFalse( rdn1.equals( rdn2 ) );
        assertFalse( rdn2.equals( rdn1 ) );

        rdn1 = new Rdn( schemaManager, " cn = b + sn = d " );
        rdn2 = new Rdn( schemaManager, " l = f + gn = h " );
        assertFalse( rdn1.equals( rdn2 ) );
        assertFalse( rdn2.equals( rdn1 ) );
    }


    /**
     * Test for DIRSHARED-3.
     * Tests that equals() is invertable for single-valued RDNs.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testCompareInvertableNC2NC() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = b " );
        Rdn rdn2 = new Rdn( schemaManager, " cn = c " );
        assertFalse( rdn1.equals( rdn2 ) );
        assertFalse( rdn2.equals( rdn1 ) );

    }


    /**
     * Test for DIRSHARED-3.
     * Tests that equals() is invertable for multi-valued RDNs with different values.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testCompareInvertableNCS2NCSDifferentValues() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = b + sn = c " );
        Rdn rdn2 = new Rdn( schemaManager, " cn = b + sn = y " );
        assertFalse( rdn1.equals( rdn2 ) );
        assertFalse( rdn2.equals( rdn1 ) );
    }


    /**
     * Test for DIRSHARED-3.
     * Tests that equals() is invertable for multi-valued RDNs with different types.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testCompareInvertableNCS2NCSDifferentTypes() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = b + sn = d  " );
        Rdn rdn2 = new Rdn( schemaManager, " l = f + gn = h " );
        assertFalse( rdn1.equals( rdn2 ) );
        assertFalse( rdn2.equals( rdn1 ) );
    }


    /**
     * Test for DIRSHARED-3.
     * Tests that equals() is invertable for multi-valued RDNs with different order.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testCompareInvertableNCS2NCSUnordered() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " sn = d + cn = b " );
        Rdn rdn2 = new Rdn( schemaManager, " cn = b + l = f " );
        assertFalse( rdn1.equals( rdn2 ) );
        assertFalse( rdn2.equals( rdn1 ) );
    }


    /**
     * Compares with a null Rdn.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCompareToNullRdn() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = b " );

        assertFalse( rdn1.equals( null ) );
    }


    /**
     * Compares a simple NC to a simple NC.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCompareToNC2NC() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = b " );
        Rdn rdn2 = new Rdn( schemaManager, " cn = b " );

        assertTrue( rdn1.equals( rdn2 ) );
    }


    /**
     * Compares a simple NC to a simple NC in UperCase.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCompareToNC2NCUperCase() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = b " );
        Rdn rdn2 = new Rdn( schemaManager, " CN = b " );

        assertTrue( rdn1.equals( rdn2 ) );
    }


    /**
     * Compares a simple NC to a different simple NC.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCompareToNC2NCNotEquals() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = b " );
        Rdn rdn2 = new Rdn( schemaManager, " CN = d " );

        assertFalse( rdn1.equals( rdn2 ) );
    }


    /**
     * 
     * Test the getValue method.
     *
     * @throws LdapException If the test failed
     */
    @Test
    public void testGetValue() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, " cn = b + sn = f + gn = h + l = d " );

        assertEquals( "b", rdn.getValue() );
    }


    /**
     * 
     * Test the getType method.
     *
     * @throws LdapException If the test failed
     */
    @Test
    public void testGetType() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, " cn = b + sn = f + gn = h + l = d " );

        assertEquals( "2.5.4.3", rdn.getNormType() );
    }


    /**
     * Test the getSize method.
     *
     * @throws LdapException If the test failed
     */
    @Test
    public void testGetSize() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, " cn = b + sn = f + gn = h + l = d " );

        assertEquals( 4, rdn.size() );
    }


    /**
     * Test the getSize method.
     *
     */
    @Test
    public void testGetSize0()
    {
        Rdn rdn = new Rdn( schemaManager );

        assertEquals( 0, rdn.size() );
    }


    /**
     * Test the equals method
     *
     * @throws LdapException If the test failed
     */
    @Test
    public void testEquals() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, "cn=b + sn=d + gn=f" );

        assertFalse( rdn.equals( null ) );
        assertFalse( rdn.equals( "test" ) );
        assertFalse( rdn.equals( new Rdn( schemaManager, "cn=c + sn=d + gn=f" ) ) );
        assertFalse( rdn.equals( new Rdn( schemaManager, "cn=b" ) ) );
        assertTrue( rdn.equals( new Rdn( schemaManager, "cn=b + sn=d + gn=f" ) ) );
        assertTrue( rdn.equals( new Rdn( schemaManager, "cn=b + SN=d + GN=f" ) ) );
        assertTrue( rdn.equals( new Rdn( schemaManager, "sn=d + gn=f + CN=b" ) ) );
    }


    @Test
    public void testUnescapeValueHexa()
    {
        byte[] res = ( byte[] ) Rdn.unescapeValue( "#fF" );

        assertEquals( "0xFF ", Strings.dumpBytes( res ) );

        res = ( byte[] ) Rdn.unescapeValue( "#0123456789aBCDEF" );
        assertEquals( "0x01 0x23 0x45 0x67 0x89 0xAB 0xCD 0xEF ", Strings.dumpBytes( res ) );
    }


    @Test
    public void testUnescapeValueHexaWrong()
    {
        try
        {
            Rdn.unescapeValue( "#fF1" );
            fail(); // Should not happen
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }
    }


    @Test
    public void testUnescapeValueString()
    {
        String res = ( String ) Rdn.unescapeValue( "azerty" );

        assertEquals( "azerty", res );
    }


    @Test
    public void testUnescapeValueStringSpecial()
    {
        String res = ( String ) Rdn.unescapeValue( "\\\\\\#\\,\\+\\;\\<\\>\\=\\\"\\ " );

        assertEquals( "\\#,+;<>=\" ", res );
    }


    @Test
    public void testUnescapeValueStringWithSpaceInTheMiddle()
    {
        String res = ( String ) Rdn.unescapeValue( "a b" );

        assertEquals( "a b", res );
    }


    @Test
    public void testUnescapeValueStringWithSpaceInAtTheBeginning()
    {
        String res = ( String ) Rdn.unescapeValue( "\\ a b" );

        assertEquals( " a b", res );
    }


    @Test
    public void testUnescapeValueStringWithSpaceInAtTheEnd()
    {
        String res = ( String ) Rdn.unescapeValue( "a b\\ " );

        assertEquals( "a b ", res );
    }


    @Test
    public void testUnescapeValueStringWithPoundInTheMiddle()
    {
        String res = ( String ) Rdn.unescapeValue( "a#b" );

        assertEquals( "a#b", res );
    }


    @Test
    public void testUnescapeValueStringWithPoundAtTheEnd()
    {
        String res = ( String ) Rdn.unescapeValue( "ab#" );

        assertEquals( "ab#", res );
    }


    @Test
    public void testEscapeValueString()
    {
        String res = Rdn.escapeValue( Strings.getBytesUtf8( "azerty" ) );

        assertEquals( "azerty", res );
    }


    @Test
    public void testEscapeValueStringSpecial()
    {
        String res = Rdn.escapeValue( Strings.getBytesUtf8( "\\#,+;<>=\" " ) );

        assertEquals( "\\\\#\\,\\+\\;\\<\\>\\=\\\"\\ ", res );
    }


    @Test
    public void testEscapeValueNumeric()
    {
        String res = Rdn.escapeValue( new byte[]
            { '-', 0x00, '-', 0x1F, '-', 0x7F, '-' } );

        assertEquals( "-\\00-\\1F-\\7F-", res );
    }


    @Test
    public void testEscapeValueMix()
    {
        String res = Rdn.escapeValue( new byte[]
            { '\\', 0x00, '-', '+', '#', 0x7F, '-' } );

        assertEquals( "\\\\\\00-\\+#\\7F-", res );
    }


    @Test
    public void testDIRSERVER_703() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, "cn=Kate Bush+sn=Bush" );
        assertEquals( "cn=Kate Bush+sn=Bush", rdn.getName() );
    }


    @Test
    public void testMultiValuedIterator() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, "cn=Kate Bush+sn=Bush" );
        Iterator<Ava> iterator = rdn.iterator();
        assertNotNull( iterator );
        assertTrue( iterator.hasNext() );
        assertNotNull( iterator.next() );
        assertTrue( iterator.hasNext() );
        assertNotNull( iterator.next() );
        assertFalse( iterator.hasNext() );
    }


    @Test
    public void testSingleValuedIterator() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, "cn=Kate Bush" );
        Iterator<Ava> iterator = rdn.iterator();
        assertNotNull( iterator );
        assertTrue( iterator.hasNext() );
        assertNotNull( iterator.next() );
        assertFalse( iterator.hasNext() );
    }


    @Test
    public void testEmptyIterator()
    {
        Rdn rdn = new Rdn( schemaManager );
        Iterator<Ava> iterator = rdn.iterator();
        assertNotNull( iterator );
        assertFalse( iterator.hasNext() );
    }


    @Test
    public void testRdnWithSpaces() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, "cn=a\\ b\\ c" );
        assertEquals( "cn=a b c", rdn.getEscaped() );
    }
    
    /*
    @Test
        public void testEscapedSpaceInValue() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, "cn=a b c" );
        Rdn rdn2 = new Rdn( schemaManager, "cn=a\\ b\\ c" );
        assertEquals( "2.5.4.3=a b c", rdn1.getEscaped() );
        assertEquals( "2.5.4.3=a b c", rdn2.getEscaped() );
        assertTrue( rdn1.equals( rdn2 ) );

        Rdn rdn3 = new Rdn( schemaManager, "cn=\\ a b c\\ " );
        Rdn rdn4 = new Rdn( schemaManager, "cn=\\ a\\ b\\ c\\ " );
        assertEquals( "2.5.4.3= a b c ", rdn3.getEscaped() );
        assertEquals( "cn=\\ a b c\\ ", rdn3.getName() );
        assertEquals( "2.5.4.3=\\ a b c\\ ", rdn4.getEscaped() );
        assertEquals( "cn=\\ a\\ b\\ c\\ ", rdn4.getName() );
        assertTrue( rdn3.equals( rdn4 ) );
    }
    */
    
    /*
    public void testEscapedSpaceInValue2() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, "cn=\\ a\\ " );

        assertEquals( "cn=\\ a\\ ", rdn.getName() );
        assertEquals( "2.5.4.3=\\ a\\ ", rdn.getEscaped() );
    }
    */


    @Test
    public void testEscapedSpaceInValue() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, "cn=a b c" );
        assertEquals( "cn=a b c", rdn1.getEscaped() );

        Rdn rdn2 = new Rdn( schemaManager, "cn=a\\ b\\ c" );
        assertEquals( "cn=a b c", rdn2.getEscaped() );
        
        assertTrue( rdn1.equals( rdn2 ) );

        Rdn rdn3 = new Rdn( schemaManager, "cn=\\ a b c\\ " );
        assertEquals( "cn=\\ a b c\\ ", rdn3.getEscaped() );
        assertEquals( "cn=\\ a b c\\ ", rdn3.getName() );

        Rdn rdn4 = new Rdn( schemaManager, "cn=\\ a\\ b\\ c\\ " );
        assertEquals( "cn=\\ a b c\\ ", rdn4.getEscaped() );
        assertEquals( "cn=\\ a\\ b\\ c\\ ", rdn4.getName() );
        assertTrue( rdn3.equals( rdn4 ) );
    }


    /**
     * attributeValue = string / hexstring
     * string =   [ ( leadchar / pair ) [ *( stringchar / pair )
     *   ( trailchar / pair ) ] ]
     * leadchar = LUTF1 / UTFMB
     * pair = ESC ( ESC / special / hexpair )
     * special = escaped / SPACE / SHARP / EQUALS
     * 
     * --&gt; replace &lt;ESC&gt;&lt;special&gt; with &lt;special&gt;
     * 
     * '\#' will be replaced by '#'
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testEscapedHashInValue2() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, "cn=a\\#b" );
        assertEquals( "cn=a#b", rdn.getEscaped() );
        assertEquals( "cn=a\\#b", rdn.getName() );
        
        // Check the AVA
        assertEquals( "cn=a#b", rdn.getAva().getEscaped() );
        assertEquals( "cn=a\\#b", rdn.getAva().getName() );
        
        // Check the value
        assertEquals( "a#b", rdn.getAva().getValue().getString() );
    }


    @Test
    public void testEscapedHashInValue() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, "cn=a#b#c" );
        Rdn rdn2 = new Rdn( schemaManager, "cn=a\\#b\\#c" );
        assertEquals( "cn=a#b#c", rdn1.getEscaped() );
        assertEquals( "cn=a#b#c", rdn2.getEscaped() );
        assertTrue( rdn1.equals( rdn2 ) );

        Rdn rdn3 = new Rdn( schemaManager, "cn=\\#a#b#c\\#" );
        Rdn rdn4 = new Rdn( schemaManager, "cn=\\#a\\#b\\#c\\#" );
        assertEquals( "cn=\\#a#b#c#", rdn3.getEscaped() );
        assertEquals( "cn=\\#a#b#c#", rdn4.getEscaped() );
        assertTrue( rdn3.equals( rdn4 ) );
    }


    @Test
    public void testEscapedAttributeValue()
    {
        // space doesn't need to be escaped in the middle of a string
        assertEquals( "a b", Rdn.escapeValue( "a b" ) );
        assertEquals( "\u00e4 b c", Rdn.escapeValue( "\u00e4 b c" ) );
        assertEquals( "a b c d", Rdn.escapeValue( "a b c d" ) );

        // space must be escaped at the beginning and the end of a string
        assertEquals( "\\ a b", Rdn.escapeValue( " a b" ) );
        assertEquals( "a b\\ ", Rdn.escapeValue( "a b " ) );
        assertEquals( "\\ a b\\ ", Rdn.escapeValue( " a b " ) );
        assertEquals( "\\  a  b \\ ", Rdn.escapeValue( "  a  b  " ) );

        // hash doesn't need to be escaped in the middle and the end of a string
        assertEquals( "a#b", Rdn.escapeValue( "a#b" ) );
        assertEquals( "a#b#", Rdn.escapeValue( "a#b#" ) );
        assertEquals( "a#b#c", Rdn.escapeValue( "a#b#c" ) );
        assertEquals( "a#b#c#", Rdn.escapeValue( "a#b#c#" ) );
        assertEquals( "a#b#c#d", Rdn.escapeValue( "a#b#c#d" ) );
        assertEquals( "a#b#c#d#", Rdn.escapeValue( "a#b#c#d#" ) );

        // hash must be escaped at the beginning of a string
        assertEquals( "\\#a#b", Rdn.escapeValue( "#a#b" ) );
        assertEquals( "\\##a#b", Rdn.escapeValue( "##a#b" ) );

        // other characters that need to be escaped
        // '"', '+', ',', ';', '<', '>', '\', the null (U+0000) character
        assertEquals( "\\\"\\+\\,\\;\\<\\>\\\\\\00", Rdn.escapeValue( "\"+,;<>\\\u0000" ) );

        // unicode characters don't need to be escaped
        // \u00e9 - e with acute - 2 bytes in UTF-8
        // \u20ac - Euro character - 3 bytes in UTF-8
        // \uD83D\uDE08 - Smiley - 4 bytes in UTF-8
        assertEquals( "\u00e9\u20AC\uD83D\uDE08", Rdn.escapeValue( "\u00e9\u20AC\uD83D\uDE08" ) );
    }


    /** Serialization tests ------------------------------------------------- */

    /**
     * Test serialization of an empty Rdn
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testEmptyRDNSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( schemaManager, "" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        out.writeObject( rdn );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = ( Rdn ) in.readObject();

        assertEquals( rdn, rdn2 );
    }


    @Test
    public void testNullRdnSerialization() throws IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( schemaManager );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        out.writeObject( rdn );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = ( Rdn ) in.readObject();

        assertEquals( rdn, rdn2 );
    }


    /**
     * Test serialization of a simple Rdn
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSimpleRdnSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( schemaManager, "cn=b" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn( schemaManager );
        rdn2.readExternal( in );

        assertEquals( rdn, rdn2 );
    }


    /**
     * Test serialization of a simple Rdn
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSimpleRdn2Serialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( schemaManager, " CN  = DEF " );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn( schemaManager );
        rdn2.readExternal( in );

        assertEquals( rdn, rdn2 );
    }


    /**
     * Test serialization of a simple Rdn with no value
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSimpleRdnNoValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( schemaManager, " DC  =" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn( schemaManager );
        rdn2.readExternal( in );

        assertEquals( rdn, rdn2 );
    }


    /**
     * Test serialization of a simple Rdn with one value
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSimpleRdnOneValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( schemaManager, " CN  = def " );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn( schemaManager );
        rdn2.readExternal( in );

        assertEquals( rdn, rdn2 );
    }


    /**
     * Test serialization of a simple Rdn with three values
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSimpleRdnThreeValuesSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( schemaManager, " CN = a + SN = b + GN = c " );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn( schemaManager );
        rdn2.readExternal( in );

        assertEquals( rdn, rdn2 );
    }


    /**
     * Test serialization of a simple Rdn with three unordered values
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSimpleRdnThreeValuesUnorderedSerialization() throws LdapException, IOException,
        ClassNotFoundException
    {
        Rdn rdn = new Rdn( schemaManager, " CN = b + SN = a + GN = c " );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn( schemaManager );
        rdn2.readExternal( in );

        assertEquals( rdn, rdn2 );
    }


    /**
     * test an Rdn with empty value
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnWithEmptyValue() throws LdapException
    {
        assertTrue( Rdn.isValid( "dc=" ) );
        assertTrue( Rdn.isValid( "dc=\"\"" ) );
        assertEquals( "dc=", new Rdn( schemaManager, "dc=" ).getEscaped() );
        assertEquals( "dc=", new Rdn( schemaManager, "dc=\"\"" ).getEscaped() );
    }


    /**
     * test an Rdn with escaped comma
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnWithEscapedComa() throws LdapException
    {
        assertTrue( Rdn.isValid( "cn=b\\,c" ) );
        assertEquals( "cn=b\\,c", new Rdn( schemaManager, "cn=b\\,c" ).getEscaped() );

        assertTrue( Rdn.isValid( "cn=\"b,c\"" ) );
        assertEquals( "cn=b\\,c", new Rdn( schemaManager, "cn=\"b,c\"" ).getEscaped() );
        assertEquals( "cn=\"b,c\"", new Rdn( schemaManager, "cn=\"b,c\"" ).getName() );

        assertTrue( Rdn.isValid( "cn=\"b\\,c\"" ) );
        Rdn rdn = new Rdn( schemaManager, "cn=\"b\\,c\"" );
        assertEquals( "cn=\"b\\,c\"", rdn.getName() );
        assertEquals( "cn=b\\,c", rdn.getEscaped() );
    }


    /**
     * Tests the equals and equals results of cloned multi-valued RDNs.
     * Test for DIRSHARED-9.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testComparingOfClonedMultiValuedRDNs() throws LdapException
    {
        // Use upper case attribute types to test if normalized types are used
        // for comparison
        Rdn rdn = new Rdn( schemaManager, " CN = b + SN = d" );
        Rdn clonedRdn = rdn.clone();

        assertTrue( rdn.equals( clonedRdn ) );
    }


    /**
     * Tests the equals and equals results of copy constructed multi-valued RDNs.
     * Test for DIRSHARED-9.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testComparingOfCopyConstructedMultiValuedRDNs() throws LdapException
    {
        // Use upper case attribute types to test if normalized types are used
        // for comparison
        Rdn rdn = new Rdn( schemaManager, " CN = b + SN = d" );
        Rdn copiedRdn = new Rdn( rdn );

        assertTrue( rdn.equals( copiedRdn ) );
    }


    /**
     * test the UpName method on a Rdn with more than one atav
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testGetUpNameMultipleAtav() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, " CN = b + SN = d " );

        assertEquals( " CN = b + SN = d ", rdn.getName() );
    }


    @Test
    public void testSchemaAware() throws LdapException
    {
        Rdn rdn = new Rdn( "cn=John" );

        assertFalse( rdn.isSchemaAware() );

        rdn = new Rdn( schemaManager, rdn );

        assertTrue( rdn.isSchemaAware() );
    }
}
