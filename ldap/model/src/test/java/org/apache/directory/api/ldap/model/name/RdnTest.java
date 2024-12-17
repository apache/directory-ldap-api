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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Iterator;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Test the class Rdn
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class RdnTest
{
    /** A null schemaManager used in tests */
    SchemaManager schemaManager = null;


    /**
     * Test a null Rdn
     */
    @Test
    public void testRdnNull()
    {
        assertEquals( "", new Rdn().toString() );
    }


    /**
     * test an empty Rdn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnEmpty() throws LdapException
    {
        assertEquals( "", new Rdn( "" ).toString() );
    }


    /**
     * test a simple Rdn : a = b
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnSimple() throws LdapException
    {
        assertEquals( "a = b", new Rdn( "a = b" ).getName() );
    }


    /**
     * test a composite Rdn : a = b, d = e
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnComposite() throws LdapException
    {
        assertEquals( "a = b + c = d", new Rdn( "a = b + c = d" ).getName() );
    }


    /**
     * test a composite Rdn with or without spaces: a=b, a =b, a= b, a = b, a =
     * b
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnCompositeWithSpace() throws LdapException
    {
        assertEquals( "a=b", new Rdn( "a", "b" ).getName() );
        assertEquals( " a=b", new Rdn( " a", "b" ).getName() );
        assertEquals( "a =b", new Rdn( "a ", "b" ).getName() );
        assertEquals( "a= b", new Rdn( "a", " b" ).getName() );
        assertEquals( "a=b ", new Rdn( "a", "b " ).getName() );
        assertEquals( " a =b", new Rdn( " a ", "b" ).getName() );
        assertEquals( " a= b", new Rdn( " a", " b" ).getName() );
        assertEquals( " a=b ", new Rdn( " a", "b " ).getName() );
        assertEquals( "a = b", new Rdn( "a ", " b" ).getName() );
        assertEquals( "a =b ", new Rdn( "a ", "b " ).getName() );
        assertEquals( "a= b ", new Rdn( "a", " b " ).getName() );
        assertEquals( " a = b", new Rdn( " a ", " b" ).getName() );
        assertEquals( " a =b ", new Rdn( " a ", "b " ).getName() );
        assertEquals( " a= b ", new Rdn( " a", " b " ).getName() );
        assertEquals( "a = b ", new Rdn( "a ", " b " ).getName() );
        assertEquals( " a = b ", new Rdn( " a ", " b " ).getName() );
    }


    /**
     * test a simple Rdn with differents separators : a = b + c = d
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnSimpleMultivaluedAttribute() throws LdapException
    {
        String result = new Rdn( "a = b + c = d" ).getName();
        assertEquals( "a = b + c = d", result );
    }


    /**
     * test a composite Rdn with differents separators : a=b+c=d, e=f + g=h +
     * i=j
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnCompositeMultivaluedAttribute() throws LdapException
    {
        Rdn rdn = new Rdn( "a =b+c=d + e=f + g  =h + i =j " );

        // NameComponent are not ordered
        assertEquals( "b", rdn.getValue( "a" ) );
        assertEquals( "d", rdn.getValue( "c" ) );
        assertEquals( "f", rdn.getValue( "  E  " ) );
        assertEquals( "h", rdn.getValue( "g" ) );
        assertEquals( "j", rdn.getValue( "i" ) );
    }


    /**
     * test a simple Rdn with an oid prefix (uppercase) : OID.12.34.56 = azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnOidUpper() throws LdapException
    {
        assertEquals( "OID.12.34.56 =  azerty", new Rdn( "OID.12.34.56 =  azerty" ).getName() );
    }


    /**
     * test a simple Rdn with an oid prefix (lowercase) : oid.12.34.56 = azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnOidLower() throws LdapException
    {
        assertEquals( "oid.12.34.56 = azerty", new Rdn( "oid.12.34.56 = azerty" ).getName() );
    }


    /**
     * test a simple Rdn with an oid attribut wiithout oid prefix : 12.34.56 =
     * azerty
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnOidWithoutPrefix() throws LdapException
    {
        assertEquals( "12.34.56 = azerty", new Rdn( "12.34.56 = azerty" ).getName() );
    }


    /**
     * test a composite Rdn with an oid attribut wiithout oid prefix : 12.34.56 =
     * azerty; 7.8 = test
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnCompositeOidWithoutPrefix() throws LdapException
    {
        String result = new Rdn( "12.34.56 = azerty + 7.8 = test" ).getName();
        assertEquals( "12.34.56 = azerty + 7.8 = test", result );
    }


    /**
     * test a simple Rdn with pair char attribute value : a = \,\=\+\&lt;\&gt;\#\;\\\"\C3\A9"
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnPairCharAttributeValue() throws LdapException
    {
        String rdn = Strings.utf8ToString( new byte[]
            { 'a', '=', '\\', ',', '\\', '=', '\\', '+', '\\', '<', '\\', '>', '#', '\\', ';', '\\', '\\', '\\', '"', '\\',
                'C', '3', '\\', 'A', '9' } );
        assertEquals( "a=\\,\\=\\+\\<\\>#\\;\\\\\\\"\\C3\\A9", new Rdn( rdn ).getName() );
        assertEquals( "a=\\,=\\+\\<\\>#\\;\\\\\\\"\u00e9", new Rdn( rdn ).getEscaped() );
    }


    /**
     * test a simple Rdn with hexString attribute value : a = #0010A0AAFF
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnHexStringAttributeValue() throws LdapException
    {
        assertEquals( "a = #0010A0AAFF", new Rdn( "a = #0010A0AAFF" ).getName() );
    }


    /**
     * test exception from illegal hexString attribute value : a=#zz.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testBadRdnHexStringAttributeValue() throws LdapException
    {
        try
        {
            new Rdn( "a=#zz" );
            fail();
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }
    }


    /**
     * test a simple Rdn with quoted attribute value : a = "quoted \"value"
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnQuotedAttributeValue() throws LdapException
    {
        Rdn rdn = new Rdn( "a = quoted \\\"value" );
        assertEquals( "a = quoted \\\"value", rdn.getName() );
        assertEquals( "quoted \"value", rdn.getValue( "a" ) );
    }


    /**
     * Test the clone method for a Rdn.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCloningOneNameComponent() throws LdapException
    {
        Rdn rdn = new Rdn( "a", "b" );

        Rdn rdnClone = rdn.clone();

        rdn = new Rdn( "c=d" );

        assertEquals( "b", rdnClone.getValue( "a" ) );
    }


    /**
     * Test the creation of a new Rdn
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCreation() throws LdapException
    {
        Rdn rdn = new Rdn( "A", "  b  " );
        assertEquals( "A=  b  ", rdn.getName() );
        assertEquals( "A=\\  b \\ ", rdn.getEscaped() );
    }


    /**
     * Test the clone method for a Rdn.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCloningTwoNameComponent() throws LdapException
    {
        Rdn rdn = new Rdn( "a = b + aa = bb" );

        Rdn rdnClone = rdn.clone();

        rdn.clear();
        rdn = new Rdn( "c=d" );

        assertEquals( "b", rdnClone.getValue( "a" ) );
        assertEquals( "bb", rdnClone.getValue( "aa" ) );
        assertEquals( null, rdnClone.getValue( "c" ) );
    }


    /**
     * Test the equals method for a Rdn.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRDNCompareToNull() throws LdapException
    {
        Rdn rdn1 = new Rdn( " a = b + c = d + e = f + g = h " );
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
        Rdn rdn1 = new Rdn( " a = b + c = d + e = f + g = h " );
        Rdn rdn2 = new Rdn( " a = b " );
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
        Rdn rdn1 = new Rdn( " a = b " );
        Rdn rdn2 = new Rdn( " a = b + c = d + e = f + g = h " );

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
        Rdn rdn1 = new Rdn( " a = b + c = d + e = f + g = h " );
        Rdn rdn2 = new Rdn( " a = b + c = d + e = f + g = h " );

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
        Rdn rdn1 = new Rdn( " a = b + b = f + g = h + c = d " );
        Rdn rdn2 = new Rdn( " a = b + c = d + b = f + g = h " );

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
        Rdn rdn1 = new Rdn( " a = f + g = h + c = d " );
        Rdn rdn2 = new Rdn( " c = d + a = h + g = h " );

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
        Rdn rdn1 = new Rdn( " a = b + c = d " );
        Rdn rdn2 = new Rdn( " a = b + c = y " );
        assertFalse( rdn1.equals( rdn2 ) );
        assertFalse( rdn2.equals( rdn1 ) );

        // the third ATAV differs
        Rdn rdn3 = new Rdn( " a = b + c = d + e = f " );
        Rdn rdn4 = new Rdn( " a = b + c = d + e = y " );
        assertFalse( rdn3.equals( rdn4 ) );
        assertFalse( rdn4.equals( rdn3 ) );

        // the second ATAV differs in value only
        Rdn rdn5 = new Rdn( " a = b + b = c " );
        Rdn rdn6 = new Rdn( " a = b + b = y " );
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
        Rdn rdn1 = new Rdn( " a = b + c = d " );
        Rdn rdn2 = new Rdn( " c = d + a = b " );
        assertTrue( rdn1.equals( rdn2 ) );

        rdn1 = new Rdn( " a = b + c = e " );
        rdn2 = new Rdn( " c = d + a = b " );
        assertFalse( rdn1.equals( rdn2 ) );
        assertFalse( rdn2.equals( rdn1 ) );

        rdn1 = new Rdn( " a = b + c = d " );
        rdn2 = new Rdn( " e = f + g = h " );
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
        Rdn rdn1 = new Rdn( " a = b " );
        Rdn rdn2 = new Rdn( " a = c " );
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
        Rdn rdn1 = new Rdn( " a = b + b = c " );
        Rdn rdn2 = new Rdn( " a = b + b = y " );
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
        Rdn rdn1 = new Rdn( " a = b + c = d  " );
        Rdn rdn2 = new Rdn( " e = f + g = h " );
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
        Rdn rdn1 = new Rdn( " c = d + a = b " );
        Rdn rdn2 = new Rdn( " a = b + e = f " );
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
        Rdn rdn1 = new Rdn( " a = b " );

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
        Rdn rdn1 = new Rdn( " a = b " );
        Rdn rdn2 = new Rdn( " a = b " );

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
        Rdn rdn1 = new Rdn( " a = b " );
        Rdn rdn2 = new Rdn( " A = b " );

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
        Rdn rdn1 = new Rdn( " a = b " );
        Rdn rdn2 = new Rdn( " A = d " );

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
        Rdn rdn = new Rdn( " a = b + b = f + g = h + c = d " );

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
        Rdn rdn = new Rdn( " a = b + b = f + g = h + c = d " );

        assertEquals( "a", rdn.getNormType() );
    }


    /**
     * Test the getSize method.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testGetSize() throws LdapException
    {
        Rdn rdn = new Rdn( " a = b + b = f + g = h + c = d " );

        assertEquals( 4, rdn.size() );
    }


    /**
     * Test the getSize method.
     */
    @Test
    public void testGetSize0()
    {
        Rdn rdn = new Rdn();

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
        Rdn rdn = new Rdn( "a=b + c=d + e=f" );

        assertFalse( rdn.equals( null ) );
        assertFalse( rdn.equals( "test" ) );
        assertFalse( rdn.equals( new Rdn( "a=c + c=d + e=f" ) ) );
        assertFalse( rdn.equals( new Rdn( "a=b" ) ) );
        assertTrue( rdn.equals( new Rdn( "a=b + c=d + e=f" ) ) );
        assertTrue( rdn.equals( new Rdn( "a=b + C=d + E=f" ) ) );
        assertTrue( rdn.equals( new Rdn( "c=d + e=f + a=b" ) ) );
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
    public void testUnescapeValueStringWithEqualInTheMiddle()
    {
        String res = ( String ) Rdn.unescapeValue( "a=b" );

        assertEquals( "a=b", res );
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
        Rdn rdn = new Rdn( "cn=Kate Bush+sn=Bush" );
        assertEquals( "cn=Kate Bush+sn=Bush", rdn.getName() );
    }


    @Test
    public void testMultiValuedIterator() throws LdapException
    {
        Rdn rdn = new Rdn( "cn=Kate Bush+sn=Bush" );
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
        Rdn rdn = new Rdn( "cn=Kate Bush" );
        Iterator<Ava> iterator = rdn.iterator();
        assertNotNull( iterator );
        assertTrue( iterator.hasNext() );
        assertNotNull( iterator.next() );
        assertFalse( iterator.hasNext() );
    }


    @Test
    public void testEmptyIterator()
    {
        Rdn rdn = new Rdn();
        Iterator<Ava> iterator = rdn.iterator();
        assertNotNull( iterator );
        assertFalse( iterator.hasNext() );
    }


    @Test
    public void testRdnWithSpaces() throws LdapException
    {
        Rdn rdn = new Rdn( "cn=a\\ b\\ c" );
        assertEquals( "cn=a\\ b\\ c", rdn.getName() );
    }


    @Test
    public void testEscapedSpaceInValue() throws LdapException
    {
        Rdn rdn1 = new Rdn( "cn=a b c" );
        Rdn rdn2 = new Rdn( "cn=a\\ b\\ c" );
        assertEquals( "cn=a b c", rdn1.getName() );
        assertTrue( rdn1.equals( rdn2 ) );

        Rdn rdn3 = new Rdn( "cn= \\ a b c\\  " );
        Rdn rdn4 = new Rdn( "cn=\\ a\\ b\\ c\\ " );
        assertEquals( "cn= \\ a b c\\  ", rdn3.getName() );
        assertEquals( "cn=\\ a b c\\ ", rdn3.getEscaped() );
        assertTrue( rdn3.equals( rdn4 ) );
    }


    @Test
    public void testEscapedHashInValue() throws LdapException
    {
        Rdn rdn1 = new Rdn( "cn=a#b#c" );
        Rdn rdn2 = new Rdn( "cn=a\\#b\\#c" );
        assertEquals( "cn=a#b#c", rdn1.getName() );
        assertTrue( rdn1.equals( rdn2 ) );

        Rdn rdn3 = new Rdn( "cn=\\#a#b#c\\#" );
        Rdn rdn4 = new Rdn( "cn=\\#a\\#b\\#c\\#" );
        assertEquals( "cn=\\#a#b#c\\#", rdn3.getName() );
        assertEquals( "cn=\\#a#b#c#", rdn3.getEscaped() );
        assertTrue( rdn3.equals( rdn4 ) );
    }


    @Test
    public void testEscapedAttributeValue()
    {
        // space doesn't need to be escaped in the middle of a string
        assertEquals( "a b", Rdn.escapeValue( "a b" ) );
        assertEquals( "a b c", Rdn.escapeValue( "a b c" ) );
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
        Rdn rdn = new Rdn( "" );

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
        Rdn rdn = new Rdn();

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
        Rdn rdn = new Rdn( "a=b" );

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
    public void testSimpleRdn2Serialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( " ABC  = DEF " );

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
     * Test serialization of a simple Rdn with no value
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSimpleRdnNoValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( " ABC  =" );

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
     * Test serialization of a simple Rdn with one value
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSimpleRdnOneValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( " ABC  = def " );

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
     * Test serialization of a simple Rdn with three values
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSimpleRdnThreeValuesSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( " A = a + B = b + C = c " );

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
        Rdn rdn = new Rdn( " B = b + A = a + C = c " );

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
     * test an Rdn with empty value
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnWithEmptyValue() throws LdapException
    {
        assertTrue( Rdn.isValid( "a=" ) );
        assertTrue( Rdn.isValid( "a=\"\"" ) );
        assertEquals( "a=\"\"", new Rdn( "a=\"\"" ).getName() );
        assertEquals( "a=", new Rdn( "a=" ).getName() );
    }


    /**
     * test an Rdn with escaped comma
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnWithEscapedComa() throws LdapException
    {
        assertTrue( Rdn.isValid( "a=b\\,c" ) );
        assertEquals( "a=b\\,c", new Rdn( "a=b\\,c" ).getName() );

        assertTrue( Rdn.isValid( "a=\"b,c\"" ) );
        assertEquals( "a=\"b,c\"", new Rdn( "a=\"b,c\"" ).getName() );
        assertEquals( "a=b\\,c", new Rdn( "a=\"b,c\"" ).getEscaped() );
        assertEquals( "a=\"b,c\"", new Rdn( "a=\"b,c\"" ).getName() );

        assertTrue( Rdn.isValid( "a=\"b\\,c\"" ) );
        Rdn rdn = new Rdn( "a=\"b\\,c\"" );
        assertEquals( "a=\"b\\,c\"", rdn.getName() );
        assertEquals( "a=b\\,c", rdn.getEscaped() );
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
        Rdn rdn = new Rdn( " A = b + C = d" );
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
        Rdn rdn = new Rdn( " A = b + C = d" );
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
        Rdn rdn = new Rdn( " A = b + C = d " );

        assertEquals( " A = b + C = d ", rdn.getName() );
    }


    /**
     * test the iterator over a RDN
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testIterator() throws LdapException
    {
        Rdn rdn = new Rdn( "cn=John + sn=Doe" );

        String[] expected = new String[]
            { "cn=John ", " sn=Doe" };
        int i = 0;

        for ( Ava ava : rdn )
        {
            assertEquals( expected[i], ava.getName() );
            i++;
        }
    }


    /**
     * test that a RDN with two AVAs throws an exception
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testWrongRdn() throws LdapException
    {
        assertThrows( LdapInvalidDnException.class, () -> 
        {
            new Rdn( " A = b, C = d " );
        } );
    }


    /**
     * test that a RDN can have an attributeType twice
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnAtUsedTwice() throws LdapException
    {
        Rdn rdn = new Rdn( " A = b + A = d " );

        assertEquals( " A = b + A = d ", rdn.getName() );
    }


    @Test
    public void testAvaConstructor() throws LdapInvalidDnException
    {
        Rdn rdn = new Rdn( new Ava( "CN", "\u00E4" ), new Ava( "A", "d" ) );
        assertEquals( "CN=\u00E4+A=d", rdn.getName() );
        assertEquals( "\u00E4", rdn.getValue( "CN" ) );
        assertEquals( "\u00E4", rdn.getValue() );
        assertEquals( "CN", rdn.getType() );
        assertEquals( "cn", rdn.getNormType() );
    }


    /**
     * test that a RDN can have an attributeType twice
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testAvaConstructorRdnAtUsedTwice() throws LdapException
    {
        Rdn rdn = new Rdn( new Ava( "A", "b" ), new Ava( "A", "d" ) );

        assertEquals( "A=b+A=d", rdn.getName() );
    }
}
