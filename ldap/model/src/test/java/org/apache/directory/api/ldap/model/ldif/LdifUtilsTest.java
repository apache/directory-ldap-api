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
package org.apache.directory.api.ldap.model.ldif;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaITImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the LdifUtils methods
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class LdifUtilsTest
{
    private String testString = "this is a test";


    /**
     * Tests the method IsLdifSafe with a null String
     */
    @Test
    public void testIsLdifNullString()
    {
        assertTrue( LdifUtils.isLDIFSafe( null ) );
    }


    /**
     * Tests the method IsLdifSafe with an empty String
     */
    @Test
    public void testIsLdifEmptyString()
    {
        assertTrue( LdifUtils.isLDIFSafe( "" ) );
    }


    /**
     * Tests the method IsLdifSafe with a String starting with the
     * char NUL (ASCII code 0)
     */
    @Test
    public void testIsLdifSafeStartingWithNUL()
    {
        char c = ( char ) 0;

        assertFalse( LdifUtils.isLDIFSafe( c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String starting with the
     * char LF (ASCII code 10)
     */
    @Test
    public void testIsLdifSafeStartingWithLF()
    {
        char c = ( char ) 10;

        assertFalse( LdifUtils.isLDIFSafe( c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String starting with the
     * char CR (ASCII code 13)
     */
    @Test
    public void testIsLdifSafeStartingWithCR()
    {
        char c = ( char ) 13;

        assertFalse( LdifUtils.isLDIFSafe( c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String starting with the
     * char SPACE (ASCII code 32)
     */
    @Test
    public void testIsLdifSafeStartingWithSpace()
    {
        char c = ( char ) 32;

        assertFalse( LdifUtils.isLDIFSafe( c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String starting with the
     * char COLON (:) (ASCII code 58)
     */
    @Test
    public void testIsLdifSafeStartingWithColon()
    {
        char c = ( char ) 58;

        assertFalse( LdifUtils.isLDIFSafe( c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String starting with the
     * char LESS_THAN (&lt;) (ASCII code 60)
     */
    @Test
    public void testIsLdifSafeStartingWithLessThan()
    {
        char c = ( char ) 60;

        assertFalse( LdifUtils.isLDIFSafe( c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String starting with the
     * char with ASCII code 127
     */
    @Test
    public void testIsLdifSafeStartingWithCharGreaterThan127()
    {
        char c = ( char ) 127;

        assertTrue( LdifUtils.isLDIFSafe( c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String starting with the
     * char with ASCII code greater than 127
     */
    @Test
    public void testIsLdifSafeStartingWithCharGreaterThan127Bis()
    {
        char c = ( char ) 222;

        assertFalse( LdifUtils.isLDIFSafe( c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String containing the
     * char NUL (ASCII code 0)
     */
    @Test
    public void testIsLdifSafeContainsNUL()
    {
        char c = ( char ) 0;

        assertFalse( LdifUtils.isLDIFSafe( testString + c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String containing the
     * char LF (ASCII code 10)
     */
    @Test
    public void testIsLdifSafeContainsLF()
    {
        char c = ( char ) 10;

        assertFalse( LdifUtils.isLDIFSafe( testString + c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String containing the
     * char CR (ASCII code 13)
     */
    @Test
    public void testIsLdifSafeContainsCR()
    {
        char c = ( char ) 13;

        assertFalse( LdifUtils.isLDIFSafe( testString + c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String containing the
     * char with ASCII code 127
     */
    @Test
    public void testIsLdifSafeContainsCharGreaterThan127()
    {
        char c = ( char ) 127;

        assertTrue( LdifUtils.isLDIFSafe( testString + c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String containing a
     * char with ASCII code greater than 127
     */
    @Test
    public void testIsLdifSafeContainsCharGreaterThan127Bis()
    {
        char c = ( char ) 328;

        assertFalse( LdifUtils.isLDIFSafe( testString + c + testString ) );
    }


    /**
     * Tests the method IsLdifSafe with a String ending with the
     * char SPACE (ASCII code 32)
     */
    @Test
    public void testIsLdifSafeEndingWithSpace()
    {
        char c = ( char ) 32;

        assertFalse( LdifUtils.isLDIFSafe( testString + c ) );
    }


    /**
     * Tests the method IsLdifSafe with a correct String
     */
    @Test
    public void testIsLdifSafeCorrectString()
    {
        assertTrue( LdifUtils.isLDIFSafe( testString ) );
    }


    /**
     * Test the way LDIF lines are stripped to a number of chars
     */
    @Test
    public void testStripLineToNChars()
    {
        String line = "abc";

        try
        {
            LdifUtils.stripLineToNChars( line, 1 );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            // This is correct
        }

        String res = LdifUtils.stripLineToNChars( line, 2 );
        assertEquals( "ab\n c", res );
        assertEquals( "abc", LdifUtils.stripLineToNChars( line, 3 ) );
    }


    /**
     * Test that the LDIF is stripped to 5 chars per line
     *
     */
    @Test
    public void testStripLineTo5Chars()
    {
        assertEquals( "a", LdifUtils.stripLineToNChars( "a", 5 ) );
        assertEquals( "ab", LdifUtils.stripLineToNChars( "ab", 5 ) );
        assertEquals( "abc", LdifUtils.stripLineToNChars( "abc", 5 ) );
        assertEquals( "abcd", LdifUtils.stripLineToNChars( "abcd", 5 ) );
        assertEquals( "abcde", LdifUtils.stripLineToNChars( "abcde", 5 ) );
        assertEquals( "abcde\n f", LdifUtils.stripLineToNChars( "abcdef", 5 ) );
        assertEquals( "abcde\n fg", LdifUtils.stripLineToNChars( "abcdefg", 5 ) );
        assertEquals( "abcde\n fgh", LdifUtils.stripLineToNChars( "abcdefgh", 5 ) );
        assertEquals( "abcde\n fghi", LdifUtils.stripLineToNChars( "abcdefghi", 5 ) );
        assertEquals( "abcde\n fghi\n j", LdifUtils.stripLineToNChars( "abcdefghij", 5 ) );
        assertEquals( "abcde\n fghi\n jk", LdifUtils.stripLineToNChars( "abcdefghijk", 5 ) );
        assertEquals( "abcde\n fghi\n jkl", LdifUtils.stripLineToNChars( "abcdefghijkl", 5 ) );
        assertEquals( "abcde\n fghi\n jklm", LdifUtils.stripLineToNChars( "abcdefghijklm", 5 ) );
        assertEquals( "abcde\n fghi\n jklm\n n", LdifUtils.stripLineToNChars( "abcdefghijklmn", 5 ) );
        assertEquals( "abcde\n fghi\n jklm\n no", LdifUtils.stripLineToNChars( "abcdefghijklmno", 5 ) );
        assertEquals( "abcde\n fghi\n jklm\n nop", LdifUtils.stripLineToNChars( "abcdefghijklmnop", 5 ) );
    }


    /**
     * Tests that unsafe characters are encoded using UTF-8 charset. 
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testConvertToLdifEncoding() throws LdapException
    {
        Attributes attributes = new BasicAttributes( "cn", "Saarbr\u00FCcken" );
        String ldif = LdifUtils.convertToLdif( attributes );
        assertEquals( "cn:: U2FhcmJyw7xja2Vu\n", ldif );
    }


    /**
     * Tests that null values are correctly encoded 
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testConvertToLdifAttrWithNullValues() throws LdapException
    {
        Attributes attributes = new BasicAttributes( "cn", null );
        String ldif = LdifUtils.convertToLdif( attributes );
        assertEquals( "cn:\n", ldif );
    }


    /**
     * Test a conversion of an entry from a LDIF file
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testConvertToLdif() throws LdapException
    {
        LdifEntry entry = new LdifEntry();
        entry.setDn( "cn=Saarbr\u00FCcken, dc=example, dc=com" );
        entry.setChangeType( ChangeType.Add );

        entry.addAttribute( "objectClass", "top", "person", "inetorgPerson" );
        entry.addAttribute( "cn", "Saarbr\u00FCcken" );
        entry.addAttribute( "sn", "test" );

        LdifUtils.convertToLdif( entry, 15 );
    }


    /**
     * Test a conversion of an attributes from a LDIF file
     * 
     * @throws LdapException If the test failed
     * @throws LdapLdifException If the test failed
     */
    @Test
    public void testConvertAttributesfromLdif() throws LdapException, LdapLdifException
    {
        Attributes attributes = new BasicAttributes( true );

        Attribute oc = new BasicAttribute( "objectclass" );
        oc.add( "top" );
        oc.add( "person" );
        oc.add( "inetorgPerson" );

        attributes.put( oc );

        attributes.put( "cn", "Saarbrucken" );
        attributes.put( "sn", "test" );

        String ldif = LdifUtils.convertToLdif( attributes, ( Dn ) null, 15 );
        Attributes result = LdifUtils.getJndiAttributesFromLdif( ldif );
        assertEquals( attributes, result );
    }


    /**
     * Check that the correct reverse LDIF is produced for a modifyDn
     * operation that moves and renames the entry while preserving the
     * old rdn.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseModifyDNSuperior() throws LdapException
    {
        Dn dn = new Dn( "cn=john doe, dc=example, dc=com" );
        Dn newSuperior = new Dn( "ou=system" );

        Entry entry = new DefaultEntry( dn );
        entry.add( "objectClass", "person", "uidObject" );
        entry.add( "cn", "john doe", "jack doe" );
        entry.add( "sn", "doe" );
        entry.add( "uid", "jdoe" );

        List<LdifEntry> reverseds = LdifRevertor.reverseMoveAndRename( entry, newSuperior, new Rdn( "cn=jack doe" ),
            false );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );

        LdifEntry reversed = reverseds.get( 0 );
        assertEquals( "cn=jack doe,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertFalse( reversed.isDeleteOldRdn() );
        assertEquals( "cn=john doe", reversed.getNewRdn() );
        assertEquals( "dc=example, dc=com", Strings.trim( reversed.getNewSuperior() ) );
        assertNull( reversed.getEntry() );
    }


    /**
     * Test a reversed ModifyDN with a deleteOldRdn, rdn change, and a superior
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testReverseModifyDNDeleteOldRdnSuperior() throws LdapException
    {
        Dn dn = new Dn( "cn=john doe, dc=example, dc=com" );
        Dn newSuperior = new Dn( "ou=system" );

        Entry entry = new DefaultEntry( dn );
        entry.add( "objectClass", "person", "uidObject" );
        entry.add( "cn", "john doe" );
        entry.add( "sn", "doe" );
        entry.add( "uid", "jdoe" );

        List<LdifEntry> reverseds = LdifRevertor.reverseMoveAndRename( entry, newSuperior, new Rdn( "cn=jack doe" ),
            false );

        assertNotNull( reverseds );
        assertEquals( 1, reverseds.size() );

        LdifEntry reversed = reverseds.get( 0 );
        assertEquals( "cn=jack doe,ou=system", reversed.getDn().getName() );
        assertEquals( ChangeType.ModRdn, reversed.getChangeType() );
        assertTrue( reversed.isDeleteOldRdn() );
        assertEquals( "cn=john doe", reversed.getNewRdn() );
        assertEquals( "dc=example, dc=com", Strings.trim( reversed.getNewSuperior() ) );
        assertNull( reversed.getEntry() );
    }


    @Test
    public void testCreateAttributesVarargs() throws LdapException, LdapLdifException, NamingException
    {
        String mOid = "m-oid: 1.2.3.4";
        String description = "description";

        Attributes attrs = LdifUtils.createJndiAttributes(
            "objectClass: top",
            "objectClass: metaTop",
            "objectClass: metaSyntax",
            mOid,
            "m-description", description );

        assertEquals( "top", attrs.get( "objectClass" ).get( 0 ) );
        assertEquals( "metaTop", attrs.get( "objectClass" ).get( 1 ) );
        assertEquals( "metaSyntax", attrs.get( "objectClass" ).get( 2 ) );
        assertEquals( "1.2.3.4", attrs.get( "m-oid" ).get() );
        assertEquals( "description", attrs.get( "m-description" ).get() );

        try
        {
            LdifUtils.createJndiAttributes(
                "objectClass", "top",
                "objectClass" );
            fail();
        }
        catch ( LdapInvalidAttributeValueException iave )
        {
            assertTrue( true );
        }
    }


    @Test
    public void testConvertEntryNoControls() throws Exception
    {
        LdifReader reader = new LdifReader();

        String expected =
            "dn: ou=test\n" +
                "ObjectClass: top\n" +
                "ObjectClass: metaTop\n" +
                "ObjectClass: metaSyntax\n" +
                "m-oid: 1.2.3.4\n" +
                "m-description: description\n\n";

        List<LdifEntry> entries = reader.parseLdif( expected );
        LdifEntry expectedEntry = entries.get( 0 );

        LdifEntry entry = new LdifEntry();

        entry.setDn( "ou=test" );
        entry.addAttribute( "ObjectClass", "top", "metaTop", "metaSyntax" );
        entry.addAttribute( "m-oid", "1.2.3.4" );
        entry.addAttribute( "m-description", "description" );

        String converted = LdifUtils.convertToLdif( entry );

        assertNotNull( converted );

        entries = reader.parseLdif( converted );
        LdifEntry convertedEntry = entries.get( 0 );

        assertEquals( expectedEntry, convertedEntry );
        
        reader.close();
    }


    @Test
    public void testConvertEntryOneControl() throws Exception
    {
        LdifReader reader = new LdifReader();

        String expected =
            "dn: ou=test\n" +
                "control: 2.16.840.1.113730.3.4.2 false\n" +
                "changetype: add\n" +
                "ObjectClass: top\n" +
                "ObjectClass: metaTop\n" +
                "ObjectClass: metaSyntax\n" +
                "m-oid: 1.2.3.4\n" +
                "m-description: description\n\n";

        List<LdifEntry> entries = reader.parseLdif( expected );
        LdifEntry expectedEntry = entries.get( 0 );

        LdifEntry entry = new LdifEntry();

        entry.setDn( "ou=test" );
        entry.addAttribute( "ObjectClass", "top", "metaTop", "metaSyntax" );
        entry.addAttribute( "m-oid", "1.2.3.4" );
        entry.addAttribute( "m-description", "description" );

        ManageDsaITImpl control = new ManageDsaITImpl();

        entry.addControl( control );

        String converted = LdifUtils.convertToLdif( entry );

        assertNotNull( converted );

        entries = reader.parseLdif( converted );
        LdifEntry convertedEntry = entries.get( 0 );

        assertEquals( expectedEntry, convertedEntry );
        reader.close();
    }
}
