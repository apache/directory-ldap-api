/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.ldap.entry;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * A test class for the DefaultEntry class
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class SchemaAwareEntryTest
{
    private static Dn exampleDn;
    private static final byte[] BYTES1 = new byte[]
        { 'a', 'b' };
    private static final byte[] BYTES2 = new byte[]
        { 'b' };
    private static final byte[] BYTES3 = new byte[]
        { 'c' };

    private static SchemaManager schemaManager;


    /**
     * Helper method which creates an entry with 4 attributes.
     */
    private Entry createEntry()
    {
        try
        {
            Entry entry = new DefaultEntry( exampleDn );

            Attribute attrOC = new DefaultAttribute( "objectClass", "top", "person" );
            Attribute attrCN = new DefaultAttribute( "cn", "test1", "test2" );
            Attribute attrSN = new DefaultAttribute( "sn", "Test1", "Test2" );
            Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, BYTES2 );

            entry.put( attrOC, attrCN, attrSN, attrPWD );

            return entry;
        }
        catch ( LdapException ne )
        {
            // Do nothing
            return null;
        }
    }


    /**
     * Serialize a ClientEntry
     */
    private ByteArrayOutputStream serializeValue( Entry value ) throws IOException
    {
        ObjectOutputStream oOut = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try
        {
            oOut = new ObjectOutputStream( out );
            oOut.writeObject( value );
        }
        catch ( IOException ioe )
        {
            throw ioe;
        }
        finally
        {
            try
            {
                if ( oOut != null )
                {
                    oOut.flush();
                    oOut.close();
                }
            }
            catch ( IOException ioe )
            {
                throw ioe;
            }
        }

        return out;
    }


    /**
     * Deserialize a ClientEntry
     */
    private Entry deserializeValue( ByteArrayOutputStream out ) throws IOException, ClassNotFoundException
    {
        ObjectInputStream oIn = null;
        ByteArrayInputStream in = new ByteArrayInputStream( out.toByteArray() );

        try
        {
            oIn = new ObjectInputStream( in );

            Entry value = ( Entry ) oIn.readObject();

            return value;
        }
        catch ( IOException ioe )
        {
            throw ioe;
        }
        finally
        {
            try
            {
                if ( oIn != null )
                {
                    oIn.close();
                }
            }
            catch ( IOException ioe )
            {
                throw ioe;
            }
        }
    }


    /**
     * @throws Exception If the test failed
     */
    @BeforeAll
    public static void setUpBeforeClass() throws Exception
    {
        exampleDn = new Dn( "dc=example,dc=com" );
        schemaManager = new DefaultSchemaManager();
    }


    /**
     * Test method for DefaultEntry()
     */
    @Test
    public void testDefaultClientEntry()
    {
        Entry entry = new DefaultEntry();

        assertNotNull( entry );
        assertEquals( Dn.EMPTY_DN, entry.getDn() );
        assertEquals( 0, entry.size() );
    }


    /**
     * Test method for DefaultEntry()
     * 
     * @throws Exception If the test failed
     */
    @Test
    public void testDefaultClientEntryLdif() throws Exception
    {
        Entry entry = new DefaultEntry(
            "ou=example, dc=com",
            "ObjectClass: top",
            "ObjectClass: person",
            "cn: test",
            "sn: test" );

        assertNotNull( entry );
        assertEquals( "ou=example, dc=com", entry.getDn().toString() );
        assertEquals( 3, entry.size() );
        assertTrue( entry.contains( "objectClass", "top", "person" ) );
        assertTrue( entry.contains( "cn", "test" ) );
        assertTrue( entry.contains( "sn", "test" ) );
    }


    /**
     * Test method for DefaultEntry( Dn )
     */
    @Test
    public void testDefaultClientEntryLdapDN()
    {
        Entry entry = new DefaultEntry( exampleDn );

        assertNotNull( entry );
        assertNotNull( entry.getDn() );
        assertEquals( exampleDn, entry.getDn() );
        assertEquals( 0, entry.size() );
    }


    /**
     * Test method for add( EntryAttribute... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testAddEntryAttributeArray() throws LdapException
    {
        Entry entry = createEntry();

        assertEquals( 4, entry.size() );
        assertTrue( entry.containsAttribute( "ObjectClass" ) );
        assertTrue( entry.containsAttribute( "CN" ) );
        assertTrue( entry.containsAttribute( "  sn  " ) );
        assertTrue( entry.containsAttribute( "userPassword" ) );

        Attribute attr = entry.get( "objectclass" );
        assertEquals( 2, attr.size() );

        Attribute attrCN2 = new DefaultAttribute( "cn", "test1", "test3" );
        entry.add( attrCN2 );
        assertEquals( 4, entry.size() );
        attr = entry.get( "cn" );
        assertEquals( 3, attr.size() );
        assertTrue( attr.contains( "test1", "test2", "test3" ) );

        // Check adding some byte[] values (they will not be transformed to Strings)
        attrCN2.clear();
        attrCN2.add( BYTES1, BYTES2 );
        entry.add( attrCN2 );
        assertEquals( 4, entry.size() );
        attr = entry.get( "cn" );
        assertEquals( 3, attr.size() );
        assertTrue( attr.contains( "test1", "test2", "test3" ) );
        assertFalse( attr.contains( "ab", "b" ) );
    }


    /**
     * Test method for add( String, byte[]... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testAddStringByteArrayArray() throws LdapException
    {
        Entry entry = new DefaultEntry();

        entry.add( "userPassword", ( byte[] ) null );
        assertEquals( 1, entry.size() );
        Attribute attributePWD = entry.get( "userPassword" );
        assertEquals( 1, attributePWD.size() );
        assertNotNull( attributePWD.get() );
        assertNull( attributePWD.get().getBytes() );

        entry.add( "jpegPhoto", BYTES1, BYTES1, BYTES2 );
        assertEquals( 2, entry.size() );
        Attribute attributeJPG = entry.get( "jpegPhoto" );
        assertEquals( 2, attributeJPG.size() );
        assertNotNull( attributeJPG.get() );
        assertTrue( attributeJPG.contains( BYTES1 ) );
        assertTrue( attributeJPG.contains( BYTES2 ) );
    }


    /**
     * Test method for add( String, String... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testAddStringStringArray() throws LdapException
    {
        Entry entry = new DefaultEntry();

        entry.add( "cn", ( String ) null );
        assertEquals( 1, entry.size() );
        Attribute attributeCN = entry.get( "cn" );
        assertEquals( 1, attributeCN.size() );
        assertNotNull( attributeCN.get() );
        assertNull( attributeCN.get().getString() );

        entry.add( "sn", "test", "test", "TEST" );
        assertEquals( 2, entry.size() );
        Attribute attributeSN = entry.get( "sn" );
        assertEquals( 2, attributeSN.size() );
        assertNotNull( attributeSN.get() );
        assertTrue( attributeSN.contains( "test" ) );
        assertTrue( attributeSN.contains( "TEST" ) );
    }


    /**
     * Test method for add( String, Value... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testAddStringValueArray() throws LdapException
    {
        Entry entry = new DefaultEntry();

        Value value = new Value( ( String ) null );

        entry.add( "cn", value );
        assertEquals( 1, entry.size() );
        Attribute attributeCN = entry.get( "cn" );
        assertEquals( 1, attributeCN.size() );
        assertNotNull( attributeCN.get() );
        assertNull( attributeCN.get().getString() );

        Value value1 = new Value( "test1" );
        Value value2 = new Value( "test2" );
        Value value3 = new Value( "test1" );

        entry.add( "sn", value1, value2, value3 );
        assertEquals( 2, entry.size() );
        Attribute attributeSN = entry.get( "sn" );
        assertEquals( 2, attributeSN.size() );
        assertNotNull( attributeSN.get() );
        assertTrue( attributeSN.contains( value1 ) );
        assertTrue( attributeSN.contains( value2 ) );

        Value value4 = new Value( BYTES1 );
        entry.add( "l", value1, value4 );
        assertEquals( 3, entry.size() );
        Attribute attributeL = entry.get( "l" );
        assertEquals( 2, attributeL.size() );
        assertNotNull( attributeL.get() );
        assertTrue( attributeL.contains( value1 ) );

        // The byte[] value must have been transformed to a String
        assertTrue( attributeL.contains( "ab" ) );
    }


    /**
     * Test method for clear()
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testClear() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        assertEquals( 0, entry.size() );
        assertNull( entry.get( "ObjectClass" ) );
        entry.clear();
        assertEquals( 0, entry.size() );
        assertNull( entry.get( "ObjectClass" ) );

        entry.add( "ObjectClass", "top", "person" );
        assertEquals( 1, entry.size() );
        assertNotNull( entry.get( "ObjectClass" ) );

        entry.clear();
        assertEquals( 0, entry.size() );
        assertNull( entry.get( "ObjectClass" ) );
    }


    /**
     * Test method for clone()
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testClone() throws LdapException
    {
        Entry entry1 = new DefaultEntry();

        Entry entry2 = entry1.clone();

        assertEquals( entry1, entry2 );
        entry2.setDn( exampleDn );

        assertEquals( Dn.EMPTY_DN, entry1.getDn() );

        entry1.setDn( exampleDn );
        entry2 = entry1.clone();
        assertEquals( entry1, entry2 );

        entry1.add( "objectClass", "top", "person" );
        entry1.add( "cn", "test1", "test2" );

        entry2 = entry1.clone();
        assertEquals( entry1, entry2 );

        entry1.add( "cn", "test3" );
        assertEquals( 2, entry2.get( "cn" ).size() );
        assertFalse( entry2.contains( "cn", "test3" ) );

        entry1.add( "sn", ( String ) null );
        assertFalse( entry2.containsAttribute( "sn" ) );
    }


    /**
     * Test method for contains( EntryAttribute... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testContainsEntryAttributeArray() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        Attribute attrOC = new DefaultAttribute( "objectClass", "top", "person" );
        Attribute attrCN = new DefaultAttribute( "cn", "test1", "test2" );
        Attribute attrSN = new DefaultAttribute( "sn", "Test1", "Test2" );
        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, BYTES2 );

        assertFalse( entry.contains( attrOC, attrCN ) );

        entry.add( attrOC, attrCN );

        assertTrue( entry.contains( attrOC, attrCN ) );
        assertFalse( entry.contains( attrOC, attrCN, attrSN ) );

        entry.add( attrSN, attrPWD );

        assertTrue( entry.contains( attrSN, attrPWD ) );
    }


    /**
     * Test method for contains( String, byte[]... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testContainsStringByteArray() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        assertFalse( entry.containsAttribute( "objectClass" ) );

        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, ( byte[] ) null, BYTES2 );

        entry.add( attrPWD );

        assertTrue( entry.contains( "  userPASSWORD  ", BYTES1, BYTES2 ) );
        assertTrue( entry.contains( "  userPASSWORD  ", ( byte[] ) null ) );

        // We can search for byte[] using Strings. the strings will be converted to byte[]
        assertTrue( entry.contains( "  userPASSWORD  ", "ab", "b" ) );

        assertFalse( entry.contains( "  userPASSWORD  ", "ab", "b", "d" ) );
    }


    /**
     * Test method for contains( String, String... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testContainsStringStringArray() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        assertFalse( entry.containsAttribute( "objectClass" ) );

        Attribute attrOC = new DefaultAttribute( "objectClass", "top", "person" );
        Attribute attrCN = new DefaultAttribute( "cn", "test1", "test2" );
        Attribute attrSN = new DefaultAttribute( "sn", "Test1", "Test2", ( String ) null );
        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, BYTES2 );

        entry.add( attrOC, attrCN, attrSN, attrPWD );

        assertTrue( entry.contains( "OBJECTCLASS", "top", "person" ) );
        assertTrue( entry.contains( " cn ", "test1", "test2" ) );
        assertTrue( entry.contains( "Sn", "Test1", "Test2", ( String ) null ) );
        assertTrue( entry.contains( "  userPASSWORD  ", "ab", "b" ) );

        assertFalse( entry.contains( "OBJECTCLASS", "PERSON" ) );
        assertFalse( entry.contains( " cn ", "test1", "test3" ) );
        assertFalse( entry.contains( "Sn", "Test" ) );
        assertFalse( entry.contains( "  userPASSWORD  ", ( String ) null ) );
    }


    /**
     * Test method for contains( Sring, Value... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testContainsStringValueArray() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        assertFalse( entry.containsAttribute( "objectClass" ) );

        Attribute attrCN = new DefaultAttribute( "cn", "test1", "test2", ( String ) null );
        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, BYTES2, ( byte[] ) null );

        entry.add( attrCN, attrPWD );

        Value strValue1 = new Value( "test1" );
        Value strValue2 = new Value( "test2" );
        Value strValue3 = new Value( "test3" );
        Value strNullValue = new Value( ( String ) null );

        Value binValue1 = new Value( BYTES1 );
        Value binValue2 = new Value( BYTES2 );
        Value binValue3 = new Value( BYTES3 );
        Value binNullValue = new Value( ( byte[] ) null );

        assertTrue( entry.contains( "CN", strValue1, strValue2, strNullValue ) );
        assertTrue( entry.contains( "userpassword", binValue1, binValue2, binNullValue ) );

        assertFalse( entry.contains( "cn", strValue3 ) );
        assertFalse( entry.contains( "UserPassword", binValue3 ) );
    }


    /**
     * Test method for containsAttribute( String )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testContainsAttribute() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        assertFalse( entry.containsAttribute( "objectClass" ) );

        Attribute attrOC = new DefaultAttribute( "objectClass", "top", "person" );
        Attribute attrCN = new DefaultAttribute( "cn", "test1", "test2" );
        Attribute attrSN = new DefaultAttribute( "sn", "Test1", "Test2" );
        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, BYTES2 );

        entry.add( attrOC, attrCN, attrSN, attrPWD );

        assertTrue( entry.containsAttribute( "OBJECTCLASS" ) );
        assertTrue( entry.containsAttribute( " cn " ) );
        assertTrue( entry.containsAttribute( "Sn" ) );
        assertTrue( entry.containsAttribute( "  userPASSWORD  " ) );

        entry.clear();

        assertFalse( entry.containsAttribute( "OBJECTCLASS" ) );
        assertFalse( entry.containsAttribute( " cn " ) );
        assertFalse( entry.containsAttribute( "Sn" ) );
        assertFalse( entry.containsAttribute( "  userPASSWORD  " ) );
    }


    /**
     * Test method for equals()
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testEqualsObject() throws LdapException
    {
        Entry entry1 = new DefaultEntry();
        Entry entry2 = new DefaultEntry();

        assertEquals( entry1, entry2 );

        entry1.setDn( exampleDn );
        assertNotSame( entry1, entry2 );

        entry2.setDn( exampleDn );
        assertEquals( entry1, entry2 );

        Attribute attrOC = new DefaultAttribute( "objectClass", "top", "person" );
        Attribute attrCN = new DefaultAttribute( "cn", "test1", "test2" );
        Attribute attrSN = new DefaultAttribute( "sn", "Test1", "Test2" );
        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, BYTES2 );

        entry1.put( attrOC, attrCN, attrSN, attrPWD );
        entry2.put( attrOC, attrCN, attrSN );
        assertNotSame( entry1, entry2 );

        entry2.put( attrPWD );
        assertEquals( entry1, entry2 );

        Attribute attrL1 = new DefaultAttribute( "l", "Paris", "New-York" );
        Attribute attrL2 = new DefaultAttribute( "l", "Paris", "Tokyo" );

        entry1.put( attrL1 );
        entry2.put( attrL1 );
        assertEquals( entry1, entry2 );

        entry1.add( "l", "London" );
        assertNotSame( entry1, entry2 );

        entry2.add( attrL2 );
        assertNotSame( entry1, entry2 );

        entry1.clear();
        entry2.clear();
        assertEquals( entry1, entry2 );
    }


    /**
     * Test method for get( String )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testGet() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        assertNull( entry.get( "objectClass" ) );

        Attribute attrOC = new DefaultAttribute( "objectClass", "top", "person" );
        Attribute attrCN = new DefaultAttribute( "cn", "test1", "test2" );
        Attribute attrSN = new DefaultAttribute( "sn", "Test1", "Test2" );
        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, BYTES2 );

        entry.add( attrOC, attrCN, attrSN, attrPWD );

        assertNotNull( entry.get( "  CN  " ) );
        Attribute attribute = entry.get( "cN" );

        assertEquals( attribute, attrCN );

        assertNull( entry.get( ( String ) null ) );
        assertNull( entry.get( "  " ) );
        assertNull( entry.get( "l" ) );
    }


    /**
     * Test method for getDN()
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testGetDn() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        assertEquals( exampleDn, entry.getDn() );

        Dn testDn = new Dn( "cn=test" );
        entry.setDn( testDn );

        assertEquals( testDn, entry.getDn() );
    }


    /**
     * Test method for hashcode()
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testHashCode() throws LdapException, LdapException
    {
        Entry entry1 = new DefaultEntry( exampleDn );
        Entry entry2 = new DefaultEntry( exampleDn );

        assertEquals( entry1.hashCode(), entry2.hashCode() );

        entry2.setDn( new Dn( "ou=system,dc=com" ) );
        assertNotSame( entry1.hashCode(), entry2.hashCode() );

        entry2.setDn( exampleDn );
        assertEquals( entry1.hashCode(), entry2.hashCode() );

        Attribute attrOC = new DefaultAttribute( "objectClass", "top", "person" );
        Attribute attrCN = new DefaultAttribute( "cn", "test1", "test2" );
        Attribute attrSN = new DefaultAttribute( "sn", "Test1", "Test2" );
        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, BYTES2 );

        entry1.add( attrOC, attrCN, attrSN, attrPWD );
        entry2.add( attrOC, attrCN, attrSN, attrPWD );

        assertEquals( entry1.hashCode(), entry2.hashCode() );

        Entry entry3 = new DefaultEntry( exampleDn );
        entry3.add( attrOC, attrSN, attrCN, attrPWD );

        assertEquals( entry1.hashCode(), entry3.hashCode() );
    }


    /**
     * Test method for hasObjectClass( String )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testHasObjectClass() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        assertFalse( entry.containsAttribute( "objectClass" ) );
        assertFalse( entry.hasObjectClass( "top" ) );

        entry.add( new DefaultAttribute( "objectClass", "top", "person" ) );

        assertTrue( entry.hasObjectClass( "top" ) );
        assertTrue( entry.hasObjectClass( "person" ) );
        assertFalse( entry.hasObjectClass( "inetorgperson" ) );
        assertFalse( entry.hasObjectClass( ( String ) null ) );
        assertFalse( entry.hasObjectClass( "" ) );
    }


    /**
     * Test method for Iterator()
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testIterator() throws LdapException
    {
        Entry entry = createEntry();

        Iterator<Attribute> iterator = entry.iterator();

        assertTrue( iterator.hasNext() );

        Set<String> expectedIds = new HashSet<String>();
        expectedIds.add( "objectclass" );
        expectedIds.add( "cn" );
        expectedIds.add( "sn" );
        expectedIds.add( "userpassword" );

        while ( iterator.hasNext() )
        {
            Attribute attribute = iterator.next();

            String id = attribute.getId();
            assertTrue( expectedIds.contains( id ) );
            expectedIds.remove( id );
        }

        assertEquals( 0, expectedIds.size() );
    }


    /**
     * Test method for put( EntryAttribute... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testPutEntryAttributeArray() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        Attribute attrOC = new DefaultAttribute( "objectClass", "top", "person" );
        Attribute attrCN = new DefaultAttribute( "cn", "test1", "test2" );
        Attribute attrSN = new DefaultAttribute( "sn", "Test1", "Test2" );
        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, BYTES2 );

        List<Attribute> removed = entry.put( attrOC, attrCN, attrSN, attrPWD );

        assertEquals( 4, entry.size() );
        assertEquals( 0, removed.size() );
        assertTrue( entry.containsAttribute( "ObjectClass" ) );
        assertTrue( entry.containsAttribute( "CN" ) );
        assertTrue( entry.containsAttribute( "  sn  " ) );
        assertTrue( entry.containsAttribute( "userPassword" ) );

        Attribute attrCN2 = new DefaultAttribute( "cn", "test3", "test4" );
        removed = entry.put( attrCN2 );
        assertEquals( 4, entry.size() );
        assertEquals( 1, removed.size() );
        assertTrue( entry.containsAttribute( "CN" ) );
        assertTrue( entry.contains( "cn", "test3", "test4" ) );
    }


    /**
     * Test method for put( String, byte[]... )
     */
    @Test
    public void testPutStringByteArrayArray()
    {
        Entry entry = new DefaultEntry( exampleDn );

        try
        {
            entry.put( ( String ) null, BYTES1 );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }

        try
        {
            entry.put( "   ", BYTES1 );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }

        entry.put( "userPassword", ( byte[] ) null );
        assertEquals( 1, entry.size() );
        assertNotNull( entry.get( "userPassword" ) );
        assertEquals( 1, entry.get( "userPassword" ).size() );
        assertNull( entry.get( "userPassword" ).get().getBytes() );

        entry.put( "jpegPhoto", BYTES1, BYTES2, BYTES1 );
        assertEquals( 2, entry.size() );
        assertNotNull( entry.get( "jpegPhoto" ) );
        assertEquals( 2, entry.get( "JPEGPhoto" ).size() );
        Attribute attribute = entry.get( "jpegPhoto" );
        assertTrue( attribute.contains( BYTES1 ) );
        assertTrue( attribute.contains( BYTES2 ) );
        assertEquals( "jpegphoto", attribute.getId() );
        assertEquals( "jpegPhoto", attribute.getUpId() );
    }


    /**
     * Test method for put( String, String... )
     */
    @Test
    public void testPutStringStringArray()
    {
        Entry entry = new DefaultEntry( exampleDn );

        try
        {
            entry.put( ( String ) null, "a" );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }

        try
        {
            entry.put( "   ", "a" );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }

        entry.put( "sn", ( String ) null );
        assertEquals( 1, entry.size() );
        assertNotNull( entry.get( "sn" ), "sn" );
        assertEquals( 1, entry.get( "sn" ).size() );
        assertNull( entry.get( "sn" ).get().getString() );

        entry.put( "ObjectClass", "top", "person", "top" );
        assertEquals( 2, entry.size() );
        assertNotNull( entry.get( "sn" ), "objectclass" );
        assertEquals( 2, entry.get( "OBJECTCLASS" ).size() );
        Attribute attribute = entry.get( "objectClass" );
        assertTrue( attribute.contains( "top" ) );
        assertTrue( attribute.contains( "person" ) );
        assertEquals( "objectclass", attribute.getId() );
        assertEquals( "ObjectClass", attribute.getUpId() );
    }


    /**
     * Test method for pu( String, Value... )
     */
    @Test
    public void testPutStringValueArray()
    {
        Entry entry = new DefaultEntry( exampleDn );

        Value strValueTop = new Value( "top" );
        Value strValuePerson = new Value( "person" );
        Value strValueTop2 = new Value( "top" );
        Value strNullValue = new Value( ( String ) null );

        Value binValue1 = new Value( BYTES1 );
        Value binValue2 = new Value( BYTES2 );
        Value binValue3 = new Value( BYTES1 );
        Value binNullValue = new Value( ( byte[] ) null );

        try
        {
            entry.put( ( String ) null, strValueTop );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }

        try
        {
            entry.put( "   ", strValueTop );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }

        entry.put( "sn", strNullValue );
        assertEquals( 1, entry.size() );
        assertNotNull( entry.get( "sn" ), "sn" );
        assertEquals( 1, entry.get( "sn" ).size() );
        assertNull( entry.get( "sn" ).get().getString() );

        entry.clear();

        entry.put( "ObjectClass", strValueTop, strValuePerson, strValueTop2, strNullValue );
        assertEquals( 1, entry.size() );
        assertNotNull( entry.get( "objectclass" ), "objectclass" );
        assertEquals( 3, entry.get( "OBJECTCLASS" ).size() );
        Attribute attribute = entry.get( "objectClass" );
        assertTrue( attribute.contains( "top" ) );
        assertTrue( attribute.contains( "person" ) );
        assertTrue( attribute.contains( ( String ) null ) );
        assertEquals( "objectclass", attribute.getId() );
        assertEquals( "ObjectClass", attribute.getUpId() );

        entry.clear();

        entry.put( "userpassword", strNullValue );
        assertEquals( 1, entry.size() );
        assertNotNull( entry.get( "userpassword" ), "userpassword" );
        assertEquals( 1, entry.get( "userpassword" ).size() );
        assertNull( entry.get( "userpassword" ).get().getString() );

        entry.clear();

        entry.put( "userPassword", binValue1, binValue2, binValue3, binNullValue );
        assertEquals( 1, entry.size() );
        assertNotNull( entry.get( "userpassword" ), "userpassword" );
        assertEquals( 3, entry.get( "userpassword" ).size() );
        attribute = entry.get( "userpassword" );
        assertTrue( attribute.contains( BYTES1 ) );
        assertTrue( attribute.contains( BYTES2 ) );
        assertTrue( attribute.contains( ( byte[] ) null ) );
        assertEquals( "userpassword", attribute.getId() );
        assertEquals( "userPassword", attribute.getUpId() );
    }


    /**
     * Test method for removeAttributes( String... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRemoveAttributesStringArray() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        Attribute attrOC = new DefaultAttribute( "objectClass", "top", "person" );
        Attribute attrCN = new DefaultAttribute( "cn", "test1", "test2" );
        Attribute attrSN = new DefaultAttribute( "sn", "Test1", "Test2" );
        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, BYTES2 );

        entry.put( attrOC, attrCN, attrSN, attrPWD );

        entry.removeAttributes( "CN", "SN" );

        assertFalse( entry.containsAttribute( "cn", "sn" ) );
        assertTrue( entry.containsAttribute( "objectclass", "userpassword" ) );

        entry.removeAttributes( "badId" );

        entry.removeAttributes( ( String ) null );
    }


    /**
     * Test method for remove( EntryAttribute... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRemoveEntryAttributeArray() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        Attribute attrOC = new DefaultAttribute( "objectClass", "top", "person" );
        Attribute attrCN = new DefaultAttribute( "cn", "test1", "test2" );
        Attribute attrSN = new DefaultAttribute( "sn", "Test1", "Test2" );
        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, BYTES2 );

        entry.put( attrOC, attrCN, attrSN, attrPWD );

        List<Attribute> removed = entry.remove( attrSN, attrPWD );

        assertEquals( 2, removed.size() );
        assertEquals( 2, entry.size() );
        assertTrue( removed.contains( attrSN ) );
        assertTrue( removed.contains( attrPWD ) );
        assertTrue( entry.contains( "objectClass", "top", "person" ) );
        assertTrue( entry.contains( "cn", "test1", "test2" ) );
        assertFalse( entry.containsAttribute( "sn" ) );
        assertFalse( entry.containsAttribute( "userPassword" ) );

        removed = entry.remove( attrSN, attrPWD );

        assertEquals( 0, removed.size() );
    }


    /**
     * Test method for remove(String, byte[]... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRemoveStringByteArrayArray() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, ( byte[] ) null, BYTES2 );

        entry.put( attrPWD );
        assertTrue( entry.remove( "userPassword", ( byte[] ) null ) );
        assertTrue( entry.remove( "userPassword", BYTES1, BYTES2 ) );
        assertFalse( entry.containsAttribute( "userPassword" ) );

        entry.add( "userPassword", BYTES1, ( byte[] ) null, BYTES2 );
        assertTrue( entry.remove( "userPassword", ( byte[] ) null ) );
        assertEquals( 2, entry.get( "userPassword" ).size() );
        assertTrue( entry.remove( "userPassword", BYTES1, BYTES3 ) );
        assertEquals( 1, entry.get( "userPassword" ).size() );
        assertTrue( Arrays.equals( BYTES2, entry.get( "userPassword" ).getBytes() ) );

        assertFalse( entry.remove( "userPassword", BYTES3 ) );
        assertFalse( entry.remove( "void", "whatever" ) );
    }


    /**
     * Test method for remove( String, String... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRemoveStringStringArray() throws LdapException
    {
        Entry entry = createEntry();

        assertTrue( entry.remove( "cn", "test1" ) );
        assertTrue( entry.remove( "cn", "test2" ) );
        assertFalse( entry.containsAttribute( "cn" ) );

        entry.add( "cn", "test1", ( String ) null, "test2" );
        assertTrue( entry.remove( "cn", ( String ) null ) );
        assertEquals( 2, entry.get( "cn" ).size() );
        assertTrue( entry.remove( "cn", "test1", "test3" ) );
        assertEquals( 1, entry.get( "cn" ).size() );
        assertEquals( "test2", entry.get( "cn" ).get().getString() );

        assertFalse( entry.remove( "cn", "test3" ) );
        assertFalse( entry.remove( "void", "whatever" ) );
    }


    /**
     * Test method for remove(String, Value... )
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRemoveStringValueArray() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        Attribute attrCN = new DefaultAttribute( "cn", "test1", "test2", ( String ) null );
        Attribute attrPWD = new DefaultAttribute( "userPassword", BYTES1, BYTES2, ( byte[] ) null );

        entry.add( attrCN, attrPWD );

        Value strValue1 = new Value( "test1" );
        Value strValue2 = new Value( "test2" );
        Value strValue3 = new Value( "test3" );
        Value strNullValue = new Value( ( String ) null );

        Value binValue1 = new Value( BYTES1 );
        Value binValue2 = new Value( BYTES2 );
        Value binValue3 = new Value( BYTES3 );
        Value binNullValue = new Value( ( byte[] ) null );

        assertTrue( entry.remove( "cn", strValue1, strNullValue ) );
        assertTrue( entry.contains( "cn", strValue2 ) );
        assertFalse( entry.remove( "cn", strValue3 ) );
        assertTrue( entry.remove( "cn", strValue2 ) );
        assertFalse( entry.containsAttribute( "cn" ) );

        entry.add( attrCN, attrPWD );

        assertTrue( entry.remove( "userpassword", binValue1, binNullValue ) );
        assertTrue( entry.contains( "userpassword", binValue2 ) );
        assertFalse( entry.remove( "userpassword", binValue3 ) );
        assertTrue( entry.remove( "userpassword", binValue2 ) );
        assertFalse( entry.containsAttribute( "userpassword" ) );
    }


    /**
     * Test method for setDN( Dn )
     */
    @Test
    public void testSetDn()
    {
        Entry entry = new DefaultEntry();

        assertEquals( Dn.EMPTY_DN, entry.getDn() );

        entry.setDn( exampleDn );
        assertEquals( exampleDn, entry.getDn() );
    }


    /**
     * Test method for size()
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testSize() throws LdapException
    {
        Entry entry = new DefaultEntry( exampleDn );

        assertEquals( 0, entry.size() );
        entry.add( "ObjectClass", "top", "person" );
        entry.add( "cn", "test" );
        entry.add( "sn", "Test" );

        assertEquals( 3, entry.size() );

        entry.clear();
        assertEquals( 0, entry.size() );
    }


    /**
     * Test method for for {@link org.apache.directory.api.ldap.model.entry.DefaultEntry#toString()}.
     */
    @Test
    public void testToString()
    {
        Entry entry = new DefaultEntry( exampleDn );

        assertEquals( "Entry\n    dn: dc=example,dc=com\n\n", entry.toString() );

        Value strValueTop = new Value( "top" );
        Value strValuePerson = new Value( "person" );
        Value strNullValue = new Value( ( String ) null );

        Value binValue1 = new Value( BYTES1 );
        Value binValue2 = new Value( BYTES2 );
        Value binNullValue = new Value( ( byte[] ) null );

        entry.put( "ObjectClass", strValueTop, strValuePerson, strNullValue );
        entry.put( "UserPassword", binValue1, binValue2, binNullValue );

        String expected =
            "Entry\n"
                + "    dn: dc=example,dc=com\n"
                + "    ObjectClass: top\n"
                + "    ObjectClass: person\n"
                + "    ObjectClass: ''\n"
                + "    UserPassword: 0x61 0x62 \n"
                + "    UserPassword: 0x62 \n"
                + "    UserPassword: ''\n";

        assertEquals( expected, entry.toString() );
    }


    /**
     * Test the serialization of a complete entry
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSerializeCompleteEntry() throws LdapException, IOException, ClassNotFoundException
    {
        Dn dn = new Dn( schemaManager,  "ou=system" );

        byte[] password = Strings.getBytesUtf8( "secret" );
        Entry entry = new DefaultEntry( dn );
        entry.add( "ObjectClass", "top", "person" );
        entry.add( "cn", "test1" );
        entry.add( "userPassword", password );

        Entry entrySer = deserializeValue( serializeValue( entry ) );

        assertEquals( entry, entrySer );
    }


    /**
     * Test the serialization of an entry with no Dn
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSerializeEntryWithNoDN() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] password = Strings.getBytesUtf8( "secret" );
        Entry entry = new DefaultEntry();
        entry.add( "ObjectClass", "top", "person" );
        entry.add( "cn", "test1" );
        entry.add( "userPassword", password );

        Entry entrySer = deserializeValue( serializeValue( entry ) );

        assertEquals( entry, entrySer );
    }


    /**
     * Test the serialization of an entry with no attribute and no Dn
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSerializeEntryWithNoDNNoAttribute() throws LdapException, IOException, ClassNotFoundException
    {
        Entry entry = new DefaultEntry();

        Entry entrySer = deserializeValue( serializeValue( entry ) );

        assertEquals( entry, entrySer );
    }


    /**
     * Test the serialization of an entry with no attribute
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSerializeEntryWithNoAttribute() throws LdapException, IOException, ClassNotFoundException
    {
        Dn dn = new Dn( schemaManager, "ou=system" );

        Entry entry = new DefaultEntry( dn );

        Entry entrySer = deserializeValue( serializeValue( entry ) );

        assertEquals( entry, entrySer );
    }


    /**
     * Test method for userCertificate;binary AT
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testUserCertificateBinary() throws LdapException
    {
        Entry entry = new DefaultEntry( schemaManager );
        entry.add( "objectClass", "top", "person", "inetorgPerson" );
        entry.add( "cn", "test1", "test2" );
        entry.add( "sn", "Test1", "Test2" );
        entry.add( "userPassword", BYTES1, BYTES2 );

        entry.add( "userCertificate;binary", Strings.getBytesUtf8( "secret" ) );
        assertTrue( entry.containsAttribute( "userCertificate;binary" ) );
        assertTrue( entry.containsAttribute( "userCertificate" ) );

        entry.removeAttributes( "userCertificate;binary" );
        assertFalse( entry.containsAttribute( "userCertificate;binary" ) );
        assertFalse( entry.containsAttribute( "userCertificate" ) );

        entry.add( "userCertificate", Strings.getBytesUtf8( "secret" ) );
        assertTrue( entry.containsAttribute( "userCertificate;binary" ) );
        assertTrue( entry.containsAttribute( "userCertificate" ) );
    }
}
