/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.ldap.model.entry;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.Iterator;

import javax.naming.directory.InvalidAttributeValueException;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.util.Strings;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the DefaultEntryAttribute class
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class AttributeTest
{
    private static final Value<String> NULL_STRING_VALUE = new StringValue( ( String ) null );
    private static final Value<byte[]> NULL_BINARY_VALUE = new BinaryValue( ( byte[] ) null );
    private static final byte[] BYTES1 = new byte[]
        { 'a', 'b' };
    private static final byte[] BYTES2 = new byte[]
        { 'b' };
    private static final byte[] BYTES3 = new byte[]
        { 'c' };
    private static final byte[] BYTES4 = new byte[]
        { 'd' };

    private static final StringValue STR_VALUE1 = new StringValue( "a" );
    private static final StringValue STR_VALUE2 = new StringValue( "b" );
    private static final StringValue STR_VALUE3 = new StringValue( "c" );
    private static final StringValue STR_VALUE4 = new StringValue( "d" );

    private static final BinaryValue BIN_VALUE1 = new BinaryValue( BYTES1 );
    private static final BinaryValue BIN_VALUE2 = new BinaryValue( BYTES2 );
    private static final BinaryValue BIN_VALUE3 = new BinaryValue( BYTES3 );
    private static final BinaryValue BIN_VALUE4 = new BinaryValue( BYTES4 );


    /**
     * Serialize a DefaultEntryAttribute
     */
    private ByteArrayOutputStream serializeValue( DefaultAttribute value ) throws IOException
    {
        ObjectOutputStream oOut = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try
        {
            oOut = new ObjectOutputStream( out );
            value.writeExternal( oOut );
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
     * Deserialize a DefaultEntryAttribute
     */
    private DefaultAttribute deserializeValue( ByteArrayOutputStream out ) throws IOException, ClassNotFoundException
    {
        ObjectInputStream oIn = null;
        ByteArrayInputStream in = new ByteArrayInputStream( out.toByteArray() );

        try
        {
            oIn = new ObjectInputStream( in );

            DefaultAttribute value = new DefaultAttribute();
            value.readExternal( oIn );

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
     * @throws Exception
     */
    @BeforeClass
    public static void setUpBeforeClass() throws Exception
    {
    }


    /**
     * Test method new DefaultEntryAttribute()
     */
    @Test
    public void testDefaultClientAttribute()
    {
        Attribute attr = new DefaultAttribute();

        assertFalse( attr.isHumanReadable() );
        assertEquals( 0, attr.size() );
        assertNull( attr.getId() );
        assertNull( attr.getUpId() );
    }


    /**
     * Test method new DefaultEntryAttribute( String )
     */
    @Test
    public void testDefaultClientAttributeString()
    {
        Attribute attr = new DefaultAttribute( "TEST" );

        assertFalse( attr.isHumanReadable() );
        assertEquals( 0, attr.size() );
        assertEquals( "test", attr.getId() );
        assertEquals( "TEST", attr.getUpId() );
    }


    /**
     * Test method new DefaultEntryAttribute( String, Value... )
     */
    @Test
    public void testDefaultClientAttributeStringValueArray()
    {
        Attribute attr = new DefaultAttribute( "Test", STR_VALUE1, STR_VALUE2 );

        assertTrue( attr.isHumanReadable() );
        assertEquals( 2, attr.size() );
        assertTrue( attr.contains( "a" ) );
        assertTrue( attr.contains( "b" ) );
        assertEquals( "test", attr.getId() );
        assertEquals( "Test", attr.getUpId() );
    }


    /**
     * Test method 
     */
    @Test
    public void testDefaultClientAttributeStringStringArray()
    {
        Attribute attr = new DefaultAttribute( "Test", "a", "b" );

        assertTrue( attr.isHumanReadable() );
        assertEquals( 2, attr.size() );
        assertTrue( attr.contains( "a" ) );
        assertTrue( attr.contains( "b" ) );
        assertEquals( "test", attr.getId() );
        assertEquals( "Test", attr.getUpId() );
    }


    /**
     * Test method 
     */
    @Test
    public void testDefaultClientAttributeStringBytesArray()
    {
        Attribute attr = new DefaultAttribute( "Test", BYTES1, BYTES2 );

        assertFalse( attr.isHumanReadable() );
        assertEquals( 2, attr.size() );
        assertTrue( attr.contains( BYTES1 ) );
        assertTrue( attr.contains( BYTES2 ) );
        assertEquals( "test", attr.getId() );
        assertEquals( "Test", attr.getUpId() );
    }


    /**
     * Test method getBytes()
     */
    @Test
    public void testGetBytes() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        attr1.add( ( byte[] ) null );
        assertNull( attr1.getBytes() );

        Attribute attr2 = new DefaultAttribute( "test" );

        attr2.add( BYTES1, BYTES2 );
        assertTrue( Arrays.equals( BYTES1, attr2.getBytes() ) );

        Attribute attr3 = new DefaultAttribute( "test" );

        attr3.add( "a", "b" );

        try
        {
            attr3.getBytes();
            fail();
        }
        catch ( LdapInvalidAttributeValueException ivae )
        {
            assertTrue( true );
        }
    }


    /**
     * Test method getString()
     */
    @Test
    public void testGetString() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        attr1.add( ( String ) null );
        assertEquals( "", attr1.getString() );

        Attribute attr2 = new DefaultAttribute( "test" );

        attr2.add( "a", "b" );
        assertEquals( "a", attr2.getString() );

        Attribute attr3 = new DefaultAttribute( "test" );

        attr3.add( BYTES1, BYTES2 );

        try
        {
            attr3.getString();
            fail();
        }
        catch ( LdapInvalidAttributeValueException ivae )
        {
            assertTrue( true );
        }
    }


    /**
     * Test method getId()
     */
    @Test
    public void testGetId()
    {
        Attribute attr = new DefaultAttribute();

        assertNull( attr.getId() );

        attr.setUpId( "test" );
        assertEquals( "test", attr.getId() );

        attr.setUpId( "  TEST  " );
        assertEquals( "test", attr.getId() );
    }


    /**
     * Test method SetId(String)
     */
    @Test
    public void testSetId()
    {
        Attribute attr = new DefaultAttribute();

        try
        {
            attr.setUpId( null );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }

        try
        {
            attr.setUpId( "" );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }

        try
        {
            attr.setUpId( "  " );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }

        attr.setUpId( "Test" );
        assertEquals( "test", attr.getId() );

        attr.setUpId( " Test " );
        assertEquals( "test", attr.getId() );
    }


    /**
     * Test method getUpId()
     */
    @Test
    public void testGetUpId()
    {
        Attribute attr = new DefaultAttribute();

        assertNull( attr.getUpId() );

        attr.setUpId( "test" );
        assertEquals( "test", attr.getUpId() );

        attr.setUpId( "  TEST  " );
        assertEquals( "  TEST  ", attr.getUpId() );
    }


    /**
     * Test method setUpId(String)
     */
    @Test
    public void testSetUpId()
    {
        Attribute attr = new DefaultAttribute();

        try
        {
            attr.setUpId( null );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }

        try
        {
            attr.setUpId( "" );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }

        try
        {
            attr.setUpId( "  " );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            assertTrue( true );
        }

        attr.setUpId( "Test" );
        assertEquals( "Test", attr.getUpId() );
        assertEquals( "test", attr.getId() );

        attr.setUpId( " Test " );
        assertEquals( " Test ", attr.getUpId() );
        assertEquals( "test", attr.getId() );
    }


    /**
     * Test method iterator()
     */
    @Test
    public void testIterator() throws LdapException
    {
        Attribute attr = new DefaultAttribute();
        attr.add( "a", "b", "c" );

        Iterator<Value<?>> iter = attr.iterator();

        assertTrue( iter.hasNext() );

        String[] values = new String[]
            { "a", "b", "c" };
        int pos = 0;

        for ( Value<?> val : attr )
        {
            assertTrue( val instanceof StringValue );
            assertEquals( values[pos++], val.getString() );
        }
    }


    /**
     * Test method add(Value...)
     */
    @Test
    public void testAddValueArray() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        int nbAdded = attr1.add( new StringValue( ( String ) null ) );
        assertEquals( 1, nbAdded );
        assertTrue( attr1.isHumanReadable() );
        assertEquals( NULL_STRING_VALUE, attr1.get() );

        Attribute attr2 = new DefaultAttribute( "test" );

        nbAdded = attr2.add( new BinaryValue( ( byte[] ) null ) );
        assertEquals( 1, nbAdded );
        assertFalse( attr2.isHumanReadable() );
        assertEquals( NULL_BINARY_VALUE, attr2.get() );

        Attribute attr3 = new DefaultAttribute( "test" );

        nbAdded = attr3.add( new StringValue( "a" ), new StringValue( "b" ) );
        assertEquals( 2, nbAdded );
        assertTrue( attr3.isHumanReadable() );
        assertTrue( attr3.contains( "a" ) );
        assertTrue( attr3.contains( "b" ) );

        Attribute attr4 = new DefaultAttribute( "test" );

        nbAdded = attr4.add( new BinaryValue( BYTES1 ), new BinaryValue( BYTES2 ) );
        assertEquals( 2, nbAdded );
        assertFalse( attr4.isHumanReadable() );
        assertTrue( attr4.contains( BYTES1 ) );
        assertTrue( attr4.contains( BYTES2 ) );

        Attribute attr5 = new DefaultAttribute( "test" );

        nbAdded = attr5.add( new StringValue( "c" ), new BinaryValue( BYTES1 ) );
        assertEquals( 2, nbAdded );
        assertTrue( attr5.isHumanReadable() );
        assertTrue( attr5.contains( "ab" ) );
        assertTrue( attr5.contains( "c" ) );

        Attribute attr6 = new DefaultAttribute( "test" );

        nbAdded = attr6.add( new BinaryValue( BYTES1 ), new StringValue( "c" ) );
        assertEquals( 2, nbAdded );
        assertFalse( attr6.isHumanReadable() );
        assertTrue( attr6.contains( BYTES1 ) );
        assertTrue( attr6.contains( BYTES3 ) );

        Attribute attr7 = new DefaultAttribute( "test" );

        nbAdded = attr7.add( new BinaryValue( ( byte[] ) null ), new StringValue( "c" ) );
        assertEquals( 2, nbAdded );
        assertFalse( attr7.isHumanReadable() );
        assertTrue( attr7.contains( NULL_BINARY_VALUE ) );
        assertTrue( attr7.contains( BYTES3 ) );

        Attribute attr8 = new DefaultAttribute( "test" );

        nbAdded = attr8.add( new StringValue( ( String ) null ), new BinaryValue( BYTES1 ) );
        assertEquals( 2, nbAdded );
        assertTrue( attr8.isHumanReadable() );
        assertTrue( attr8.contains( NULL_STRING_VALUE ) );
        assertTrue( attr8.contains( "ab" ) );
    }


    /**
     * Test method add( String... )
     */
    @Test
    public void testAddStringArray() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );
        assertEquals( 0, attr1.size() );

        int nbAdded = attr1.add( ( String ) null );
        assertEquals( 1, nbAdded );
        assertTrue( attr1.isHumanReadable() );
        assertEquals( NULL_STRING_VALUE, attr1.get() );
        assertEquals( 1, attr1.size() );

        Attribute attr2 = new DefaultAttribute( "test" );

        nbAdded = attr2.add( "" );
        assertEquals( 1, nbAdded );
        assertTrue( attr2.isHumanReadable() );
        assertEquals( "", attr2.getString() );
        assertEquals( 1, attr2.size() );

        Attribute attr3 = new DefaultAttribute( "test" );

        nbAdded = attr3.add( "t" );
        assertEquals( 1, nbAdded );
        assertTrue( attr3.isHumanReadable() );
        assertEquals( "t", attr3.getString() );

        Attribute attr4 = new DefaultAttribute( "test" );

        nbAdded = attr4.add( "a", "b", "c", "d" );
        assertEquals( 4, nbAdded );
        assertTrue( attr4.isHumanReadable() );
        assertEquals( "a", attr4.getString() );
        assertTrue( attr4.contains( "a" ) );
        assertTrue( attr4.contains( "b" ) );
        assertTrue( attr4.contains( "c" ) );
        assertTrue( attr4.contains( "d" ) );

        nbAdded = attr4.add( "e" );
        assertEquals( 1, nbAdded );
        assertTrue( attr4.isHumanReadable() );
        assertEquals( "a", attr4.getString() );
        assertTrue( attr4.contains( "a" ) );
        assertTrue( attr4.contains( "b" ) );
        assertTrue( attr4.contains( "c" ) );
        assertTrue( attr4.contains( "d" ) );
        assertTrue( attr4.contains( "e" ) );

        nbAdded = attr4.add( BYTES1 );
        assertEquals( 0, nbAdded );
        assertTrue( attr4.isHumanReadable() );
        assertEquals( "a", attr4.getString() );
        assertTrue( attr4.contains( "a" ) );
        assertTrue( attr4.contains( "b" ) );
        assertTrue( attr4.contains( "c" ) );
        assertTrue( attr4.contains( "d" ) );
        assertTrue( attr4.contains( "e" ) );
        assertFalse( attr4.contains( "ab" ) );

        Attribute attr5 = new DefaultAttribute( "test" );

        nbAdded = attr5.add( "a", "b", ( String ) null, "d" );
        assertEquals( 4, nbAdded );
        assertTrue( attr5.isHumanReadable() );
        assertTrue( attr5.contains( "a" ) );
        assertTrue( attr5.contains( "b" ) );
        assertTrue( attr5.contains( ( String ) null ) );
        assertTrue( attr5.contains( "d" ) );

        Attribute attr6 = new DefaultAttribute( "test" );

        nbAdded = attr6.add( "a", ( String ) null );
        assertEquals( 2, nbAdded );
        assertTrue( attr6.isHumanReadable() );
        assertTrue( attr6.contains( "a" ) );
        assertTrue( attr6.contains( ( String ) null ) );

        Attribute attr7 = new DefaultAttribute( "test" );

        attr7.add( "a", "b" );
        assertEquals( 2, attr7.size() );

        assertEquals( 1, attr7.add( "b", "c" ) );
        assertEquals( 3, attr7.size() );
        assertTrue( attr7.contains( "a", "b", "c" ) );
    }


    /**
     * Test method add( byte[]... )
     */
    @Test
    public void testAddByteArray() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );
        assertEquals( 0, attr1.size() );

        int nbAdded = attr1.add( ( byte[] ) null );
        assertEquals( 1, nbAdded );
        assertFalse( attr1.isHumanReadable() );
        assertTrue( Arrays.equals( NULL_BINARY_VALUE.getBytes(), attr1.getBytes() ) );
        assertEquals( 1, attr1.size() );

        Attribute attr2 = new DefaultAttribute( "test" );

        nbAdded = attr2.add( Strings.EMPTY_BYTES );
        assertEquals( 1, nbAdded );
        assertFalse( attr2.isHumanReadable() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, attr2.getBytes() ) );
        assertEquals( 1, attr2.size() );

        Attribute attr3 = new DefaultAttribute( "test" );

        nbAdded = attr3.add( BYTES1 );
        assertEquals( 1, nbAdded );
        assertFalse( attr3.isHumanReadable() );
        assertTrue( Arrays.equals( BYTES1, attr3.getBytes() ) );

        Attribute attr4 = new DefaultAttribute( "test" );

        nbAdded = attr4.add( BYTES1, BYTES2, BYTES3, BYTES4 );
        assertEquals( 4, nbAdded );
        assertFalse( attr4.isHumanReadable() );
        assertTrue( attr4.contains( BYTES1 ) );
        assertTrue( attr4.contains( BYTES2 ) );
        assertTrue( attr4.contains( BYTES3 ) );
        assertTrue( attr4.contains( BYTES4 ) );

        Attribute attr5 = new DefaultAttribute( "test" );

        nbAdded = attr5.add( BYTES1, BYTES2, ( byte[] ) null, BYTES3 );
        assertEquals( 4, nbAdded );
        assertFalse( attr5.isHumanReadable() );
        assertTrue( attr5.contains( BYTES1 ) );
        assertTrue( attr5.contains( BYTES2 ) );
        assertTrue( attr5.contains( ( byte[] ) null ) );
        assertTrue( attr5.contains( BYTES3 ) );

        Attribute attr6 = new DefaultAttribute( "test" );

        nbAdded = attr6.add( BYTES1, ( byte[] ) null );
        assertEquals( 2, nbAdded );
        assertFalse( attr6.isHumanReadable() );
        assertTrue( attr6.contains( "ab" ) );
        assertTrue( attr6.contains( ( byte[] ) null ) );
    }


    /**
     * Test method clear()
     */
    @Test
    public void testClear() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        assertEquals( 0, attr1.size() );

        attr1.add( ( String ) null );
        assertEquals( 1, attr1.size() );
        assertTrue( attr1.isHumanReadable() );
        attr1.clear();
        assertTrue( attr1.isHumanReadable() );
        assertEquals( 0, attr1.size() );

        Attribute attr2 = new DefaultAttribute( "test" );
        attr2.add( BYTES1, BYTES2 );
        assertEquals( 2, attr2.size() );
        assertFalse( attr2.isHumanReadable() );
        attr2.clear();
        assertFalse( attr2.isHumanReadable() );
        assertEquals( 0, attr2.size() );
    }


    /**
     * Test method contains( Value... )
     */
    @Test
    public void testContainsValueArray() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        assertEquals( 0, attr1.size() );
        assertFalse( attr1.contains( STR_VALUE1 ) );
        assertFalse( attr1.contains( NULL_STRING_VALUE ) );

        attr1.add( ( String ) null );
        assertEquals( 1, attr1.size() );
        assertTrue( attr1.contains( NULL_STRING_VALUE ) );

        attr1.remove( ( String ) null );
        assertFalse( attr1.contains( NULL_STRING_VALUE ) );
        assertEquals( 0, attr1.size() );

        attr1.add( "a", "b", "c" );
        assertEquals( 3, attr1.size() );
        assertTrue( attr1.contains( STR_VALUE1 ) );
        assertTrue( attr1.contains( STR_VALUE2 ) );
        assertTrue( attr1.contains( STR_VALUE3 ) );
        assertTrue( attr1.contains( STR_VALUE1, STR_VALUE3 ) );
        assertFalse( attr1.contains( STR_VALUE4 ) );
        assertFalse( attr1.contains( NULL_STRING_VALUE ) );
        assertTrue( attr1.contains( STR_VALUE1, BIN_VALUE2 ) );

        Attribute attr2 = new DefaultAttribute( "test" );
        assertEquals( 0, attr2.size() );
        assertFalse( attr2.contains( BYTES1 ) );
        assertFalse( attr2.contains( NULL_BINARY_VALUE ) );

        attr2.add( ( byte[] ) null );
        assertEquals( 1, attr2.size() );
        assertTrue( attr2.contains( NULL_BINARY_VALUE ) );

        attr2.remove( ( byte[] ) null );
        assertFalse( attr2.contains( NULL_BINARY_VALUE ) );
        assertEquals( 0, attr2.size() );

        attr2.add( BYTES1, BYTES2, BYTES3 );
        assertEquals( 3, attr2.size() );
        assertTrue( attr2.contains( BIN_VALUE1 ) );
        assertTrue( attr2.contains( BIN_VALUE2 ) );
        assertTrue( attr2.contains( BIN_VALUE3 ) );
        assertFalse( attr2.contains( NULL_BINARY_VALUE ) );
        assertTrue( attr2.contains( STR_VALUE2, BIN_VALUE1 ) );
    }


    /**
     * Test method contains( String... )
     */
    @Test
    public void testContainsStringArray() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        assertEquals( 0, attr1.size() );
        assertFalse( attr1.contains( "a" ) );
        assertFalse( attr1.contains( ( String ) null ) );

        attr1.add( ( String ) null );
        assertEquals( 1, attr1.size() );
        assertTrue( attr1.contains( ( String ) null ) );

        attr1.remove( ( String ) null );
        assertFalse( attr1.contains( ( String ) null ) );
        assertEquals( 0, attr1.size() );

        attr1.add( "a", "b", "c" );
        assertEquals( 3, attr1.size() );
        assertTrue( attr1.contains( "a" ) );
        assertTrue( attr1.contains( "b" ) );
        assertTrue( attr1.contains( "c" ) );
        assertFalse( attr1.contains( "e" ) );
        assertFalse( attr1.contains( ( String ) null ) );

        Attribute attr2 = new DefaultAttribute( "test" );
        assertEquals( 0, attr2.size() );
        assertFalse( attr2.contains( BYTES1 ) );
        assertFalse( attr2.contains( ( byte[] ) null ) );

        attr2.add( ( byte[] ) null );
        assertEquals( 1, attr2.size() );
        assertTrue( attr2.contains( ( byte[] ) null ) );

        attr2.remove( ( byte[] ) null );
        assertFalse( attr2.contains( ( byte[] ) null ) );
        assertEquals( 0, attr2.size() );

        attr2.add( BYTES1, BYTES2, BYTES3 );
        assertEquals( 3, attr2.size() );
        assertTrue( attr2.contains( "ab" ) );
        assertTrue( attr2.contains( "b" ) );
        assertTrue( attr2.contains( "c" ) );
        assertFalse( attr2.contains( ( String ) null ) );
    }


    /**
     * Test method contains( byte... )
     */
    @Test
    public void testContainsByteArray() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        assertEquals( 0, attr1.size() );
        assertFalse( attr1.contains( BYTES1 ) );
        assertFalse( attr1.contains( ( byte[] ) null ) );

        attr1.add( ( byte[] ) null );
        assertEquals( 1, attr1.size() );
        assertTrue( attr1.contains( ( byte[] ) null ) );

        attr1.remove( ( byte[] ) null );
        assertFalse( attr1.contains( ( byte[] ) null ) );
        assertEquals( 0, attr1.size() );

        attr1.add( BYTES1, BYTES2, BYTES3 );
        assertEquals( 3, attr1.size() );
        assertTrue( attr1.contains( BYTES1 ) );
        assertTrue( attr1.contains( BYTES2 ) );
        assertTrue( attr1.contains( BYTES3 ) );
        assertFalse( attr1.contains( BYTES4 ) );
        assertFalse( attr1.contains( ( byte[] ) null ) );

        Attribute attr2 = new DefaultAttribute( "test" );
        assertEquals( 0, attr2.size() );
        assertFalse( attr2.contains( "a" ) );
        assertFalse( attr2.contains( ( String ) null ) );

        attr2.add( ( String ) null );
        assertEquals( 1, attr2.size() );
        assertTrue( attr2.contains( ( String ) null ) );

        attr2.remove( ( String ) null );
        assertFalse( attr2.contains( ( String ) null ) );
        assertEquals( 0, attr2.size() );

        attr2.add( "ab", "b", "c" );
        assertEquals( 3, attr2.size() );
        assertTrue( attr2.contains( BYTES1 ) );
        assertTrue( attr2.contains( BYTES2 ) );
        assertTrue( attr2.contains( BYTES3 ) );
        assertFalse( attr2.contains( ( byte[] ) null ) );
    }


    /**
     * Test method get()
     */
    @Test
    public void testGet() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        attr1.add( ( String ) null );
        assertEquals( NULL_STRING_VALUE, attr1.get() );

        Attribute attr2 = new DefaultAttribute( "test" );

        attr2.add( "a", "b", "c" );
        assertEquals( "a", attr2.get().getString() );

        attr2.remove( "a" );
        assertEquals( "b", attr2.get().getString() );

        attr2.remove( "b" );
        assertEquals( "c", attr2.get().getString() );

        attr2.remove( "c" );
        assertNull( attr2.get() );

        Attribute attr3 = new DefaultAttribute( "test" );

        attr3.add( BYTES1, BYTES2, BYTES3 );
        assertTrue( Arrays.equals( BYTES1, attr3.get().getBytes() ) );

        attr3.remove( BYTES1 );
        assertTrue( Arrays.equals( BYTES2, attr3.get().getBytes() ) );

        attr3.remove( BYTES2 );
        assertTrue( Arrays.equals( BYTES3, attr3.get().getBytes() ) );

        attr3.remove( BYTES3 );
        assertNull( attr2.get() );
    }


    /**
     * Test method getAll()
     */
    @Test
    public void testIterator2() throws LdapException
    {
        Attribute attr = new DefaultAttribute( "test" );

        Iterator<Value<?>> iterator = attr.iterator();
        assertFalse( iterator.hasNext() );

        attr.add( NULL_STRING_VALUE );
        iterator = attr.iterator();
        assertTrue( iterator.hasNext() );

        Value<?> value = iterator.next();
        assertEquals( NULL_STRING_VALUE, value );

        attr.clear();
        iterator = attr.iterator();
        assertFalse( iterator.hasNext() );

        attr.add( "a", "b", "c" );
        iterator = attr.iterator();
        assertTrue( iterator.hasNext() );
        assertEquals( "a", iterator.next().getString() );
        assertEquals( "b", iterator.next().getString() );
        assertEquals( "c", iterator.next().getString() );
        assertFalse( iterator.hasNext() );
    }


    /**
     * Test method size()
     */
    @Test
    public void testSize() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        assertEquals( 0, attr1.size() );

        attr1.add( ( String ) null );
        assertEquals( 1, attr1.size() );

        Attribute attr2 = new DefaultAttribute( "test" );

        attr2.add( "a", "b" );
        assertEquals( 2, attr2.size() );

        attr2.clear();
        assertEquals( 0, attr2.size() );
    }


    /**
     * Test method remove( Value... )
     */
    @Test
    public void testRemoveValueArray() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        assertFalse( attr1.remove( STR_VALUE1 ) );
        assertFalse( attr1.remove( STR_VALUE1 ) );

        attr1.add( "a", "b", "c" );
        assertTrue( attr1.remove( STR_VALUE1 ) );
        assertEquals( 2, attr1.size() );

        assertTrue( attr1.remove( STR_VALUE2, STR_VALUE3 ) );
        assertEquals( 0, attr1.size() );

        assertFalse( attr1.remove( STR_VALUE4 ) );

        attr1.clear();
        attr1.add( "a", "b", "c" );
        assertFalse( attr1.remove( STR_VALUE2, STR_VALUE4 ) );
        assertEquals( 2, attr1.size() );

        attr1.clear();
        attr1.add( "a", ( String ) null, "b" );
        assertTrue( attr1.remove( NULL_STRING_VALUE, STR_VALUE1 ) );
        assertEquals( 1, attr1.size() );

        attr1.clear();
        attr1.add( "a", ( String ) null, "b" );
        attr1.add( BYTES3 );
        assertTrue( attr1.remove( NULL_STRING_VALUE, STR_VALUE1 ) );
        assertEquals( 1, attr1.size() );

        Attribute attr2 = new DefaultAttribute( "test" );

        assertFalse( attr2.remove( BIN_VALUE1 ) );

        attr2.clear();
        attr2.add( BYTES1, BYTES2, BYTES3 );
        assertTrue( attr2.remove( BIN_VALUE1 ) );
        assertEquals( 2, attr2.size() );

        assertTrue( attr2.remove( BIN_VALUE2, BIN_VALUE3 ) );
        assertEquals( 0, attr2.size() );

        assertFalse( attr2.remove( BIN_VALUE4 ) );

        attr2.clear();
        attr2.add( BYTES1, BYTES2, BYTES3 );
        assertFalse( attr2.remove( BIN_VALUE2, STR_VALUE4 ) );
        assertEquals( 2, attr2.size() );

        attr2.clear();
        attr2.add( BYTES1, ( byte[] ) null, BYTES3 );
        assertFalse( attr2.remove( NULL_STRING_VALUE, BIN_VALUE1 ) );
        assertEquals( 2, attr2.size() );

        attr2.clear();
        attr2.add( BYTES1, ( byte[] ) null, BYTES2 );
        attr2.add( "c" );
        assertEquals( 4, attr2.size() );
        assertFalse( attr2.remove( NULL_STRING_VALUE, BIN_VALUE1, STR_VALUE3 ) );
        assertEquals( 3, attr2.size() );
    }


    /**
     * Test method remove( byte... )
     */
    @Test
    public void testRemoveByteArray() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        assertFalse( attr1.remove( BYTES1 ) );

        attr1.add( BYTES1, BYTES2, BYTES3 );
        assertTrue( attr1.remove( BYTES1 ) );
        assertEquals( 2, attr1.size() );

        assertTrue( attr1.remove( BYTES2, BYTES3 ) );
        assertEquals( 0, attr1.size() );

        assertFalse( attr1.remove( BYTES4 ) );

        attr1.clear();
        attr1.add( BYTES1, BYTES2, BYTES3 );
        assertFalse( attr1.remove( BYTES3, BYTES4 ) );
        assertEquals( 2, attr1.size() );

        attr1.clear();
        attr1.add( BYTES1, ( byte[] ) null, BYTES2 );
        assertTrue( attr1.remove( ( byte[] ) null, BYTES1 ) );
        assertEquals( 1, attr1.size() );

        Attribute attr2 = new DefaultAttribute( "test" );

        attr2.add( "ab", "b", "c" );

        assertFalse( attr2.remove( ( byte[] ) null ) );
        assertTrue( attr2.remove( BYTES1, BYTES2 ) );
        assertFalse( attr2.remove( BYTES4 ) );
    }


    /**
     * Test method remove( String... )
     */
    @Test
    public void testRemoveStringArray() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        assertFalse( attr1.remove( "a" ) );

        attr1.add( "a", "b", "c" );
        assertTrue( attr1.remove( "a" ) );
        assertEquals( 2, attr1.size() );

        assertTrue( attr1.remove( "b", "c" ) );
        assertEquals( 0, attr1.size() );

        assertFalse( attr1.remove( "d" ) );

        attr1.clear();
        attr1.add( "a", "b", "c" );
        assertFalse( attr1.remove( "b", "e" ) );
        assertEquals( 2, attr1.size() );

        attr1.clear();
        attr1.add( "a", ( String ) null, "b" );
        assertTrue( attr1.remove( ( String ) null, "a" ) );
        assertEquals( 1, attr1.size() );

        Attribute attr2 = new DefaultAttribute( "test" );

        attr2.add( BYTES1, BYTES2, BYTES3 );

        assertFalse( attr2.remove( ( String ) null ) );
        assertTrue( attr2.remove( "ab", "c" ) );
        assertFalse( attr2.remove( "d" ) );
    }


    /**
     * Test method put( String... )
     */
    @Test
    public void testPutStringArray() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        int nbAdded = attr1.add( ( String ) null );
        assertEquals( 1, nbAdded );
        assertTrue( attr1.isHumanReadable() );
        assertEquals( NULL_STRING_VALUE, attr1.get() );

        Attribute attr2 = new DefaultAttribute( "test" );

        nbAdded = attr2.add( "" );
        assertEquals( 1, nbAdded );
        assertTrue( attr2.isHumanReadable() );
        assertEquals( "", attr2.getString() );

        Attribute attr3 = new DefaultAttribute( "test" );

        nbAdded = attr3.add( "t" );
        assertEquals( 1, nbAdded );
        assertTrue( attr3.isHumanReadable() );
        assertEquals( "t", attr3.getString() );

        Attribute attr4 = new DefaultAttribute( "test" );

        nbAdded = attr4.add( "a", "b", "c", "d" );
        assertEquals( 4, nbAdded );
        assertTrue( attr4.isHumanReadable() );
        assertTrue( attr4.contains( "a" ) );
        assertTrue( attr4.contains( "b" ) );
        assertTrue( attr4.contains( "c" ) );
        assertTrue( attr4.contains( "d" ) );

        Attribute attr5 = new DefaultAttribute( "test" );

        nbAdded = attr5.add( "a", "b", ( String ) null, "d" );
        assertEquals( 4, nbAdded );
        assertTrue( attr5.isHumanReadable() );
        assertTrue( attr5.contains( "a" ) );
        assertTrue( attr5.contains( "b" ) );
        assertTrue( attr5.contains( ( String ) null ) );
        assertTrue( attr5.contains( "d" ) );

        Attribute attr6 = new DefaultAttribute( "test" );

        nbAdded = attr6.add( "a", ( String ) null );
        assertEquals( 2, nbAdded );
        assertTrue( attr6.isHumanReadable() );
        assertTrue( attr6.contains( "a" ) );
        assertTrue( attr6.contains( ( String ) null ) );
    }


    /**
     * Test method put( byte[]... )
     */
    @Test
    public void testPutByteArray() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        int nbAdded = attr1.add( ( byte[] ) null );
        assertEquals( 1, nbAdded );
        assertFalse( attr1.isHumanReadable() );
        assertTrue( Arrays.equals( NULL_BINARY_VALUE.getBytes(), attr1.getBytes() ) );

        Attribute attr2 = new DefaultAttribute( "test" );

        nbAdded = attr2.add( Strings.EMPTY_BYTES );
        assertEquals( 1, nbAdded );
        assertFalse( attr2.isHumanReadable() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, attr2.getBytes() ) );

        Attribute attr3 = new DefaultAttribute( "test" );

        nbAdded = attr3.add( BYTES1 );
        assertEquals( 1, nbAdded );
        assertFalse( attr3.isHumanReadable() );
        assertTrue( Arrays.equals( BYTES1, attr3.getBytes() ) );

        Attribute attr4 = new DefaultAttribute( "test" );

        nbAdded = attr4.add( BYTES1, BYTES2 );
        assertEquals( 2, nbAdded );
        assertFalse( attr4.isHumanReadable() );
        assertTrue( attr4.contains( BYTES1 ) );
        assertTrue( attr4.contains( BYTES2 ) );

        nbAdded = attr4.add( BYTES3, BYTES4 );
        assertEquals( 2, nbAdded );
        assertFalse( attr4.isHumanReadable() );
        assertTrue( attr4.contains( BYTES3 ) );
        assertTrue( attr4.contains( BYTES4 ) );

        Attribute attr5 = new DefaultAttribute( "test" );

        nbAdded = attr5.add( BYTES1, BYTES2, ( byte[] ) null, BYTES3 );
        assertEquals( 4, nbAdded );
        assertFalse( attr5.isHumanReadable() );
        assertTrue( attr5.contains( BYTES1 ) );
        assertTrue( attr5.contains( BYTES2 ) );
        assertTrue( attr5.contains( ( byte[] ) null ) );
        assertTrue( attr5.contains( BYTES3 ) );

        Attribute attr6 = new DefaultAttribute( "test" );

        nbAdded = attr6.add( BYTES1, ( byte[] ) null );
        assertEquals( 2, nbAdded );
        assertFalse( attr6.isHumanReadable() );
        assertTrue( attr6.contains( "ab" ) );
        assertTrue( attr6.contains( ( byte[] ) null ) );
    }


    /**
     * Test method put( Value... )
     */
    @Test
    public void testPutValueArray() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        assertEquals( 0, attr1.size() );

        attr1.add( NULL_STRING_VALUE );
        assertEquals( 1, attr1.size() );
        assertTrue( attr1.contains( NULL_STRING_VALUE ) );

        attr1.clear();
        attr1.add( STR_VALUE1, STR_VALUE2, STR_VALUE3 );
        assertEquals( 3, attr1.size() );
        assertTrue( attr1.contains( STR_VALUE1 ) );
        assertTrue( attr1.contains( STR_VALUE2 ) );
        assertTrue( attr1.contains( STR_VALUE3 ) );

        attr1.clear();
        attr1.add( STR_VALUE1, NULL_STRING_VALUE, STR_VALUE3 );
        assertEquals( 3, attr1.size() );
        assertTrue( attr1.contains( STR_VALUE1 ) );
        assertTrue( attr1.contains( NULL_STRING_VALUE ) );
        assertTrue( attr1.contains( STR_VALUE3 ) );

        attr1.clear();
        attr1.add( STR_VALUE1, NULL_STRING_VALUE, BIN_VALUE3 );
        assertEquals( 3, attr1.size() );
        assertTrue( attr1.contains( STR_VALUE1 ) );
        assertTrue( attr1.contains( NULL_STRING_VALUE ) );
        assertTrue( attr1.contains( STR_VALUE3 ) );

        Attribute attr2 = new DefaultAttribute( "test" );
        assertEquals( 0, attr2.size() );

        attr2.add( NULL_BINARY_VALUE );
        assertEquals( 1, attr2.size() );
        assertTrue( attr2.contains( NULL_BINARY_VALUE ) );

        attr2.clear();
        attr2.add( BIN_VALUE1, BIN_VALUE2, BIN_VALUE3 );
        assertEquals( 3, attr2.size() );
        assertTrue( attr2.contains( BIN_VALUE1 ) );
        assertTrue( attr2.contains( BIN_VALUE2 ) );
        assertTrue( attr2.contains( BIN_VALUE3 ) );

        attr2.clear();
        attr2.add( BIN_VALUE1, NULL_BINARY_VALUE, STR_VALUE3 );
        assertEquals( 3, attr2.size() );
        assertTrue( attr2.contains( BIN_VALUE1 ) );
        assertTrue( attr2.contains( NULL_BINARY_VALUE ) );
        assertTrue( attr2.contains( BIN_VALUE3 ) );
    }


    /**
     * Test method toString()
     */
    @Test
    public void testToString() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        assertEquals( "test: (null)", attr1.toString() );

        attr1.add( "a" );
        assertEquals( "test: a", attr1.toString() );

        attr1.add( "b" );
        assertEquals( "test: a\ntest: b", attr1.toString() );

        Attribute attr2 = new DefaultAttribute( "test" );

        attr2.add( BYTES1 );
        assertEquals( "test: 0x61 0x62 ", attr2.toString() );

        attr2.add( BYTES3 );
        assertEquals( "test: 0x61 0x62 \ntest: 0x63 ", attr2.toString() );
    }


    /**
     * Test method hashCode()
     */
    @Test
    public void testHashCode() throws InvalidAttributeValueException, LdapException
    {
        Attribute attr = new DefaultAttribute();
        assertEquals( 37, attr.hashCode() );

        Attribute attr1 = new DefaultAttribute( "test" );
        Attribute attr2 = new DefaultAttribute( "test" );

        assertEquals( attr1.hashCode(), attr2.hashCode() );

        attr1.add( "a", "b", "c" );
        attr2.add( "a", "b", "c" );
        assertEquals( attr1.hashCode(), attr2.hashCode() );

        attr1.add( "d" );
        attr2.add( "d" );
        assertEquals( attr1.hashCode(), attr2.hashCode() );

        attr1.add( NULL_STRING_VALUE );
        attr2.add( NULL_STRING_VALUE );
        assertEquals( attr1.hashCode(), attr2.hashCode() );

        // Order mess up the hashCode
        attr1.clear();
        attr2.clear();
        attr1.add( "a", "b", "c" );
        attr2.add( "c", "b", "a" );
        assertNotSame( attr1.hashCode(), attr2.hashCode() );

        Attribute attr3 = new DefaultAttribute( "test" );
        Attribute attr4 = new DefaultAttribute( "test" );

        attr3.add( BYTES1, BYTES2 );
        attr4.add( BYTES1, BYTES2 );
        assertEquals( attr3.hashCode(), attr4.hashCode() );

        attr3.add( BYTES3 );
        attr4.add( BYTES3 );
        assertEquals( attr3.hashCode(), attr4.hashCode() );

        attr3.add( NULL_BINARY_VALUE );
        attr4.add( NULL_BINARY_VALUE );
        assertEquals( attr3.hashCode(), attr4.hashCode() );

        // Order mess up the hashCode
        attr3.clear();
        attr4.clear();
        attr3.add( BYTES1, BYTES2 );
        attr4.add( BYTES2, BYTES1 );
        assertNotSame( attr3.hashCode(), attr4.hashCode() );
    }


    /**
     * Test method testEquals()
     */
    @Test
    public void testEquals() throws LdapException
    {
        Attribute attr1 = new DefaultAttribute( "test" );

        assertFalse( attr1.equals( null ) );

        Attribute attr2 = new DefaultAttribute( "test" );

        assertTrue( attr1.equals( attr2 ) );

        attr2.setUpId( "TEST" );
        assertTrue( attr1.equals( attr2 ) );

        attr1.setUpId( "tset" );
        assertFalse( attr1.equals( attr2 ) );

        attr1.setUpId( "TEST" );
        assertTrue( attr1.equals( attr2 ) );

        attr1.add( "a", "b", "c" );
        attr2.add( "c", "b", "a" );
        assertTrue( attr1.equals( attr2 ) );

        assertTrue( attr1.equals( attr2 ) );

        Attribute attr3 = new DefaultAttribute( "test" );
        Attribute attr4 = new DefaultAttribute( "test" );

        attr3.add( NULL_BINARY_VALUE );
        attr4.add( NULL_BINARY_VALUE );
        assertTrue( attr3.equals( attr4 ) );

        Attribute attr5 = new DefaultAttribute( "test" );
        Attribute attr6 = new DefaultAttribute( "test" );

        attr5.add( NULL_BINARY_VALUE );
        attr6.add( NULL_STRING_VALUE );
        assertFalse( attr5.equals( attr6 ) );

        Attribute attr7 = new DefaultAttribute( "test" );
        Attribute attr8 = new DefaultAttribute( "test" );

        attr7.add( "a" );
        attr8.add( BYTES2 );
        assertFalse( attr7.equals( attr8 ) );

        Attribute attr9 = new DefaultAttribute( "test" );
        Attribute attr10 = new DefaultAttribute( "test" );

        attr7.add( "a" );
        attr7.add( BYTES2 );
        attr8.add( "a", "b" );
        assertTrue( attr9.equals( attr10 ) );
    }


    /**
     * Test method testClone()
     */
    @Test
    public void testClone() throws LdapException
    {
        Attribute attr = new DefaultAttribute( "test" );

        Attribute clone = attr.clone();

        assertEquals( attr, clone );
        attr.setUpId( "new" );
        assertEquals( "test", clone.getId() );

        attr.add( "a", ( String ) null, "b" );
        clone = attr.clone();
        assertEquals( attr, clone );

        attr.remove( "a" );
        assertNotSame( attr, clone );

        clone = attr.clone();
        assertEquals( attr, clone );
    }


    /**
     * Test the serialization of a complete client attribute
     */
    @Test
    public void testSerializeCompleteAttribute() throws LdapException, IOException, ClassNotFoundException
    {
        DefaultAttribute dca = new DefaultAttribute( "CommonName" );
        dca.setUpId( "CN" );
        dca.add( "test1", "test2" );

        DefaultAttribute dcaSer = deserializeValue( serializeValue( dca ) );
        assertEquals( dca.toString(), dcaSer.toString() );
        assertEquals( "cn", dcaSer.getId() );
        assertEquals( "CN", dcaSer.getUpId() );
        assertEquals( "test1", dcaSer.getString() );
        assertTrue( dcaSer.contains( "test2", "test1" ) );
        assertTrue( dcaSer.isHumanReadable() );
    }


    /**
     * Test the serialization of a client attribute with no value
     */
    @Test
    public void testSerializeAttributeWithNoValue() throws LdapException, IOException, ClassNotFoundException
    {
        DefaultAttribute dca = new DefaultAttribute( "CommonName" );
        dca.setUpId( "CN" );

        DefaultAttribute dcaSer = deserializeValue( serializeValue( dca ) );
        assertEquals( dca.toString(), dcaSer.toString() );
        assertEquals( "cn", dcaSer.getId() );
        assertEquals( "CN", dcaSer.getUpId() );
        assertEquals( 0, dcaSer.size() );
        assertFalse( dcaSer.isHumanReadable() );
    }


    /**
     * Test the serialization of a client attribute with a null value
     */
    @Test
    public void testSerializeAttributeNullValue() throws LdapException, IOException, ClassNotFoundException
    {
        DefaultAttribute dca = new DefaultAttribute( "CommonName" );
        dca.setUpId( "CN" );
        dca.add( ( String ) null );

        DefaultAttribute dcaSer = deserializeValue( serializeValue( dca ) );
        assertEquals( dca.toString(), dcaSer.toString() );
        assertEquals( "cn", dcaSer.getId() );
        assertEquals( "CN", dcaSer.getUpId() );
        assertEquals( "", dcaSer.getString() );
        assertEquals( 1, dcaSer.size() );
        assertTrue( dcaSer.contains( ( String ) null ) );
        assertTrue( dcaSer.isHumanReadable() );
    }


    /**
     * Test the serialization of a client attribute with a binary value
     */
    @Test
    public void testSerializeAttributeBinaryValue() throws LdapException, IOException, ClassNotFoundException
    {
        DefaultAttribute dca = new DefaultAttribute( "UserPassword" );
        byte[] password = Strings.getBytesUtf8( "secret" );
        dca.add( password );

        DefaultAttribute dcaSer = deserializeValue( serializeValue( dca ) );
        assertEquals( dca.toString(), dcaSer.toString() );
        assertEquals( "userpassword", dcaSer.getId() );
        assertEquals( "UserPassword", dcaSer.getUpId() );
        assertTrue( Arrays.equals( dca.getBytes(), dcaSer.getBytes() ) );
        assertEquals( 1, dcaSer.size() );
        assertTrue( dcaSer.contains( password ) );
        assertFalse( dcaSer.isHumanReadable() );
    }
}
