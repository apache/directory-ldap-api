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

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MutableAttributeType;
import org.apache.directory.api.ldap.model.schema.MutableMatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.PrepareString;
import org.apache.directory.api.ldap.model.schema.comparators.ByteArrayComparator;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.OctetStringSyntaxChecker;
import org.apache.directory.api.util.Strings;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Tests that the Value class works properly as expected.
 *
 * Some notes while conducting tests:
 *
 * <ul>
 *   <li>comparing values with different types - how does this behave</li>
 *   <li>exposing access to at from value or to a comparator?</li>
 * </ul>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class BinaryValueAttributeTypeTest
{
    private LdapSyntax s;
    private MutableAttributeType at;
    private MutableMatchingRule mr;

    private static final byte[] BYTES1 = new byte[]
        { 0x01, 0x02, 0x03, 0x04 };
    private static final byte[] BYTES2 = new byte[]
        { ( byte ) 0x81, ( byte ) 0x82, ( byte ) 0x83, ( byte ) 0x84 };


    /**
     * Initialize an AttributeType and the associated MatchingRule
     * and Syntax
     */
    @Before
    public void initAT()
    {
        s = EntryUtils.syntaxFactory( "1.1.1.1", false );
        s.setSyntaxChecker( OctetStringSyntaxChecker.INSTANCE );
        mr = EntryUtils.matchingRuleFactory( "1.1.2.1" );
        mr.setSyntax( s );

        mr.setLdapComparator( new ByteArrayComparator( "1.1.1" ) );
        mr.setNormalizer( new Normalizer( "1.1.1" )
        {
            public static final long serialVersionUID = 1L;

            public String normalize( String value ) throws LdapException
            {
                return normalize( value, PrepareString.AssertionType.ATTRIBUTE_VALUE );
            }
            

            public String normalize( String value, PrepareString.AssertionType assertionType ) throws LdapException
            {
                byte[] val = Strings.getBytesUtf8( value );
                // each byte will be changed to be > 0, and spaces will be trimmed
                byte[] newVal = new byte[val.length];
                int i = 0;

                for ( byte b : val )
                {
                    newVal[i++] = ( byte ) ( b & 0x007F );
                }

                return Strings.utf8ToString( Strings.trim( newVal ) );
            }
        } );

        at = new MutableAttributeType( "1.1.3.1" );
        at.setEquality( mr );
        at.setOrdering( mr );
        at.setSubstring( mr );
        at.setSyntax( s );
    }


    /**
     * Serialize a Value
     */
    private ByteArrayOutputStream serializeValue( Value value ) throws IOException
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
     * Deserialize a Value
     */
    private Value deserializeValue( ByteArrayOutputStream out, AttributeType at ) throws IOException,
        ClassNotFoundException
    {
        ObjectInputStream oIn = null;
        ByteArrayInputStream in = new ByteArrayInputStream( out.toByteArray() );

        try
        {
            oIn = new ObjectInputStream( in );

            Value value = Value.createValue( ( AttributeType ) null );
            value.readExternal( oIn );

            return value;
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
     * Test the constructor with bad AttributeType
     * @throws LdapInvalidAttributeValueException 
     */
    @Test
    public void testBadConstructor()
    {
        // create a AT with no syntax
        MutableAttributeType attribute = new MutableAttributeType( "1.1.3.1" );

        Value value = Value.createValue( attribute );
        assertTrue( value.isHumanReadable() );
    }


    /**
     * Test the constructor with a null value
     */
    @Test
    public void testServerBinaryValueNullValue() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getBytesAttributeType();

        Value value = new Value( attribute, ( byte[] ) null );

        assertNull( value.getBytes() );
        assertTrue( value.isNull() );
    }


    /**
     * Test the constructor with an empty value
     */
    @Test
    public void testServerBinaryValueEmptyValue() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getBytesAttributeType();

        Value value = new Value( attribute, Strings.EMPTY_BYTES );

        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, value.getBytes() ) );
        assertFalse( value.isNull() );
    }


    /**
     * Test the constructor with a value
     * @throws LdapInvalidAttributeValueException 
     */
    @Test
    public void testServerBinaryValueNoValue() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getBytesAttributeType();
        byte[] val = new byte[]
            { 0x01 };
        Value bv = new Value( attribute, val );
        assertTrue( Arrays.equals( val, bv.getBytes() ) );
        assertFalse( bv.isNull() );
    }


    /**
     * Test the constructor with a value
     */
    @Test
    public void testServerBinaryValue() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getBytesAttributeType();
        byte[] val = new byte[]
            { 0x01 };
        Value value = new Value( attribute, val );

        assertTrue( Arrays.equals( val, value.getBytes() ) );
        assertFalse( value.isNull() );
        assertTrue( Arrays.equals( val, value.getBytes() ) );
    }


    /**
     * Test the clone method
     */
    @Test
    public void testClone() throws LdapException
    {
        AttributeType at1 = EntryUtils.getBytesAttributeType();
        Value bv = new Value( at1, ( byte[] ) null );
        Value bv1 = bv.clone();

        assertEquals( bv, bv1 );

        bv = new Value( Strings.EMPTY_BYTES );

        assertNotSame( bv, bv1 );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getBytes() ) );

        bv = new Value( at, BYTES2 );
        bv1 = bv.clone();

        assertEquals( bv, bv1 );
    }


    /**
     * Test the equals method
     */
    @Test
    public void testEquals() throws LdapInvalidAttributeValueException
    {
        AttributeType at1 = EntryUtils.getBytesAttributeType();

        Value value1 = new Value( at1, new byte[]
            { 0x01, ( byte ) 0x02 } );
        Value value2 = new Value( at1, new byte[]
            { 0x01, ( byte ) 0x02 } );
        Value value3 = new Value( at1, new byte[]
            { 0x01, ( byte ) 0x82 } );
        Value value4 = new Value( at1, new byte[]
            { 0x01 } );
        Value value5 = new Value( at1, ( byte[] ) null );
        Value value6 = new Value( at, new byte[]
            { 0x01, 0x02 } );
        Value value7 = new Value( EntryUtils.getIA5StringAttributeType(),
            "test" );

        assertTrue( value1.equals( value1 ) );
        assertTrue( value1.equals( value2 ) );
        assertFalse( value1.equals( value3 ) );
        assertFalse( value1.equals( value4 ) );
        assertFalse( value1.equals( value5 ) );
        assertFalse( value1.equals( "test" ) );
        assertFalse( value1.equals( null ) );

        assertTrue( value1.equals( value6 ) );
        assertFalse( value1.equals( value7 ) );
    }


    /**
     * Test the getNormValue method
     */
    @Test
    public void testGetNormalizedValue() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getBytesAttributeType();

        Value value = new Value( attribute, ( byte[] ) null );
        assertNull( value.getBytes() );

        value = new Value( attribute, Strings.EMPTY_BYTES );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, value.getBytes() ) );

        value = new Value( attribute, BYTES2 );
        assertTrue( Arrays.equals( BYTES2, value.getBytes() ) );
    }


    /**
     * Test the getNormValue method
     */
    @Test
    public void testGetNormalizedValueCopy() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getBytesAttributeType();

        Value value = new Value( attribute, ( byte[] ) null );
        assertNull( value.getBytes() );

        value = new Value( attribute, Strings.EMPTY_BYTES );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, value.getBytes() ) );

        value = new Value( attribute, BYTES2 );
        assertTrue( Arrays.equals( BYTES2, value.getBytes() ) );
    }


    /**
     * Test the getNormValue method
     */
    @Test
    public void testGetNormalizedValueReference() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getBytesAttributeType();

        Value value = new Value( attribute, ( byte[] ) null );
        assertNull( value.getBytes() );

        value = new Value( attribute, Strings.EMPTY_BYTES );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, value.getBytes() ) );

        value = new Value( attribute, BYTES2 );
        assertTrue( Arrays.equals( BYTES2, value.getBytes() ) );
    }


    /**
     * Test the getAttributeType method
     * @throws LdapInvalidAttributeValueException 
     */
    @Test
    public void testgetAttributeType() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getBytesAttributeType();
        Value sbv = Value.createValue( attribute );

        assertEquals( attribute, sbv.getAttributeType() );
    }


    /**
     * Test the isValid method
     * 
     * The SyntaxChecker does not accept values longer than 5 chars.
     */
    @Test
    public void testIsValid() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getBytesAttributeType();

        new Value( attribute, ( byte[] ) null );
        new Value( attribute, Strings.EMPTY_BYTES );
        new Value( attribute, new byte[]
            { 0x01, 0x02 } );

        try
        {
            new Value( attribute, new byte[]
                { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 } );
            fail();
        }
        catch ( LdapInvalidAttributeValueException liave )
        {
            assertTrue( true );
        }
    }


    /**
     * Tests to make sure the hashCode method is working properly.
     * @throws Exception on errors
     */
    @Test
    public void testHashCode() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getBytesAttributeType();
        Value v0 = new Value( attribute, new byte[]
            { 0x01, 0x02 } );
        Value v1 = new Value( attribute, new byte[]
            { ( byte ) 0x81, ( byte ) 0x82 } );
        Value v2 = new Value( attribute, new byte[]
            { 0x01, 0x02 } );
        assertNotSame( v0.hashCode(), v1.hashCode() );
        assertNotSame( v1.hashCode(), v2.hashCode() );
        assertEquals( v0.hashCode(), v2.hashCode() );
        assertNotSame( v0, v1 );
        assertEquals( v0, v2 );
        assertNotSame( v1, v2 );

        Value v3 = new Value( attribute, new byte[]
            { 0x01, 0x03 } );
        assertFalse( v3.equals( v0 ) );
        assertFalse( v3.equals( v1 ) );
        assertFalse( v3.equals( v2 ) );
    }


    /**
     * Test the instanceOf method
     */
    @Test
    public void testInstanceOf() throws LdapException
    {
        AttributeType attribute = EntryUtils.getBytesAttributeType();
        Value sbv = Value.createValue( attribute );

        assertTrue( sbv.isInstanceOf( attribute ) );

        attribute = EntryUtils.getIA5StringAttributeType();

        assertFalse( sbv.isInstanceOf( attribute ) );
    }


    /**
     * Test the normalize method
     */
    @Test
    public void testNormalize() throws LdapException
    {
        AttributeType attribute = EntryUtils.getBytesAttributeType();
        Value bv = Value.createValue( attribute );

        assertEquals( null, bv.getBytes() );

        bv = new Value( attribute, Strings.EMPTY_BYTES );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getBytes() ) );

        bv = new Value( attribute, BYTES2 );
        assertTrue( Arrays.equals( BYTES2, bv.getBytes() ) );
    }


    /**
     * Test the compareTo method
     */
    @Test
    public void testCompareTo() throws LdapInvalidAttributeValueException
    {
        AttributeType at1 = EntryUtils.getBytesAttributeType();
        Value v0 = new Value( at1, BYTES1 );
        Value v1 = new Value( at1, BYTES1 );

        assertEquals( 0, v0.compareTo( v1 ) );
        assertEquals( 0, v1.compareTo( v0 ) );

        Value v2 = new Value( at1, ( byte[] ) null );

        assertEquals( 1, v0.compareTo( v2 ) );
        assertEquals( -1, v2.compareTo( v0 ) );
    }


    /**
     * Test serialization of a Value which normalized value is the same
     * than the value
     */
    @Test
    public void testNormalizedBinarySameValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] v1 = Strings.getBytesUtf8( "Test   Test" );

        // First check with a value which will be normalized
        Value sbv = new Value( at, v1 );

        Value sbvSer = deserializeValue( serializeValue( sbv ), at );

        assertEquals( sbv, sbvSer );
    }


    /**
     * Test serialization of a Value which does not have a normalized value
     */
    @Test
    public void testNoNormalizedBinaryValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] v1 = Strings.getBytesUtf8( "test" );
        byte[] v1Norm = Strings.getBytesUtf8( "test" );

        // First check with a value which will be normalized
        Value sbv = new Value( at, v1 );

        byte[] normalized = sbv.getBytes();

        assertTrue( Arrays.equals( v1Norm, normalized ) );
        assertTrue( Arrays.equals( v1, sbv.getBytes() ) );

        Value sbvSer = deserializeValue( serializeValue( sbv ), at );

        assertEquals( sbv, sbvSer );
    }


    /**
     * Test serialization of a null Value
     */
    @Test
    public void testNullBinaryValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        // First check with a value which will be normalized
        Value sbv = Value.createValue( at );

        byte[] normalized = sbv.getBytes();

        assertEquals( null, normalized );
        assertEquals( "", sbv.getValue() );

        Value sbvSer = deserializeValue( serializeValue( sbv ), at );

        assertEquals( sbv, sbvSer );
    }


    /**
     * Test serialization of an empty Value
     */
    @Test
    public void testEmptyBinaryValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        // First check with a value which will be normalized
        Value sbv = new Value( at, Strings.EMPTY_BYTES );

        byte[] normalized = sbv.getBytes();

        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, normalized ) );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, sbv.getBytes() ) );

        Value sbvSer = deserializeValue( serializeValue( sbv ), at );

        assertEquals( sbv, sbvSer );
    }


    /**
     * Test serialization of a Value which is the same than the value
     */
    @Test
    public void testSameNormalizedBinaryValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] v1 = Strings.getBytesUtf8( "test" );
        byte[] v1Norm = Strings.getBytesUtf8( "test" );

        // First check with a value which will be normalized
        Value sbv = new Value( at, v1 );

        byte[] normalized = sbv.getBytes();

        assertTrue( Arrays.equals( v1Norm, normalized ) );
        assertTrue( Arrays.equals( v1, sbv.getBytes() ) );

        Value sbvSer = deserializeValue( serializeValue( sbv ), at );

        assertEquals( sbv, sbvSer );
    }
}