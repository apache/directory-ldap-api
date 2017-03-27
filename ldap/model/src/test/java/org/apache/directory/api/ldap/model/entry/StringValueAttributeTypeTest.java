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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.ldap.model.schema.comparators.StringComparator;
import org.apache.directory.api.ldap.model.schema.normalizers.DeepTrimToLowerNormalizer;
import org.apache.directory.api.ldap.model.schema.normalizers.NoOpNormalizer;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.OctetStringSyntaxChecker;
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
public class StringValueAttributeTypeTest
{
    private EntryUtils.S s;
    private EntryUtils.AT at;
    private EntryUtils.MR mr;


    /**
     * Initialize an AttributeType and the associated MatchingRule 
     * and Syntax
     */
    @Before
    public void initAT()
    {
        s = new EntryUtils.S( "1.1.1.1", true );
        s.setSyntaxChecker( OctetStringSyntaxChecker.INSTANCE );
        mr = new EntryUtils.MR( "1.1.2.1" );
        mr.setSyntax( s );
        mr.setLdapComparator( new StringComparator( "1.1.2.1" ) );
        mr.setNormalizer( new DeepTrimToLowerNormalizer( "1.1.2.1" ) );
        at = new EntryUtils.AT( "1.1.3.1" );
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
    private Value deserializeValue( ByteArrayOutputStream out ) throws IOException, ClassNotFoundException
    {
        ObjectInputStream oIn = null;
        ByteArrayInputStream in = new ByteArrayInputStream( out.toByteArray() );

        try
        {
            oIn = new ObjectInputStream( in );

            Value value = Value.createValue( at );

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
     * Test the constructor with a null value
     */
    @Test
    public void testClientStringValueNullValue() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getIA5StringAttributeType();

        Value value = new Value( attribute, (String)null );

        assertNull( value.getValue() );
        assertTrue( value.isNull() );
    }


    /**
     * Test the getNormValue method
     */
    @Test
    public void testGetNormalizedValue() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getIA5StringAttributeType();

        Value sv = new Value( attribute, (String)null );

        assertTrue( sv.isSchemaAware() );
        assertNull( sv.getValue() );
        assertTrue( sv.isSchemaAware() );

        sv = new Value( attribute, "" );
        assertTrue( sv.isSchemaAware() );
        assertEquals( 0, sv.compareTo( "  " ) );
        assertTrue( sv.isSchemaAware() );

        sv = new Value( attribute, "TEST" );
        assertTrue( sv.isSchemaAware() );
        assertEquals( 0, sv.compareTo( " test " ) );
    }


    /**
     * Test the isValid method
     * 
     * The SyntaxChecker does not accept values longer than 5 chars.
     */
    @Test
    public void testIsValid() throws LdapInvalidAttributeValueException
    {
        AttributeType attribute = EntryUtils.getIA5StringAttributeType();

        new Value( attribute, (String)null );
        new Value( attribute, "" );
        new Value( attribute, "TEST" );

        try
        {
            new Value( attribute, "testlong" );
            fail();
        }
        catch ( LdapInvalidAttributeValueException liave )
        {
            assertTrue( true );
        }
    }


    /**
     * Test the normalize method
     */
    @Test
    public void testApply() throws LdapException
    {
        AttributeType attribute = EntryUtils.getIA5StringAttributeType();
        Value sv = Value.createValue( attribute );

        sv = new Value( at, sv );
        assertEquals( 0, sv.compareTo( ( String ) null ) );

        sv = new Value( attribute, "" );
        sv = new Value( at, sv );
        assertEquals( 0, sv.compareTo( "  " ) );

        sv = new Value( attribute, "  A   TEST  " );
        assertEquals( 0, sv.compareTo( " a  test " ) );
    }


    /**
     * Test the instanceOf method
     */
    @Test
    public void testInstanceOf() throws LdapException
    {
        AttributeType attribute = EntryUtils.getIA5StringAttributeType();
        Value ssv = Value.createValue( attribute );

        assertTrue( ssv.isInstanceOf( attribute ) );

        attribute = EntryUtils.getBytesAttributeType();

        assertFalse( ssv.isInstanceOf( attribute ) );
    }


    /**
     * Test the getAttributeType method
     */
    @Test
    public void testgetAttributeType()
    {
        AttributeType attribute = EntryUtils.getIA5StringAttributeType();
        Value ssv = Value.createValue( attribute );

        assertEquals( attribute, ssv.getAttributeType() );
    }


    /**
     * Test the equals method
     */
    @Test
    public void testEquals() throws LdapInvalidAttributeValueException
    {
        AttributeType at1 = EntryUtils.getIA5StringAttributeType();
        AttributeType at2 = EntryUtils.getBytesAttributeType();

        Value value1 = new Value( at1, "test" );
        Value value2 = new Value( at1, "test" );
        Value value3 = new Value( at1, "TEST" );
        Value value4 = new Value( at1, "tes" );
        Value value5 = new Value( at1, (byte[])null );
        Value valueBytes = new Value( at2, new byte[]
            { 0x01 } );
        Value valueString = new Value( at, "test" );

        assertTrue( value1.equals( value1 ) );
        assertTrue( value1.equals( value2 ) );
        assertTrue( value1.equals( value3 ) );
        assertFalse( value1.equals( value4 ) );
        assertFalse( value1.equals( value5 ) );
        assertTrue( value1.equals( "test" ) );
        assertFalse( value1.equals( null ) );

        assertFalse( value1.equals( valueString ) );
        assertFalse( value1.equals( valueBytes ) );
    }


    /**
     * Test the constructor with bad AttributeType
     */
    @Test
    public void testBadConstructor()
    {
        // create a AT without any syntax
        AttributeType attribute = new EntryUtils.AT( "1.1.3.1" );

        Value value = Value.createValue( attribute );
        
        assertTrue( value.isHumanReadable() );
    }


    /**
     * Tests to make sure the hashCode method is working properly.
     * @throws Exception on errors
     */
    @Test
    public void testHashCode() throws LdapInvalidAttributeValueException
    {
        AttributeType at1 = EntryUtils.getCaseIgnoringAttributeNoNumbersType();
        Value v0 = new Value( at1, "Alex" );
        Value v1 = new Value( at1, "ALEX" );
        Value v2 = new Value( at1, "alex" );

        assertEquals( v0.hashCode(), v1.hashCode() );
        assertEquals( v0.hashCode(), v2.hashCode() );
        assertEquals( v1.hashCode(), v2.hashCode() );

        assertEquals( v0, v1 );
        assertEquals( v0, v2 );
        assertEquals( v1, v2 );

        Value v3 = new Value( at1, "Timber" );

        assertNotSame( v0.hashCode(), v3.hashCode() );

        Value v4 = new Value( at, "Alex" );

        assertNotSame( v0.hashCode(), v4.hashCode() );
    }


    /**
     * Test the compareTo method
     */
    @Test
    public void testCompareTo() throws LdapInvalidAttributeValueException
    {
        AttributeType at1 = EntryUtils.getCaseIgnoringAttributeNoNumbersType();
        Value v0 = new Value( at1, "Alex" );
        Value v1 = new Value( at1, "ALEX" );

        assertEquals( 0, v0.compareTo( v1 ) );
        assertEquals( 0, v1.compareTo( v0 ) );

        Value v2 = new Value( at1, (String)null );

        assertEquals( 1, v0.compareTo( v2 ) );
        assertEquals( -1, v2.compareTo( v0 ) );
    }


    /**
     * Test the clone method
     */
    @Test
    public void testClone() throws LdapException
    {
        AttributeType at1 = EntryUtils.getCaseIgnoringAttributeNoNumbersType();
        Value sv = new Value( at1, "Test" );

        Value sv1 = sv.clone();

        assertEquals( sv, sv1 );

        sv = new Value( "" );

        assertNotSame( sv, sv1 );
        assertEquals( "", sv.getValue() );

        sv = new Value( "  This is    a   TEST  " );
        sv1 = sv.clone();

        assertEquals( sv, sv1 );
        assertEquals( sv, sv1 );
    }


    /**
     * Presumes an attribute which constrains it's values to some constant
     * strings: LOW, MEDIUM, HIGH.  Normalization does nothing. MatchingRules
     * are exact case matching.
     *
     * @throws Exception on errors
     */
    @Test
    public void testConstrainedString() throws LdapInvalidAttributeValueException
    {
        s.setSyntaxChecker( new SyntaxChecker( "1.1.1.1" )
        {
            public static final long serialVersionUID = 1L;


            public boolean isValidSyntax( Object value )
            {
                if ( value instanceof String )
                {
                    String strval = ( String ) value;
                    return strval.equals( "HIGH" ) || strval.equals( "LOW" ) || strval.equals( "MEDIUM" );
                }
                return false;
            }
        } );

        mr.setSyntax( s );

        mr.setNormalizer( new NoOpNormalizer( mr.getOid() ) );
        at.setEquality( mr );
        at.setSyntax( s );

        // check that normalization and syntax checks work as expected
        Value value = new Value( at, "HIGH" );
        assertEquals( value.getValue(), value.getValue() );

        try
        {
            new Value( at, "high" );
            fail();
        }
        catch ( LdapInvalidAttributeValueException liave )
        {
            // expected
        }

        // create a bunch to best tested for equals and in containers
        Value v0 = new Value( at, "LOW" );
        Value v1 = new Value( at, "LOW" );
        Value v2 = new Value( at, "MEDIUM" );
        Value v3 = new Value( at, "HIGH" );

        // check equals
        assertTrue( v0.equals( v1 ) );
        assertTrue( v1.equals( v0 ) );
        assertEquals( 0, v0.compareTo( v1 ) );

        assertFalse( v2.equals( v3 ) );
        assertFalse( v3.equals( v2 ) );
        assertTrue( v2.compareTo( v3 ) > 0 );
        assertTrue( v3.compareTo( v2 ) < 0 );

        // add all except v1 and v5 to a set
        HashSet<Value> set = new HashSet<Value>();
        set.add( v0 );
        set.add( v2 );
        set.add( v3 );

        // check contains method
        assertTrue( "since v1.equals( v0 ) and v0 was added then this should be true", set.contains( v1 ) );

        // check ordering based on the comparator
        List<Value> list = new ArrayList<Value>();
        list.add( v1 );
        list.add( v3 );
        list.add( v0 );
        list.add( v2 );

        Collections.sort( list );

        // High, low, low, medium
        assertTrue( "since v0 equals v1 either could be at index 0 & 1", list.get( 0 ).equals( v3 ) );
        assertTrue( "since v0 equals v1 either could be at index 0 & 1", list.get( 1 ).equals( v0 ) );
        assertTrue( "since v2 \"MEDIUM\" should be at index 2", list.get( 2 ).equals( v1 ) );
        assertTrue( "since v3 \"HIGH\" should be at index 3", list.get( 3 ).equals( v2 ) );

        assertEquals( 4, list.size() );
    }


    /**
     * Creates a string value with an attribute type that is of a syntax
     * which accepts anything.  Also there is no normalization since the
     * value is the same as the normalized value.  This makes the at technically
     * a binary value however it can be dealt with as a string so this test
     * is still OK.
     * @throws Exception on errors
     */
    @Test
    public void testAcceptAllNoNormalization() throws LdapInvalidAttributeValueException
    {
        // check that normalization and syntax checks work as expected
        Value value = new Value( at, "hello" );
        assertEquals( value.getValue(), value.getValue() );

        // create a bunch to best tested for equals and in containers
        Value v0 = new Value( at, "hello" );
        Value v1 = new Value( at, "hello" );
        Value v2 = new Value( at, "next0" );
        Value v3 = new Value( at, "next1" );
        Value v4 = Value.createValue( at );
        Value v5 = Value.createValue( at );

        // check equals
        assertTrue( v0.equals( v1 ) );
        assertTrue( v1.equals( v0 ) );
        assertTrue( v4.equals( v5 ) );
        assertTrue( v5.equals( v4 ) );
        assertFalse( v2.equals( v3 ) );
        assertFalse( v3.equals( v2 ) );

        // add all except v1 and v5 to a set
        HashSet<Value> set = new HashSet<Value>();
        set.add( v0 );
        set.add( v2 );
        set.add( v3 );
        set.add( v4 );

        // check contains method
        assertTrue( "since v1.equals( v0 ) and v0 was added then this should be true", set.contains( v1 ) );
        assertTrue( "since v4.equals( v5 ) and v4 was added then this should be true", set.contains( v5 ) );

        // check ordering based on the comparator
        ArrayList<Value> list = new ArrayList<Value>();
        list.add( v1 );
        list.add( v3 );
        list.add( v5 );
        list.add( v0 );
        list.add( v2 );
        list.add( v4 );

        Comparator<Value> c = new Comparator<Value>()
        {
            public int compare( Value o1, Value o2 )
            {
                String n1 = null;
                String n2 = null;

                if ( o1 != null )
                {
                    n1 = o1.getValue();
                }

                if ( o2 != null )
                {
                    n2 = o2.getValue();
                }

                if ( n1 == null )
                {
                    return ( n2 == null ) ? 0 : -1;
                }
                else if ( n2 == null )
                {
                    return 1;
                }

                return mr.getLdapComparator().compare( n1, n2 );
            }
        };

        Collections.sort( list, c );

        assertTrue( "since v4 equals v5 and has no value either could be at index 0 & 1", list.get( 0 ).equals( v4 ) );
        assertTrue( "since v4 equals v5 and has no value either could be at index 0 & 1", list.get( 0 ).equals( v5 ) );
        assertTrue( "since v4 equals v5 and has no value either could be at index 0 & 1", list.get( 1 ).equals( v4 ) );
        assertTrue( "since v4 equals v5 and has no value either could be at index 0 & 1", list.get( 1 ).equals( v5 ) );

        assertTrue( "since v0 equals v1 either could be at index 2 & 3", list.get( 2 ).equals( v0 ) );
        assertTrue( "since v0 equals v1 either could be at index 2 & 3", list.get( 2 ).equals( v1 ) );
        assertTrue( "since v0 equals v1 either could be at index 2 & 3", list.get( 3 ).equals( v0 ) );
        assertTrue( "since v0 equals v1 either could be at index 2 & 3", list.get( 3 ).equals( v1 ) );

        assertTrue( "since v2 \"next0\" should be at index 4", list.get( 4 ).equals( v2 ) );
        assertTrue( "since v3 \"next1\" should be at index 5", list.get( 5 ).equals( v3 ) );

        assertEquals( 6, list.size() );
    }


    /**
     * Test serialization of a Value which has a normalized value
     */
    @Test
    public void testNormalizedStringValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        // First check with a value which will be normalized
        Value ssv = new Value( at, "  Test   Test  " );

        assertEquals( 0, ssv.compareTo( " test  test " ) );
        assertEquals( "  Test   Test  ", ssv.getValue() );

        Value ssvSer = deserializeValue( serializeValue( ssv ) );

        assertEquals( ssv, ssvSer );
    }


    /**
     * Test serialization of a Value which does not have a normalized value
     */
    @Test
    public void testNoNormalizedStringValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        // First check with a value which will be normalized
        Value ssv = new Value( at, "test" );

        assertEquals( 0, ssv.compareTo( " test " ) );
        assertEquals( "test", ssv.getValue() );

        Value ssvSer = deserializeValue( serializeValue( ssv ) );

        assertEquals( ssv, ssvSer );
    }


    /**
     * Test serialization of a null Value
     */
    @Test
    public void testNullStringValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        // First check with a value which will be normalized
        Value ssv = Value.createValue( at );

        assertEquals( 0, ssv.compareTo( ( String ) null ) );
        assertNull( ssv.getValue() );

        Value ssvSer = deserializeValue( serializeValue( ssv ) );

        assertEquals( ssv, ssvSer );
    }


    /**
     * Test serialization of an empty Value
     */
    @Test
    public void testEmptyStringValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        // First check with a value which will be normalized
        Value ssv = new Value( at, "" );

        assertEquals( 0, ssv.compareTo( "  " ) );
        assertEquals( "", ssv.getValue() );

        Value ssvSer = deserializeValue( serializeValue( ssv ) );

        assertEquals( ssv, ssvSer );
    }


    /**
     * Test serialization of an empty Value
     */
    @Test
    public void testStringValueEmptyNormalizedSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        // First check with a value which will be normalized
        Value ssv = new Value( "  " );

        assertEquals( "  ", ssv.getValue() );

        Value ssvSer = deserializeValue( serializeValue( ssv ) );

        assertEquals( ssv, ssvSer );
    }
}
