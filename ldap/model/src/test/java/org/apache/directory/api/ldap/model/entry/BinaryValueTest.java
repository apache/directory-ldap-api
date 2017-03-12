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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MutableAttributeType;
import org.apache.directory.api.ldap.model.schema.MutableMatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.PrepareString;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.ldap.model.schema.comparators.ByteArrayComparator;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.OctetStringSyntaxChecker;
import org.apache.directory.api.util.Strings;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * 
 * Test the Value class
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class BinaryValueTest
{
    private static final byte[] BYTES1 = new byte[]
        { 0x01, 0x02, 0x03, 0x04 };
    private static final byte[] BYTES2 = new byte[]
        { ( byte ) 0x81, ( byte ) 0x82, ( byte ) 0x83, ( byte ) 0x84 };
    private static final byte[] INVALID_BYTES = new byte[]
        { 0x01, 0x02, 0x03, 0x04, 0x05 };
    private static final byte[] BYTES_MOD = new byte[]
        { 0x11, 0x02, 0x03, 0x04 };
    private LdapSyntax s;
    private MutableAttributeType at;
    private MutableMatchingRule mr;


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

    private static final SyntaxChecker BINARY_CHECKER = new SyntaxChecker( "1.1.1" )
    {
        public static final long serialVersionUID = 1L;


        public boolean isValidSyntax( Object value )
        {
            if ( value == null )
            {
                return true;
            }

            return ( ( byte[] ) value ).length < 5;
        }
    };


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
    private Value deserializeValue( AttributeType at, ByteArrayOutputStream out ) throws IOException,
        ClassNotFoundException
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


    @Test
    public void testHashCode()
    {
        Value bv = new Value( ( byte[] ) null );
        assertEquals( 0, bv.hashCode() );

        bv = new Value( Strings.EMPTY_BYTES );
        int h = Arrays.hashCode( Strings.EMPTY_BYTES );
        assertEquals( h, bv.hashCode() );

        h = Arrays.hashCode( BYTES1 );
        bv = new Value( BYTES1 );
        assertEquals( h, bv.hashCode() );
    }


    @Test
    public void testBinaryValueNull() throws LdapException
    {
        Value cbv = new Value( ( byte[] ) null );

        assertEquals( "", cbv.getValue() );
        assertFalse( cbv.isSchemaAware() );
        assertTrue( cbv.isValid( BINARY_CHECKER ) );
        assertTrue( cbv.isNull() );
        assertNull( cbv.getBytes() );
    }


    @Test
    public void testBinaryValueEmpty() throws LdapException
    {
        Value cbv = new Value( Strings.EMPTY_BYTES );

        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, cbv.getBytes() ) );
        assertFalse( cbv.isSchemaAware() );
        assertTrue( cbv.isValid( BINARY_CHECKER ) );
        assertFalse( cbv.isNull() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, cbv.getBytes() ) );
    }


    @Test
    public void testBinaryValue() throws LdapException
    {
        Value cbv = new Value( BYTES1 );

        assertTrue( Arrays.equals( BYTES1, cbv.getBytes() ) );
        assertFalse( cbv.isSchemaAware() );
        assertTrue( cbv.isValid( BINARY_CHECKER ) );
        assertFalse( cbv.isNull() );
    }


    @Test
    public void testSetByteArray() throws LdapException
    {
        Value bv = new Value( ( byte[] ) null );

        bv = new Value( BYTES1 );

        assertTrue( Arrays.equals( BYTES1, bv.getBytes() ) );
        assertFalse( bv.isSchemaAware() );
        assertTrue( bv.isValid( BINARY_CHECKER ) );
        assertFalse( bv.isNull() );
    }


    @Test
    public void testGetNormalizedValueCopy() throws LdapException
    {
        Value cbv = new Value( BYTES2 );

        assertTrue( Arrays.equals( BYTES2, cbv.getBytes() ) );
        assertFalse( cbv.isSchemaAware() );
        assertTrue( cbv.isValid( BINARY_CHECKER ) );
        assertFalse( cbv.isNull() );

        cbv = new Value( at, cbv );
        byte[] copy = cbv.getBytes();
        assertTrue( Arrays.equals( BYTES2, copy ) );
    }


    @Test
    public void testNormalizeNormalizer() throws LdapException
    {
        Value bv = new Value( ( byte[] ) null );

        bv = new Value( at, bv );
        assertTrue( bv.isSchemaAware() );
        assertNull( bv.getBytes() );

        bv = new Value( Strings.EMPTY_BYTES );
        bv = new Value( at, bv );
        assertTrue( bv.isSchemaAware() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getBytes() ) );

        bv = new Value( BYTES1 );
        bv = new Value( at, bv );
        assertTrue( bv.isSchemaAware() );
        assertTrue( Arrays.equals( BYTES1, bv.getBytes() ) );

        bv = new Value( BYTES2 );
        bv = new Value( at, bv );
        assertTrue( bv.isSchemaAware() );
        assertTrue( Arrays.equals( BYTES2, bv.getBytes() ) );
    }


    @Test
    public void testCompareToValueOfbyte() throws LdapException
    {
        Value bv1 = new Value( ( byte[] ) null );
        Value bv2 = new Value( ( byte[] ) null );

        assertEquals( 0, bv1.compareTo( bv2 ) );

        bv1 = new Value( BYTES1 );
        assertEquals( 1, bv1.compareTo( bv2 ) );

        bv2 = new Value( BYTES2 );
        assertEquals( 1, bv1.compareTo( bv2 ) );

        bv2 = new Value( at, bv2 );
        assertEquals( 1, bv1.compareTo( bv2 ) );

        bv1 = new Value( BYTES2 );
        assertEquals( 0, bv1.compareTo( bv2 ) );
    }


    @Test
    public void testEquals() throws LdapException
    {
        Value bv1 = new Value( ( byte[] ) null );
        Value bv2 = new Value( ( byte[] ) null );

        assertEquals( bv1, bv2 );

        bv1 = new Value( BYTES1 );
        assertNotSame( bv1, bv2 );

        bv2 = new Value( BYTES2 );
        assertNotSame( bv1, bv2 );

        bv1 = new Value( at, bv2 );
        assertEquals( bv1, bv2 );

        bv1 = new Value( BYTES2 );
        assertNotSame( bv1, bv2 );
    }


    @Test
    public void testClone()
    {
        Value bv = new Value( ( byte[] ) null );
        Value copy = bv.clone();

        assertEquals( bv, copy );

        bv = new Value( BYTES1 );
        assertNotSame( bv, copy );

        copy = bv.clone();
        assertEquals( bv, copy );

        assertTrue( Arrays.equals( BYTES1, copy.getBytes() ) );
    }


    @Test
    public void testGetCopy()
    {
        Value bv = new Value( ( byte[] ) null );

        assertEquals( "", bv.getValue() );

        bv = new Value( Strings.EMPTY_BYTES );
        assertNotNull( bv.getBytes() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getBytes() ) );

        bv = new Value( BYTES1 );
        byte[] copy = bv.getBytes();

        assertTrue( Arrays.equals( BYTES1, copy ) );

        assertTrue( Arrays.equals( BYTES1, copy ) );
    }


    @Test
    public void testCompareTo() throws LdapException
    {
        Value bv1 = new Value( ( byte[] ) null );
        Value bv2 = new Value( ( byte[] ) null );

        assertEquals( 0, bv1.compareTo( bv2 ) );

        bv1 = new Value( BYTES1 );
        assertEquals( 1, bv1.compareTo( bv2 ) );
        assertEquals( -1, bv2.compareTo( bv1 ) );

        bv2 = new Value( BYTES1 );
        assertEquals( 0, bv1.compareTo( bv2 ) );

        // Now check that the equals method works on normalized values.
        bv1 = new Value( BYTES2 );
        bv2 = new Value( BYTES1 );
        bv1 = new Value( at, bv1 );
        assertEquals( -1, bv1.compareTo( bv2 ) );

        bv1 = new Value( BYTES1 );
        bv2 = new Value( BYTES2 );
        assertEquals( 1, bv1.compareTo( bv2 ) );

        bv1 = new Value( BYTES2 );
        bv2 = new Value( BYTES1 );
        assertEquals( -1, bv1.compareTo( bv2 ) );
    }


    @Test
    public void testToString()
    {
        Value bv = new Value( ( byte[] ) null );

        assertEquals( "null", bv.toString() );

        bv = new Value( Strings.EMPTY_BYTES );
        assertEquals( "", bv.toString() );

        bv = new Value( BYTES1 );
        assertEquals( "0x01 0x02 0x03 0x04 ", bv.toString() );
    }


    @Test
    public void testGet()
    {
        Value bv = new Value( ( byte[] ) null );

        assertEquals( "", bv.getValue() );

        bv = new Value( Strings.EMPTY_BYTES );
        assertEquals( "", bv.getValue() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getBytes() ) );

        bv = new Value( BYTES1 );
        byte[] get = bv.getBytes();

        assertTrue( Arrays.equals( BYTES1, get ) );

        assertTrue( Arrays.equals( BYTES1, get ) );
    }


    @Test
    public void testGetNormalizedValue() throws LdapException
    {
        Value bv = new Value( ( byte[] ) null );

        assertFalse( bv.isSchemaAware() );

        bv = new Value( at, bv );
        byte[] value = bv.getBytes();
        assertNull( value );
        assertTrue( bv.isSchemaAware() );

        bv = new Value( BYTES2 );
        bv = new Value( at, bv );
        value = bv.getBytes();
        assertTrue( Arrays.equals( BYTES2, value ) );
    }


    @Test
    public void testIsNull()
    {
        Value bv = new Value( ( byte[] ) null );

        assertTrue( bv.isNull() );

        bv = new Value( Strings.EMPTY_BYTES );
        assertFalse( bv.isNull() );

        bv = new Value( BYTES1 );
        assertFalse( bv.isNull() );
    }


    @Test
    public void testIsValid() throws LdapException
    {
        Value bv = new Value( ( byte[] ) null );

        assertTrue( bv.isValid( BINARY_CHECKER ) );

        bv = new Value( Strings.EMPTY_BYTES );
        assertTrue( bv.isValid( BINARY_CHECKER ) );

        bv = new Value( BYTES1 );
        assertFalse( bv.isNull() );
        assertTrue( bv.isValid( BINARY_CHECKER ) );

        bv = new Value( INVALID_BYTES );
        assertFalse( bv.isNull() );
        assertFalse( bv.isValid( BINARY_CHECKER ) );
    }


    @Test
    public void testIsValidSyntaxChecker() throws LdapException
    {
        Value bv = new Value( ( byte[] ) null );

        assertTrue( bv.isValid( BINARY_CHECKER ) );

        bv = new Value( Strings.EMPTY_BYTES );
        assertTrue( bv.isValid( BINARY_CHECKER ) );

        bv = new Value( BYTES1 );
        assertTrue( bv.isValid( BINARY_CHECKER ) );

        bv = new Value( INVALID_BYTES );
        assertFalse( bv.isValid( BINARY_CHECKER ) );
    }


    @Test
    public void testNormalize() throws LdapException
    {
        Value bv = new Value( ( byte[] ) null );

        bv = new Value( at, bv );
        assertTrue( bv.isSchemaAware() );
        assertEquals( null, bv.getBytes() );

        bv = new Value( Strings.EMPTY_BYTES );
        bv = new Value( at, bv );
        assertTrue( bv.isSchemaAware() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getBytes() ) );

        bv = new Value( BYTES2 );
        bv = new Value( at, bv );
        assertTrue( bv.isSchemaAware() );
        assertTrue( Arrays.equals( BYTES2, bv.getBytes() ) );
    }


    @Test
    public void testSet() throws LdapException
    {
        Value bv = new Value( ( byte[] ) null );

        assertEquals( "", bv.getValue() );
        assertFalse( bv.isSchemaAware() );
        assertTrue( bv.isValid( BINARY_CHECKER ) );
        assertTrue( bv.isNull() );

        bv = new Value( Strings.EMPTY_BYTES );
        assertEquals( "", bv.getValue() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getBytes() ) );
        assertFalse( bv.isSchemaAware() );
        assertTrue( bv.isValid( BINARY_CHECKER ) );
        assertFalse( bv.isNull() );

        bv = new Value( BYTES1 );
        assertNotNull( bv.getBytes() );
        assertTrue( Arrays.equals( BYTES1, bv.getBytes() ) );
        assertFalse( bv.isSchemaAware() );
        assertTrue( bv.isValid( BINARY_CHECKER ) );
        assertFalse( bv.isNull() );
    }


    @Test
    public void testIsNormalized() throws LdapException
    {
        Value bv = new Value( ( byte[] ) null );
        assertFalse( bv.isSchemaAware() );

        bv = new Value( BYTES2 );
        assertFalse( bv.isSchemaAware() );

        bv = new Value( at, bv );

        assertTrue( Arrays.equals( BYTES2, bv.getBytes() ) );
        assertTrue( bv.isSchemaAware() );

        bv = new Value( BYTES2 );
        assertFalse( bv.isSchemaAware() );

        bv = new Value( BYTES_MOD );
        assertFalse( bv.isSchemaAware() );
    }


    @Test
    public void testSetNormalized() throws LdapException
    {
        Value bv = new Value( ( byte[] ) null );

        assertFalse( bv.isSchemaAware() );

        bv = new Value( BYTES2 );
        assertFalse( bv.isSchemaAware() );

        bv = new Value( at, bv );

        assertTrue( Arrays.equals( BYTES2, bv.getBytes() ) );
        assertTrue( bv.isSchemaAware() );

        assertTrue( Arrays.equals( BYTES2, bv.getBytes() ) );
    }


    /**
     * Test the serialization of a CBV with a value and a normalized value
     */
    @Test
    public void testSerializeStandard() throws LdapException, IOException, ClassNotFoundException
    {
        Value bv = new Value( ( byte[] ) null );
        bv = new Value( BYTES2 );
        bv = new Value( at, bv );
        assertTrue( bv.isValid( BINARY_CHECKER ) );

        Value cbvSer = deserializeValue( at, serializeValue( bv ) );
        assertNotSame( bv, cbvSer );
        assertTrue( cbvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CBV with a value and no normalized value
     */
    @Test
    public void testSerializeNotNormalized() throws LdapException, IOException, ClassNotFoundException
    {
        Value bv = new Value( ( byte[] ) null );
        bv = new Value( BYTES2 );
        bv.isValid( BINARY_CHECKER );

        Value cbvSer = deserializeValue( null, serializeValue( bv ) );
        assertNotSame( bv, cbvSer );
        assertFalse( cbvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CBV with a value and an empty normalized value
     */
    @Test
    public void testSerializeEmptyNormalized() throws LdapException, IOException, ClassNotFoundException
    {
        Value bv = new Value( ( byte[] ) null );
        bv = new Value( BYTES2 );
        bv.isValid( BINARY_CHECKER );
        bv = new Value( at, bv );

        Value cbvSer = deserializeValue( at, serializeValue( bv ) );
        assertNotSame( bv, cbvSer );
        assertTrue( cbvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CBV with a null value
     */
    @Test
    public void testSerializeNullValue() throws LdapException, IOException, ClassNotFoundException
    {
        Value bv = new Value( ( byte[] ) null );
        bv = new Value( ( byte[] ) null );
        bv.isValid( BINARY_CHECKER );
        bv = new Value( at, bv );

        Value cbvSer = deserializeValue( at, serializeValue( bv ) );
        assertNotSame( bv, cbvSer );
        assertTrue( cbvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CBV with an empty value
     */
    @Test
    public void testSerializeEmptyValue() throws LdapException, IOException, ClassNotFoundException
    {
        Value bv = new Value( ( byte[] ) null );
        bv = new Value( Strings.EMPTY_BYTES );
        bv.isValid( BINARY_CHECKER );
        bv = new Value( at, bv );

        Value cbvSer = deserializeValue( at, serializeValue( bv ) );
        assertNotSame( bv, cbvSer );
        assertTrue( cbvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CBV with an empty value not normalized
     */
    @Test
    public void testSerializeEmptyValueNotNormalized() throws LdapException, IOException, ClassNotFoundException
    {
        Value bv = new Value( ( byte[] ) null );
        bv = new Value( Strings.EMPTY_BYTES );
        bv.isValid( BINARY_CHECKER );

        Value cbvSer = deserializeValue( null, serializeValue( bv ) );
        assertNotSame( bv, cbvSer );
        assertFalse( cbvSer.isSchemaAware() );
    }
}
