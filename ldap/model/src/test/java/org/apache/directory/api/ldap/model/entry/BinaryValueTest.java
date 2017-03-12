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
 * Test the BinaryValue class
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


            public Value<?> normalize( Value<?> value ) throws LdapException
            {
                if ( !value.isHumanReadable() )
                {
                    byte[] val = value.getBytes();
                    // each byte will be changed to be > 0, and spaces will be trimmed
                    byte[] newVal = new byte[val.length];
                    int i = 0;

                    for ( byte b : val )
                    {
                        newVal[i++] = ( byte ) ( b & 0x007F );
                    }

                    return new BinaryValue( Strings.trim( newVal ) );
                }

                throw new IllegalStateException( "expected byte[] to normalize" );
            }


            public String normalize( String value ) throws LdapException
            {
                throw new IllegalStateException( "expected byte[] to normalize" );
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
     * Serialize a BinaryValue
     */
    private ByteArrayOutputStream serializeValue( BinaryValue value ) throws IOException
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
     * Deserialize a BinaryValue
     */
    private BinaryValue deserializeValue( AttributeType at, ByteArrayOutputStream out ) throws IOException,
        ClassNotFoundException
    {
        ObjectInputStream oIn = null;
        ByteArrayInputStream in = new ByteArrayInputStream( out.toByteArray() );

        try
        {
            oIn = new ObjectInputStream( in );

            BinaryValue value = new BinaryValue( at );
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
        BinaryValue bv = new BinaryValue( ( byte[] ) null );
        assertEquals( 0, bv.hashCode() );

        bv = new BinaryValue( Strings.EMPTY_BYTES );
        int h = Arrays.hashCode( Strings.EMPTY_BYTES );
        assertEquals( h, bv.hashCode() );

        h = Arrays.hashCode( BYTES1 );
        bv = new BinaryValue( BYTES1 );
        assertEquals( h, bv.hashCode() );
    }


    @Test
    public void testBinaryValueNull() throws LdapException
    {
        BinaryValue cbv = new BinaryValue( ( byte[] ) null );

        assertNull( cbv.getValue() );
        assertFalse( cbv.isSchemaAware() );
        assertTrue( cbv.isValid( BINARY_CHECKER ) );
        assertTrue( cbv.isNull() );
        assertNull( cbv.getNormValue() );
    }


    @Test
    public void testBinaryValueEmpty() throws LdapException
    {
        BinaryValue cbv = new BinaryValue( Strings.EMPTY_BYTES );

        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, cbv.getBytes() ) );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, cbv.getValue() ) );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, cbv.getReference() ) );
        assertFalse( cbv.isSchemaAware() );
        assertTrue( cbv.isValid( BINARY_CHECKER ) );
        assertFalse( cbv.isNull() );
        assertNotNull( cbv.getNormValue() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, cbv.getNormValue() ) );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, cbv.getNormReference() ) );
    }


    @Test
    public void testBinaryValue() throws LdapException
    {
        BinaryValue cbv = new BinaryValue( BYTES1 );

        assertTrue( Arrays.equals( BYTES1, cbv.getBytes() ) );
        assertTrue( Arrays.equals( BYTES1, cbv.getValue() ) );
        assertTrue( Arrays.equals( BYTES1, cbv.getReference() ) );
        assertFalse( cbv.isSchemaAware() );
        assertTrue( cbv.isValid( BINARY_CHECKER ) );
        assertFalse( cbv.isNull() );
        assertNotNull( cbv.getNormValue() );
        assertTrue( Arrays.equals( BYTES1, cbv.getNormValue() ) );
    }


    @Test
    public void testSetByteArray() throws LdapException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        bv = new BinaryValue( BYTES1 );

        assertTrue( Arrays.equals( BYTES1, bv.getBytes() ) );
        assertTrue( Arrays.equals( BYTES1, bv.getValue() ) );
        assertTrue( Arrays.equals( BYTES1, bv.getReference() ) );
        assertFalse( bv.isSchemaAware() );
        assertTrue( bv.isValid( BINARY_CHECKER ) );
        assertFalse( bv.isNull() );
        assertNotNull( bv.getNormValue() );
        assertTrue( Arrays.equals( BYTES1, bv.getNormValue() ) );
    }


    @Test
    public void testGetNormalizedValueCopy() throws LdapException
    {
        BinaryValue cbv = new BinaryValue( BYTES2 );

        assertTrue( Arrays.equals( BYTES2, cbv.getBytes() ) );
        assertTrue( Arrays.equals( BYTES2, cbv.getValue() ) );
        assertTrue( Arrays.equals( BYTES2, cbv.getReference() ) );
        assertFalse( cbv.isSchemaAware() );
        assertTrue( cbv.isValid( BINARY_CHECKER ) );
        assertFalse( cbv.isNull() );
        assertNotNull( cbv.getNormValue() );
        assertTrue( Arrays.equals( BYTES2, cbv.getNormValue() ) );

        cbv.apply( at );
        byte[] copy = cbv.getNormValue();
        assertTrue( Arrays.equals( BYTES1, copy ) );
        cbv.getNormReference()[0] = 0x11;
        assertTrue( Arrays.equals( BYTES1, copy ) );
    }


    @Test
    public void testNormalizeNormalizer() throws LdapException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        bv.apply( at );
        assertTrue( bv.isSchemaAware() );
        assertEquals( null, bv.getNormValue() );

        bv = new BinaryValue( Strings.EMPTY_BYTES );
        bv.apply( at );
        assertTrue( bv.isSchemaAware() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getBytes() ) );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getNormValue() ) );

        bv = new BinaryValue( BYTES1 );
        bv.apply( at );
        assertTrue( bv.isSchemaAware() );
        assertTrue( Arrays.equals( BYTES1, bv.getBytes() ) );
        assertTrue( Arrays.equals( BYTES1, bv.getNormValue() ) );

        bv = new BinaryValue( BYTES2 );
        bv.apply( at );
        assertTrue( bv.isSchemaAware() );
        assertTrue( Arrays.equals( BYTES2, bv.getBytes() ) );
        assertTrue( Arrays.equals( BYTES1, bv.getNormValue() ) );
    }


    @Test
    public void testCompareToValueOfbyte() throws LdapException
    {
        BinaryValue bv1 = new BinaryValue( ( byte[] ) null );
        BinaryValue bv2 = new BinaryValue( ( byte[] ) null );

        assertEquals( 0, bv1.compareTo( bv2 ) );

        bv1 = new BinaryValue( BYTES1 );
        assertEquals( 1, bv1.compareTo( bv2 ) );

        bv2 = new BinaryValue( BYTES2 );
        assertEquals( 1, bv1.compareTo( bv2 ) );

        bv2.apply( at );
        assertEquals( 0, bv1.compareTo( bv2 ) );

        bv1 = new BinaryValue( BYTES2 );
        assertEquals( -1, bv1.compareTo( bv2 ) );
    }


    @Test
    public void testEquals() throws LdapException
    {
        BinaryValue bv1 = new BinaryValue( ( byte[] ) null );
        BinaryValue bv2 = new BinaryValue( ( byte[] ) null );

        assertEquals( bv1, bv2 );

        bv1 = new BinaryValue( BYTES1 );
        assertNotSame( bv1, bv2 );

        bv2 = new BinaryValue( BYTES2 );
        assertNotSame( bv1, bv2 );

        bv2.apply( at );
        assertEquals( bv1, bv2 );

        bv1 = new BinaryValue( BYTES2 );
        assertNotSame( bv1, bv2 );
    }


    @Test
    public void testClone()
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );
        BinaryValue copy = bv.clone();

        assertEquals( bv, copy );

        bv = new BinaryValue( BYTES1 );
        assertNotSame( bv, copy );

        copy = bv.clone();
        assertEquals( bv, copy );

        bv.getReference()[0] = 0x11;

        assertTrue( Arrays.equals( BYTES_MOD, bv.getBytes() ) );
        assertTrue( Arrays.equals( BYTES1, copy.getBytes() ) );
    }


    @Test
    public void testGetCopy()
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        assertNull( bv.getValue() );

        bv = new BinaryValue( Strings.EMPTY_BYTES );
        assertNotNull( bv.getValue() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getValue() ) );

        bv = new BinaryValue( BYTES1 );
        byte[] copy = bv.getValue();

        assertTrue( Arrays.equals( BYTES1, copy ) );

        bv.getReference()[0] = 0x11;
        assertTrue( Arrays.equals( BYTES1, copy ) );
        assertTrue( Arrays.equals( BYTES_MOD, bv.getBytes() ) );
    }


    @Test
    public void testCompareTo() throws LdapException
    {
        BinaryValue bv1 = new BinaryValue( ( byte[] ) null );
        BinaryValue bv2 = new BinaryValue( ( byte[] ) null );

        assertEquals( 0, bv1.compareTo( bv2 ) );

        bv1 = new BinaryValue( BYTES1 );
        assertEquals( 1, bv1.compareTo( bv2 ) );
        assertEquals( -1, bv2.compareTo( bv1 ) );

        bv2 = new BinaryValue( BYTES1 );
        assertEquals( 0, bv1.compareTo( bv2 ) );

        // Now check that the equals method works on normalized values.
        bv1 = new BinaryValue( BYTES2 );
        bv2 = new BinaryValue( BYTES1 );
        bv1.apply( at );
        assertEquals( 0, bv1.compareTo( bv2 ) );

        bv1 = new BinaryValue( BYTES1 );
        bv2 = new BinaryValue( BYTES2 );
        assertEquals( 1, bv1.compareTo( bv2 ) );

        bv1 = new BinaryValue( BYTES2 );
        bv2 = new BinaryValue( BYTES1 );
        assertEquals( -1, bv1.compareTo( bv2 ) );
    }


    @Test
    public void testToString()
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        assertEquals( "null", bv.toString() );

        bv = new BinaryValue( Strings.EMPTY_BYTES );
        assertEquals( "", bv.toString() );

        bv = new BinaryValue( BYTES1 );
        assertEquals( "0x01 0x02 0x03 0x04 ", bv.toString() );
    }


    @Test
    public void testGetReference()
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        assertNull( bv.getReference() );

        bv = new BinaryValue( Strings.EMPTY_BYTES );
        assertNotNull( bv.getReference() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getReference() ) );

        bv = new BinaryValue( BYTES1 );
        byte[] reference = bv.getReference();

        assertTrue( Arrays.equals( BYTES1, reference ) );

        bv.getReference()[0] = 0x11;
        assertTrue( Arrays.equals( BYTES_MOD, reference ) );
        assertTrue( Arrays.equals( BYTES_MOD, bv.getBytes() ) );
    }


    @Test
    public void testGet()
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        assertNull( bv.getValue() );

        bv = new BinaryValue( Strings.EMPTY_BYTES );
        assertNotNull( bv.getValue() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getBytes() ) );

        bv = new BinaryValue( BYTES1 );
        byte[] get = bv.getBytes();

        assertTrue( Arrays.equals( BYTES1, get ) );

        bv.getReference()[0] = 0x11;
        assertTrue( Arrays.equals( BYTES1, get ) );
        assertTrue( Arrays.equals( BYTES_MOD, bv.getBytes() ) );
    }


    @Test
    public void testGetNormalizedValue() throws LdapException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        assertFalse( bv.isSchemaAware() );

        bv.apply( at );
        byte[] value = bv.getNormValue();
        assertNull( value );
        assertTrue( bv.isSchemaAware() );

        bv = new BinaryValue( BYTES2 );
        bv.apply( at );
        value = bv.getNormValue();
        assertTrue( Arrays.equals( BYTES1, value ) );
        bv.getNormReference()[0] = 0x11;
        assertFalse( Arrays.equals( BYTES_MOD, value ) );
    }


    @Test
    public void testGetNormalizedValueReference() throws LdapException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        assertFalse( bv.isSchemaAware() );

        bv.apply( at );
        byte[] value = bv.getNormReference();
        assertNull( value );
        assertTrue( bv.isSchemaAware() );

        bv = new BinaryValue( BYTES2 );
        bv.apply( at );
        value = bv.getNormReference();
        assertTrue( Arrays.equals( BYTES1, value ) );
        bv.getNormReference()[0] = 0x11;
        assertTrue( Arrays.equals( BYTES_MOD, value ) );
    }


    @Test
    public void testIsNull()
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        assertTrue( bv.isNull() );

        bv = new BinaryValue( Strings.EMPTY_BYTES );
        assertFalse( bv.isNull() );

        bv = new BinaryValue( BYTES1 );
        assertFalse( bv.isNull() );
    }


    @Test
    public void testIsValid() throws LdapException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        assertTrue( bv.isValid( BINARY_CHECKER ) );

        bv = new BinaryValue( Strings.EMPTY_BYTES );
        assertTrue( bv.isValid( BINARY_CHECKER ) );

        bv = new BinaryValue( BYTES1 );
        assertFalse( bv.isNull() );
        assertTrue( bv.isValid( BINARY_CHECKER ) );

        bv = new BinaryValue( INVALID_BYTES );
        assertFalse( bv.isNull() );
        assertFalse( bv.isValid( BINARY_CHECKER ) );
    }


    @Test
    public void testIsValidSyntaxChecker() throws LdapException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        assertTrue( bv.isValid( BINARY_CHECKER ) );

        bv = new BinaryValue( Strings.EMPTY_BYTES );
        assertTrue( bv.isValid( BINARY_CHECKER ) );

        bv = new BinaryValue( BYTES1 );
        assertTrue( bv.isValid( BINARY_CHECKER ) );

        bv = new BinaryValue( INVALID_BYTES );
        assertFalse( bv.isValid( BINARY_CHECKER ) );
    }


    @Test
    public void testNormalize() throws LdapException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        bv.apply( at );
        assertTrue( bv.isSchemaAware() );
        assertEquals( null, bv.getNormValue() );

        bv = new BinaryValue( Strings.EMPTY_BYTES );
        bv.apply( at );
        assertTrue( bv.isSchemaAware() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getNormValue() ) );

        bv = new BinaryValue( BYTES2 );
        bv.apply( at );
        assertTrue( bv.isSchemaAware() );
        assertTrue( Arrays.equals( BYTES2, bv.getValue() ) );
        assertTrue( Arrays.equals( BYTES1, bv.getNormValue() ) );
    }


    @Test
    public void testSet() throws LdapException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        assertNull( bv.getValue() );
        assertFalse( bv.isSchemaAware() );
        assertTrue( bv.isValid( BINARY_CHECKER ) );
        assertTrue( bv.isNull() );

        bv = new BinaryValue( Strings.EMPTY_BYTES );
        assertNotNull( bv.getValue() );
        assertTrue( Arrays.equals( Strings.EMPTY_BYTES, bv.getBytes() ) );
        assertFalse( bv.isSchemaAware() );
        assertTrue( bv.isValid( BINARY_CHECKER ) );
        assertFalse( bv.isNull() );

        bv = new BinaryValue( BYTES1 );
        assertNotNull( bv.getValue() );
        assertTrue( Arrays.equals( BYTES1, bv.getBytes() ) );
        assertFalse( bv.isSchemaAware() );
        assertTrue( bv.isValid( BINARY_CHECKER ) );
        assertFalse( bv.isNull() );
    }


    @Test
    public void testIsNormalized() throws LdapException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );
        assertFalse( bv.isSchemaAware() );

        bv = new BinaryValue( BYTES2 );
        assertFalse( bv.isSchemaAware() );

        bv.apply( at );

        assertTrue( Arrays.equals( BYTES1, bv.getNormValue() ) );
        assertTrue( bv.isSchemaAware() );

        bv = new BinaryValue( BYTES2 );
        assertFalse( bv.isSchemaAware() );

        bv = new BinaryValue( BYTES_MOD );
        assertFalse( bv.isSchemaAware() );
    }


    @Test
    public void testSetNormalized() throws LdapException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );

        assertFalse( bv.isSchemaAware() );

        bv = new BinaryValue( BYTES2 );
        assertFalse( bv.isSchemaAware() );

        bv.apply( at );

        assertTrue( Arrays.equals( BYTES1, bv.getNormValue() ) );
        assertTrue( bv.isSchemaAware() );

        assertTrue( Arrays.equals( BYTES2, bv.getValue() ) );
    }


    /**
     * Test the serialization of a CBV with a value and a normalized value
     */
    @Test
    public void testSerializeStandard() throws LdapException, IOException, ClassNotFoundException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );
        bv = new BinaryValue( BYTES2 );
        bv.apply( at );
        assertTrue( bv.isValid( BINARY_CHECKER ) );

        BinaryValue cbvSer = deserializeValue( at, serializeValue( bv ) );
        assertNotSame( bv, cbvSer );
        assertTrue( Arrays.equals( bv.getReference(), cbvSer.getReference() ) );
        assertTrue( Arrays.equals( bv.getNormReference(), cbvSer.getNormReference() ) );
        assertTrue( cbvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CBV with a value and no normalized value
     */
    @Test
    public void testSerializeNotNormalized() throws LdapException, IOException, ClassNotFoundException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );
        bv = new BinaryValue( BYTES2 );
        bv.isValid( BINARY_CHECKER );

        BinaryValue cbvSer = deserializeValue( null, serializeValue( bv ) );
        assertNotSame( bv, cbvSer );
        assertTrue( Arrays.equals( bv.getReference(), cbvSer.getReference() ) );
        assertTrue( Arrays.equals( bv.getReference(), cbvSer.getNormReference() ) );
        assertFalse( cbvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CBV with a value and an empty normalized value
     */
    @Test
    public void testSerializeEmptyNormalized() throws LdapException, IOException, ClassNotFoundException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );
        bv = new BinaryValue( BYTES2 );
        bv.isValid( BINARY_CHECKER );
        bv.apply( at );

        BinaryValue cbvSer = deserializeValue( at, serializeValue( bv ) );
        assertNotSame( bv, cbvSer );
        assertTrue( Arrays.equals( bv.getReference(), cbvSer.getReference() ) );
        assertTrue( Arrays.equals( bv.getNormReference(), cbvSer.getNormReference() ) );
        assertTrue( cbvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CBV with a null value
     */
    @Test
    public void testSerializeNullValue() throws LdapException, IOException, ClassNotFoundException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );
        bv = new BinaryValue( ( byte[] ) null );
        bv.isValid( BINARY_CHECKER );
        bv.apply( at );

        BinaryValue cbvSer = deserializeValue( at, serializeValue( bv ) );
        assertNotSame( bv, cbvSer );
        assertTrue( Arrays.equals( bv.getReference(), cbvSer.getReference() ) );
        assertTrue( Arrays.equals( bv.getNormReference(), cbvSer.getNormReference() ) );
        assertTrue( cbvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CBV with an empty value
     */
    @Test
    public void testSerializeEmptyValue() throws LdapException, IOException, ClassNotFoundException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );
        bv = new BinaryValue( Strings.EMPTY_BYTES );
        bv.isValid( BINARY_CHECKER );
        bv.apply( at );

        BinaryValue cbvSer = deserializeValue( at, serializeValue( bv ) );
        assertNotSame( bv, cbvSer );
        assertTrue( Arrays.equals( bv.getReference(), cbvSer.getReference() ) );
        assertTrue( Arrays.equals( bv.getNormReference(), cbvSer.getNormReference() ) );
        assertTrue( cbvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CBV with an empty value not normalized
     */
    @Test
    public void testSerializeEmptyValueNotNormalized() throws LdapException, IOException, ClassNotFoundException
    {
        BinaryValue bv = new BinaryValue( ( byte[] ) null );
        bv = new BinaryValue( Strings.EMPTY_BYTES );
        bv.isValid( BINARY_CHECKER );

        BinaryValue cbvSer = deserializeValue( null, serializeValue( bv ) );
        assertNotSame( bv, cbvSer );
        assertTrue( Arrays.equals( bv.getReference(), cbvSer.getReference() ) );
        assertTrue( Arrays.equals( bv.getNormReference(), cbvSer.getNormReference() ) );
        assertFalse( cbvSer.isSchemaAware() );
    }
}
