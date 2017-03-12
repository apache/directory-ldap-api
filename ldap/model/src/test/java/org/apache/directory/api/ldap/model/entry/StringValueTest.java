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

import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.comparators.StringComparator;
import org.apache.directory.api.ldap.model.schema.normalizers.DeepTrimToLowerNormalizer;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.Ia5StringSyntaxChecker;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.OctetStringSyntaxChecker;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * 
 * Test the StringValue class
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class StringValueTest
{
    private static EntryUtils.S s;
    private static EntryUtils.AT at;
    private static EntryUtils.MR mr;


    /**
     * Initialize an AttributeType and the associated MatchingRule 
     * and Syntax
     */
    @BeforeClass
    public static void initAT()
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


    //----------------------------------------------------------------------------------
    // Helper method
    //----------------------------------------------------------------------------------
    /**
     * Serialize a StringValue
     */
    private ByteArrayOutputStream serializeValue( StringValue value ) throws IOException
    {
        ObjectOutputStream oOut = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        oOut = new ObjectOutputStream( out );
        value.writeExternal( oOut );

        return out;
    }


    /**
     * Deserialize a StringValue
     */
    private StringValue deserializeValue( AttributeType at, ByteArrayOutputStream out ) throws IOException,
        ClassNotFoundException
    {
        ObjectInputStream oIn = null;
        ByteArrayInputStream in = new ByteArrayInputStream( out.toByteArray() );

        try
        {
            oIn = new ObjectInputStream( in );

            StringValue value = new StringValue( at );
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


    //----------------------------------------------------------------------------------
    // Test the clone() method
    //----------------------------------------------------------------------------------
    /**
     * Test cloning an empty value
     */
    @Test
    public void testCloneEmptyValue() throws LdapException
    {
        StringValue sv = new StringValue( ( String ) null );

        StringValue sv1 = ( StringValue ) sv.clone();

        assertEquals( sv, sv1 );

        StringValue sv2 = new StringValue( "" );

        assertNotSame( sv2, sv1 );
        assertNull( sv1.getValue() );
        assertEquals( "", sv2.getString() );
    }


    /**
     * Test cloning a value
     */
    @Test
    public void testCloneValue() throws LdapException
    {
        StringValue sv = new StringValue( "  This is    a   TEST  " );

        StringValue sv1 = ( StringValue ) sv.clone();

        sv1 = sv.clone();

        assertEquals( sv, sv1 );
        assertEquals( "  This is    a   TEST  ", sv.getString() );

        sv.apply( at );

        assertNotSame( sv, sv1 );
        assertEquals( "  This is    a   TEST  ", sv1.getString() );
        assertEquals( "  This is    a   TEST  ", sv1.getNormValue() );
        assertEquals( "  This is    a   TEST  ", sv.getString() );
        assertEquals( "this is a test", sv.getNormValue() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#hashCode()}.
     */
    @Test
    public void testHashCode()
    {
        StringValue csv = new StringValue( "test" );

        int hash = "test".hashCode();
        assertEquals( hash, csv.hashCode() );

        csv = new StringValue( ( String ) null );
        hash = "".hashCode();
        assertEquals( hash, csv.hashCode() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#ClientStringValue()}.
     */
    @Test
    public void testClientStringValueNull() throws LdapException
    {
        StringValue csv = new StringValue( ( String ) null );

        assertNull( csv.getValue() );
        assertFalse( csv.isSchemaAware() );
        assertTrue( csv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
        assertTrue( csv.isNull() );
        assertNull( csv.getNormValue() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#ClientStringValue(java.lang.String)}.
     */
    @Test
    public void testClientStringValueEmpty() throws LdapException
    {
        StringValue csv = new StringValue( "" );

        assertNotNull( csv.getValue() );
        assertEquals( "", csv.getString() );
        assertFalse( csv.isSchemaAware() );
        assertTrue( csv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
        assertFalse( csv.isNull() );
        assertNotNull( csv.getNormValue() );
        assertEquals( "", csv.getNormValue() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#ClientStringValue(java.lang.String)}.
     */
    @Test
    public void testClientStringValueString() throws LdapException
    {
        StringValue csv = new StringValue( "test" );

        assertEquals( "test", csv.getValue() );
        assertFalse( csv.isSchemaAware() );
        assertTrue( csv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
        assertFalse( csv.isNull() );
        assertNotNull( csv.getNormValue() );
        assertEquals( "test", csv.getNormValue() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#getValue()}.
     */
    @Test
    public void testGet()
    {
        StringValue sv = new StringValue( "test" );
        assertEquals( "test", sv.getValue() );

        StringValue sv2 = new StringValue( "" );
        assertEquals( "", sv2.getValue() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#getCopy()}.
     */
    @Test
    public void testGetCopy()
    {
        StringValue sv = new StringValue( "test" );

        assertEquals( "test", sv.getValue() );

        StringValue sv2 = new StringValue( "" );
        assertEquals( "", sv2.getValue() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#set(java.lang.String)}.
     */
    @Test
    public void testSet() throws LdapException
    {
        StringValue sv = new StringValue( ( String ) null );

        assertNull( sv.getValue() );
        assertFalse( sv.isSchemaAware() );
        assertTrue( sv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
        assertTrue( sv.isNull() );

        sv = new StringValue( "" );
        assertNotNull( sv.getValue() );
        assertEquals( "", sv.getValue() );
        assertFalse( sv.isSchemaAware() );
        assertTrue( sv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
        assertFalse( sv.isNull() );

        sv = new StringValue( "Test" );
        assertNotNull( sv.getValue() );
        assertEquals( "Test", sv.getValue() );
        assertFalse( sv.isSchemaAware() );
        assertTrue( sv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
        assertFalse( sv.isNull() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#isNull()}.
     */
    @Test
    public void testIsNull()
    {
        StringValue sv = new StringValue( ( String ) null );
        assertTrue( sv.isNull() );

        sv = new StringValue( "test" );
        assertFalse( sv.isNull() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#isSchemaAware()}.
     */
    @Test
    public void testIsNormalized() throws LdapException
    {
        StringValue sv = new StringValue( "  This is    a   TEST  " );

        assertFalse( sv.isSchemaAware() );

        sv.apply( at );

        assertEquals( "this is a test", sv.getNormValue() );
        assertTrue( sv.isSchemaAware() );

        sv = new StringValue( "test" );
        assertFalse( sv.isSchemaAware() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#setNormalized(boolean)}.
     */
    @Test
    public void testSetNormalized() throws LdapException
    {
        StringValue sv = new StringValue( ( String ) null );

        assertFalse( sv.isSchemaAware() );

        sv = new StringValue( "  This is    a   TEST  " );
        assertFalse( sv.isSchemaAware() );

        sv.apply( at );

        assertEquals( "this is a test", sv.getNormValue() );
        assertTrue( sv.isSchemaAware() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#getNormValue()}.
     */
    @Test
    public void testGetNormalizedValue() throws LdapException
    {
        StringValue sv = new StringValue( ( String ) null );

        assertEquals( null, sv.getNormValue() );

        sv = new StringValue( "  This is    a   TEST  " );
        assertEquals( "  This is    a   TEST  ", sv.getNormValue() );

        sv.apply( at );

        assertEquals( "this is a test", sv.getNormValue() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#getNormValue()}.
     */
    @Test
    public void getNormValueCopy() throws LdapException
    {
        StringValue sv = new StringValue( ( String ) null );

        assertEquals( null, sv.getNormValue() );

        sv = new StringValue( "  This is    a   TEST  " );
        assertEquals( "  This is    a   TEST  ", sv.getNormValue() );

        sv.apply( at );

        assertEquals( "this is a test", sv.getNormValue() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#normalize(org.apache.directory.api.ldap.model.schema.Normalizer)}.
     */
    @Test
    public void testNormalize() throws LdapException
    {
        StringValue sv = new StringValue( ( String ) null );

        sv.apply( at );
        assertEquals( null, sv.getNormValue() );

        sv = new StringValue( "" );
        sv.apply( at );
        assertEquals( "", sv.getNormValue() );

        sv = new StringValue( "  This is    a   TEST  " );
        assertEquals( "  This is    a   TEST  ", sv.getNormValue() );

        sv.apply( at );

        assertEquals( "this is a test", sv.getNormValue() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#isValid(org.apache.directory.api.ldap.model.schema.SyntaxChecker)}.
     */
    @Test
    public void testIsValid() throws LdapException
    {
        StringValue sv = new StringValue( "Test" );

        assertTrue( sv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );

        sv = new StringValue( "é" );
        assertFalse( sv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#compareTo(org.apache.directory.api.ldap.model.entry.Value)}.
     */
    @Test
    public void testCompareTo() throws LdapException
    {
        StringValue sv1 = new StringValue( ( String ) null );
        StringValue sv2 = new StringValue( ( String ) null );

        assertEquals( 0, sv1.compareTo( sv2 ) );

        sv1 = new StringValue( "Test" );
        assertEquals( 1, sv1.compareTo( sv2 ) );
        assertEquals( -1, sv2.compareTo( sv1 ) );

        sv2 = new StringValue( "Test" );
        assertEquals( 0, sv1.compareTo( sv2 ) );

        // Now check that the equals method works on normalized values.
        sv1 = new StringValue( "  This is    a TEST   " );
        sv2 = new StringValue( "this is a test" );
        sv1.apply( at );
        assertEquals( 0, sv1.compareTo( sv2 ) );

        sv1 = new StringValue( "a" );
        sv2 = new StringValue( "b" );
        assertEquals( -1, sv1.compareTo( sv2 ) );

        sv1 = new StringValue( "b" );
        sv2 = new StringValue( "a" );
        assertEquals( 1, sv1.compareTo( sv2 ) );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#equals(java.lang.Object)}.
     */
    @Test
    public void testEquals() throws LdapException
    {
        StringValue sv1 = new StringValue( ( String ) null );
        StringValue sv2 = new StringValue( ( String ) null );

        assertEquals( sv1, sv2 );

        sv1 = new StringValue( "Test" );
        assertNotSame( sv1, sv2 );

        sv2 = new StringValue( "Test" );
        assertEquals( sv1, sv2 );

        // Now check that the equals method works on normalized values.
        sv1 = new StringValue( "  This is    a TEST   " );
        sv2 = new StringValue( "this is a test" );
        sv1.apply( at );
        assertEquals( sv1, sv2 );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.StringValue#toString()}.
     */
    @Test
    public void testToString()
    {
        StringValue sv = new StringValue( ( String ) null );

        assertEquals( "null", sv.toString() );

        sv = new StringValue( "" );
        assertEquals( "", sv.toString() );

        sv = new StringValue( "Test" );
        assertEquals( "Test", sv.toString() );
    }


    /**
     * Test the serialization of a CSV with a value and a normalized value
     */
    @Test
    public void testSerializeStandard() throws LdapException, IOException, ClassNotFoundException
    {
        StringValue csv = new StringValue( "TEST" );
        csv.apply( at );
        csv.isValid( Ia5StringSyntaxChecker.INSTANCE );

        StringValue csvSer = deserializeValue( at, serializeValue( csv ) );
        assertNotSame( csv, csvSer );
        assertEquals( csv.getValue(), csvSer.getValue() );
        assertEquals( csv.getNormValue(), csvSer.getNormValue() );
        assertTrue( csvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CSV with a value and no normalized value
     */
    @Test
    public void testSerializeNotNormalized() throws LdapException, IOException, ClassNotFoundException
    {
        StringValue csv = new StringValue( "Test" );
        csv.isValid( Ia5StringSyntaxChecker.INSTANCE );

        StringValue csvSer = deserializeValue( null, serializeValue( csv ) );
        assertNotSame( csv, csvSer );
        assertEquals( csv.getValue(), csvSer.getValue() );
        assertEquals( csv.getValue(), csvSer.getNormValue() );
        assertFalse( csvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CSV with a value and an empty normalized value
     */
    @Test
    public void testSerializeEmptyNormalized() throws LdapException, IOException, ClassNotFoundException
    {
        StringValue csv = new StringValue( "  " );
        csv.isValid( Ia5StringSyntaxChecker.INSTANCE );
        csv.apply( at );

        StringValue csvSer = deserializeValue( at, serializeValue( csv ) );
        assertNotSame( csv, csvSer );
        assertEquals( csv.getValue(), csvSer.getValue() );
        assertEquals( csv.getNormValue(), csvSer.getNormValue() );
        assertTrue( csvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CSV with a null value
     */
    @Test
    public void testSerializeNullValue() throws LdapException, IOException, ClassNotFoundException
    {
        StringValue csv = new StringValue( ( String ) null );
        csv.isValid( Ia5StringSyntaxChecker.INSTANCE );
        csv.apply( at );

        StringValue csvSer = deserializeValue( at, serializeValue( csv ) );
        assertNotSame( csv, csvSer );
        assertEquals( csv.getValue(), csvSer.getValue() );
        assertEquals( csv.getNormValue(), csvSer.getNormValue() );
        assertTrue( csvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CSV with an empty value
     */
    @Test
    public void testSerializeEmptyValue() throws LdapException, IOException, ClassNotFoundException
    {
        StringValue csv = new StringValue( "" );
        csv.isValid( Ia5StringSyntaxChecker.INSTANCE );
        csv.apply( at );

        StringValue csvSer = deserializeValue( at, serializeValue( csv ) );
        assertNotSame( csv, csvSer );
        assertEquals( csv.getValue(), csvSer.getValue() );
        assertEquals( csv.getNormValue(), csvSer.getNormValue() );
        assertTrue( csvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CSV with an empty value not normalized
     */
    @Test
    public void testSerializeEmptyValueNotNormalized() throws LdapException, IOException, ClassNotFoundException
    {
        StringValue csv = new StringValue( "" );
        csv.isValid( Ia5StringSyntaxChecker.INSTANCE );

        StringValue csvSer = deserializeValue( null, serializeValue( csv ) );
        assertNotSame( csv, csvSer );
        assertEquals( csv.getValue(), csvSer.getValue() );
        assertEquals( csv.getNormValue(), csvSer.getNormValue() );
        assertFalse( csvSer.isSchemaAware() );
    }
}
