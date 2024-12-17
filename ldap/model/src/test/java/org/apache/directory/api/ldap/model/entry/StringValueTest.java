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
package org.apache.directory.api.ldap.model.entry;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.comparators.StringComparator;
import org.apache.directory.api.ldap.model.schema.normalizers.DeepTrimToLowerNormalizer;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.DirectoryStringSyntaxChecker;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.Ia5StringSyntaxChecker;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * 
 * Test the Value class
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class StringValueTest
{
    private static EntryUtils.S s;
    private static EntryUtils.AT at;
    private static EntryUtils.MR mr;


    /**
     * Initialize an AttributeType and the associated MatchingRule 
     * and Syntax
     */
    @BeforeAll
    public static void initAT()
    {
        s = new EntryUtils.S( "1.1.1.1", true );
        s.setSyntaxChecker( DirectoryStringSyntaxChecker.INSTANCE );
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
     * Serialize a Value
     * 
     * @throws IOException If the test failed
     */
    private ByteArrayOutputStream serializeValue( Value value ) throws IOException
    {
        ObjectOutputStream oOut = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        oOut = new ObjectOutputStream( out );
        value.writeExternal( oOut );

        return out;
    }


    /**
     * Deserialize a Value
     * 
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
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


    //----------------------------------------------------------------------------------
    // Test the clone() method
    //----------------------------------------------------------------------------------
    /**
     * Test cloning an empty value
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testCloneEmptyValue() throws LdapException
    {
        Value sv = new Value( ( String ) null );

        Value sv1 = ( Value ) sv.clone();

        assertEquals( sv, sv1 );

        Value sv2 = new Value( "" );

        assertNotSame( sv2, sv1 );
        assertNull( sv1.getString() );
        assertEquals( "", sv2.getString() );
    }


    /**
     * Test cloning a value
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testCloneValue() throws LdapException
    {
        Value sv = new Value( "  This is    a   TEST  " );

        Value sv1 = ( Value ) sv.clone();

        sv1 = sv.clone();

        assertEquals( sv, sv1 );
        assertEquals( "  This is    a   TEST  ", sv.getString() );

        sv = new Value( at, sv );

        assertNotSame( sv, sv1 );
        assertEquals( "  This is    a   TEST  ", sv1.getString() );
        assertEquals( 0, sv.compareTo( "  This is    a   TEST  " ) );
        assertEquals( "  This is    a   TEST  ", sv.getString() );
        assertEquals( 0, sv.compareTo( " this  is  a  test " ) );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#hashCode()}.
     */
    @Test
    public void testHashCode()
    {
        Value csv = new Value( "test" );

        int hash = "test".hashCode();
        assertEquals( hash, csv.hashCode() );

        csv = new Value( ( String ) null );
        assertEquals( 0, csv.hashCode() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#Value(java.lang.String)}.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testClientStringValueNull() throws LdapException
    {
        Value csv = new Value( ( String ) null );

        assertNull( csv.getString() );
        assertFalse( csv.isSchemaAware() );
        assertTrue( csv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
        assertTrue( csv.isNull() );
        assertEquals( 0, csv.compareTo( ( String ) null ) );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#Value(java.lang.String)}.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testClientStringValueEmpty() throws LdapException
    {
        Value csv = new Value( "" );

        assertNotNull( csv.getString() );
        assertEquals( "", csv.getString() );
        assertFalse( csv.isSchemaAware() );
        assertTrue( csv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
        assertFalse( csv.isNull() );
        assertEquals( 0, csv.compareTo( "" ) );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#Value(java.lang.String)}.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testClientStringValueString() throws LdapException
    {
        Value csv = new Value( "test" );

        assertEquals( "test", csv.getString() );
        assertFalse( csv.isSchemaAware() );
        assertTrue( csv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
        assertFalse( csv.isNull() );
        assertEquals( 0, csv.compareTo( "test" ) );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#getString()}.
     */
    @Test
    public void testGet()
    {
        Value sv = new Value( "test" );
        assertEquals( "test", sv.getString() );

        Value sv2 = new Value( "" );
        assertEquals( "", sv2.getString() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#getString()}.
     */
    @Test
    public void testGetCopy()
    {
        Value sv = new Value( "test" );

        assertEquals( "test", sv.getString() );

        Value sv2 = new Value( "" );
        assertEquals( "", sv2.getString() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#Value(java.lang.String)}.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testSet() throws LdapException
    {
        Value sv = new Value( ( String ) null );

        assertNull( sv.getString() );
        assertFalse( sv.isSchemaAware() );
        assertTrue( sv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
        assertTrue( sv.isNull() );

        sv = new Value( "" );
        assertNotNull( sv.getString() );
        assertEquals( "", sv.getString() );
        assertFalse( sv.isSchemaAware() );
        assertTrue( sv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
        assertFalse( sv.isNull() );

        sv = new Value( "Test" );
        assertNotNull( sv.getString() );
        assertEquals( "Test", sv.getString() );
        assertFalse( sv.isSchemaAware() );
        assertTrue( sv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
        assertFalse( sv.isNull() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#isNull()}.
     */
    @Test
    public void testIsNull()
    {
        Value sv = new Value( ( String ) null );
        assertTrue( sv.isNull() );

        sv = new Value( "test" );
        assertFalse( sv.isNull() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#isSchemaAware()}.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testIsNormalized() throws LdapException
    {
        Value sv = new Value( "  This is    a   TEST  " );

        assertFalse( sv.isSchemaAware() );

        sv = new Value( at, sv );

        assertEquals( 0, sv.compareTo( " this  is  a  test " ) );
        assertTrue( sv.isSchemaAware() );

        sv = new Value( "test" );
        assertFalse( sv.isSchemaAware() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#Value(java.lang.String)}.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testSetNormalized() throws LdapException
    {
        Value sv = new Value( ( String ) null );

        assertFalse( sv.isSchemaAware() );

        sv = new Value( "  This is    a   TEST  " );
        assertFalse( sv.isSchemaAware() );

        sv = new Value( at, sv );

        assertEquals( 0, sv.compareTo( " this  is  a  test " ) );
        assertTrue( sv.isSchemaAware() );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#compareTo(java.lang.String)}.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testGetNormalizedValue() throws LdapException
    {
        Value sv = new Value( ( String ) null );

        assertEquals( 0, sv.compareTo( ( String ) null ) );

        sv = new Value( "  This is    a   TEST  " );
        assertEquals( 0, sv.compareTo( "  This is    a   TEST  " ) );

        sv = new Value( at, sv );

        assertEquals( 0, sv.compareTo( " this  is  a  test " ) );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#compareTo(java.lang.String)}.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void getNormValueCopy() throws LdapException
    {
        Value sv = new Value( ( String ) null );

        assertEquals( 0, sv.compareTo( ( String ) null ) );

        sv = new Value( "  This is    a   TEST  " );
        assertEquals( 0, sv.compareTo( "  This is    a   TEST  " ) );

        sv = new Value( at, sv );

        assertEquals( 0, sv.compareTo( " this  is  a  test " ) );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#compareTo(java.lang.String)}.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testNormalize() throws LdapException
    {
        Value sv = new Value( ( String ) null );

        sv = new Value( at, sv );
        assertEquals( 0, sv.compareTo( ( String ) null ) );

        sv = new Value( "" );
        sv = new Value( at, sv );
        assertEquals( 0, sv.compareTo( "  " ) );

        sv = new Value( "  This is    a   TEST  " );
        assertEquals( 0, sv.compareTo( "  This is    a   TEST  " ) );

        sv = new Value( at, sv );

        assertEquals( 0, sv.compareTo( " this  is  a  test " ) );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#isValid(org.apache.directory.api.ldap.model.schema.SyntaxChecker)}.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testIsValid() throws LdapException
    {
        Value sv = new Value( "Test" );

        assertTrue( sv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );

        sv = new Value( "é" );
        assertFalse( sv.isValid( Ia5StringSyntaxChecker.INSTANCE ) );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#compareTo(org.apache.directory.api.ldap.model.entry.Value)}.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testCompareTo() throws LdapException
    {
        Value sv1 = new Value( ( String ) null );
        Value sv2 = new Value( ( String ) null );

        assertEquals( 0, sv1.compareTo( sv2 ) );

        sv1 = new Value( "Test" );
        assertEquals( 1, sv1.compareTo( sv2 ) );
        assertEquals( -1, sv2.compareTo( sv1 ) );

        sv2 = new Value( "Test" );
        assertEquals( 0, sv1.compareTo( sv2 ) );

        // Now check that the equals method works on normalized values.
        sv1 = new Value( "  This is    a TEST   " );
        sv2 = new Value( "this is a test" );
        sv1 = new Value( at, sv1 );
        assertEquals( 0, sv1.compareTo( sv2 ) );

        sv1 = new Value( "a" );
        sv2 = new Value( "b" );
        assertEquals( -1, sv1.compareTo( sv2 ) );

        sv1 = new Value( "b" );
        sv2 = new Value( "a" );
        assertEquals( 1, sv1.compareTo( sv2 ) );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#equals(java.lang.Object)}.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testEquals() throws LdapException
    {
        Value sv1 = new Value( ( String ) null );
        Value sv2 = new Value( ( String ) null );

        assertEquals( sv1, sv2 );

        sv1 = new Value( "Test" );
        assertNotSame( sv1, sv2 );

        sv2 = new Value( "Test" );
        assertEquals( sv1, sv2 );

        // Now check that the equals method works on normalized values.
        sv1 = new Value( at, "  This is    a TEST   " );
        sv2 = new Value( at,  "this is a test" );
        assertEquals( sv1, sv2 );
    }


    /**
     * Test method for {@link org.apache.directory.api.ldap.model.entry.Value#toString()}.
     */
    @Test
    public void testToString()
    {
        Value sv = new Value( ( String ) null );

        assertEquals( "null", sv.toString() );

        sv = new Value( "" );
        assertEquals( "", sv.toString() );

        sv = new Value( "Test" );
        assertEquals( "Test", sv.toString() );
    }


    /**
     * Test the serialization of a CSV with a value and a normalized value
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSerializeStandard() throws LdapException, IOException, ClassNotFoundException
    {
        Value csv = new Value( "TEST" );
        csv = new Value( at, csv );
        csv.isValid( Ia5StringSyntaxChecker.INSTANCE );

        Value csvSer = deserializeValue( at, serializeValue( csv ) );
        assertNotSame( csv, csvSer );
        assertEquals( csv.getString(), csvSer.getString() );
        assertEquals( 0, csv.compareTo( csvSer ) );
        assertTrue( csvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CSV with a value and no normalized value
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSerializeNotNormalized() throws LdapException, IOException, ClassNotFoundException
    {
        Value csv = new Value( "Test" );
        csv.isValid( Ia5StringSyntaxChecker.INSTANCE );

        Value csvSer = deserializeValue( null, serializeValue( csv ) );
        assertNotSame( csv, csvSer );
        assertEquals( csv.getString(), csvSer.getString() );
        assertEquals( 0, csv.compareTo( csvSer ) );
        assertFalse( csvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CSV with a value and an empty normalized value
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSerializeEmptyNormalized() throws LdapException, IOException, ClassNotFoundException
    {
        Value csv = new Value( "  " );
        csv.isValid( Ia5StringSyntaxChecker.INSTANCE );
        csv = new Value( at, csv );

        Value csvSer = deserializeValue( at, serializeValue( csv ) );
        assertNotSame( csv, csvSer );
        assertEquals( csv.getString(), csvSer.getString() );
        assertEquals( 0, csv.compareTo( csvSer ) );
        assertTrue( csvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CSV with a null value
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSerializeNullValue() throws LdapException, IOException, ClassNotFoundException
    {
        Value csv = new Value( ( String ) null );
        csv.isValid( Ia5StringSyntaxChecker.INSTANCE );
        csv = new Value( at, csv );

        Value csvSer = deserializeValue( at, serializeValue( csv ) );
        assertNotSame( csv, csvSer );
        assertEquals( csv.getString(), csvSer.getString() );
        assertEquals( 0, csv.compareTo( csvSer ) );
        assertTrue( csvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CSV with an empty value
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSerializeEmptyValue() throws LdapException, IOException, ClassNotFoundException
    {
        Value csv = new Value( "" );
        csv.isValid( Ia5StringSyntaxChecker.INSTANCE );
        csv = new Value( at, csv );

        Value csvSer = deserializeValue( at, serializeValue( csv ) );
        assertNotSame( csv, csvSer );
        assertEquals( csv.getString(), csvSer.getString() );
        assertEquals( 0, csv.compareTo( csvSer ) );
        assertTrue( csvSer.isSchemaAware() );
    }


    /**
     * Test the serialization of a CSV with an empty value not normalized
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSerializeEmptyValueNotNormalized() throws LdapException, IOException, ClassNotFoundException
    {
        Value csv = new Value( "" );
        csv.isValid( Ia5StringSyntaxChecker.INSTANCE );

        Value csvSer = deserializeValue( null, serializeValue( csv ) );
        assertNotSame( csv, csvSer );
        assertEquals( csv.getString(), csvSer.getString() );
        assertEquals( 0, csv.compareTo( csvSer ) );
        assertFalse( csvSer.isSchemaAware() );
    }
}
