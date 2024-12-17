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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Iterator;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Test the class Rdn when it can be parsed by the Fast parser
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class FastRdnParserTest
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
        assertEquals( "a=b", new Rdn( "a = b" ).getNormName() );
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
        assertEquals( "a=b", new Rdn( "a=b" ).getNormName() );
        assertEquals( "a=b", new Rdn( " a=b" ).getNormName() );
        assertEquals( "a=b", new Rdn( "a =b" ).getNormName() );
        assertEquals( "a=b", new Rdn( "a= b" ).getNormName() );
        assertEquals( "a=b", new Rdn( "a=b " ).getNormName() );
        assertEquals( "a=b", new Rdn( " a =b" ).getNormName() );
        assertEquals( "a=b", new Rdn( " a= b" ).getNormName() );
        assertEquals( "a=b", new Rdn( " a=b " ).getNormName() );
        assertEquals( "a=b", new Rdn( "a = b" ).getNormName() );
        assertEquals( "a=b", new Rdn( "a =b " ).getNormName() );
        assertEquals( "a=b", new Rdn( "a= b " ).getNormName() );
        assertEquals( "a=b", new Rdn( " a = b" ).getNormName() );
        assertEquals( "a=b", new Rdn( " a =b " ).getNormName() );
        assertEquals( "a=b", new Rdn( " a= b " ).getNormName() );
        assertEquals( "a=b", new Rdn( "a = b " ).getNormName() );
        assertEquals( "a=b", new Rdn( " a = b " ).getNormName() );
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
        assertEquals( "12.34.56=azerty", new Rdn( "12.34.56 = azerty" ).getNormName() );
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
        assertEquals( "a=  b  ", rdn.getNormName() );
        assertEquals( "A=  b  ", rdn.getName() );
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
     * Test the getSize method.
     *
     */
    @Test
    public void testGetSize0()
    {
        Rdn rdn = new Rdn();

        assertEquals( 0, rdn.size() );
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
        Rdn rdn = new Rdn( schemaManager, "" );

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
        Rdn rdn = new Rdn( schemaManager );

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
        Rdn rdn = new Rdn( schemaManager, "a=b" );

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
        Rdn rdn = new Rdn( schemaManager, " ABC  = DEF " );

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
        Rdn rdn = new Rdn( schemaManager, " ABC  =" );

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
        Rdn rdn = new Rdn( schemaManager, " ABC  = def " );

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


    /**
     * test that a RDN can have an attributeType twice
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testRdnPerf() throws LdapException
    {
        long t0 = System.currentTimeMillis();
        
        for ( int i = 0; i < 10000000; i++ )
        {
            new Rdn( "cn=test"+ i );
        }
        
        long t1 = System.currentTimeMillis();
        
        System.out.println( "Delta = " + ( t1 - t0 ) );
    }
}
