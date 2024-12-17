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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.text.ParseException;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Test the AttributeTypeAndValue class serialization
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class AvaSerializationTest
{
    /** A null schemaManager used in tests */
    SchemaManager schemaManager = null;


    /**
     * Test serialization of a simple ATAV
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testStringAtavSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "CN", "Test" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        atav.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Ava atav2 = new Ava( schemaManager );
        atav2.readExternal( in );

        assertEquals( atav, atav2 );
    }


    @Test
    public void testBinaryAtavSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] upValue = Strings.getBytesUtf8( "  Test  " );

        Ava atav = new Ava( schemaManager, "CN", upValue );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        atav.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Ava atav2 = new Ava( schemaManager );
        atav2.readExternal( in );

        assertEquals( atav, atav2 );
    }


    /**
     * Test serialization of a simple ATAV
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testNullAtavSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        try
        {
            atav.writeExternal( out );
            fail();
        }
        catch ( IOException ioe )
        {
            assertTrue( true );
        }
    }


    @Test
    public void testNullNormValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "CN", ( String ) null );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        try
        {
            atav.writeExternal( out );
            fail();
        }
        catch ( IOException ioe )
        {
            String message = ioe.getMessage();
            assertEquals( "ERR_13619_CANNOT_SERIALIZE_AVA_VALUE_NULL Cannot serialize a wrong ATAV, the value should not be null", message );
        }
    }


    @Test
    public void testNullUpValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "CN", ( String ) null );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        try
        {
            atav.writeExternal( out );
            fail();
        }
        catch ( IOException ioe )
        {
            String message = ioe.getMessage();
            assertEquals( "ERR_13619_CANNOT_SERIALIZE_AVA_VALUE_NULL Cannot serialize a wrong ATAV, the value should not be null", message );
        }
    }


    @Test
    public void testEmptyNormValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "CN", "test" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        atav.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Ava atav2 = new Ava( schemaManager );
        atav2.readExternal( in );

        assertEquals( atav, atav2 );
    }


    @Test
    public void testEmptyUpValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "CN", "" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        atav.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Ava atav2 = new Ava( schemaManager );
        atav2.readExternal( in );

        assertEquals( atav, atav2 );
    }


    /**
     * Test serialization of a simple ATAV
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testStringAtavStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "CN", "Test" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        atav.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Ava atav2 = new Ava( schemaManager );
        atav2.readExternal( in );

        assertEquals( atav, atav2 );
    }


    @Test
    public void testBinaryAtavStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] upValue = Strings.getBytesUtf8( "  Test  " );

        Ava atav = new Ava( schemaManager, "CN", upValue );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        atav.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Ava atav2 = new Ava( schemaManager );
        atav2.readExternal( in );

        assertEquals( atav, atav2 );
    }


    /**
     * Test static serialization of a simple ATAV
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testNullAtavStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        try
        {
            atav.writeExternal( out );
            fail();
        }
        catch ( IOException ioe )
        {
            assertTrue( true );
        }
    }


    @Test
    public void testNullUpValueStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "CN", ( String ) null );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        try
        {
            atav.writeExternal( out );
            fail();
        }
        catch ( IOException ioe )
        {
            String message = ioe.getMessage();
            assertEquals( "ERR_13619_CANNOT_SERIALIZE_AVA_VALUE_NULL Cannot serialize a wrong ATAV, the value should not be null", message );
        }
    }


    @Test
    public void testEmptyNormValueStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "CN", "" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        atav.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Ava atav2 = new Ava( schemaManager );
        atav2.readExternal( in );

        assertEquals( atav, atav2 );
    }


    @Test
    public void testEmptyUpValueStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "CN", "" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        atav.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Ava atav2 = new Ava( schemaManager );
        atav2.readExternal( in );

        assertEquals( atav, atav2 );
    }


    @Test
    @Disabled
    public void testSerializationPerf() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "cn", "This is a serialization test" );

        long t0 = System.currentTimeMillis();
        
        for ( int j = 0; j < 1000; j++ )
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream out = new ObjectOutputStream( baos );
            
            for ( int i = 0; i < 100000; i++ )
            {
        
                atav.writeExternal( out );
                
                out.flush();
            }
        
            out.close();
            baos.close();
        }
        
        long t1 = System.currentTimeMillis();
        System.out.println( "delta AVA new serialization : " + ( t1 - t0 ) );
    }
}
