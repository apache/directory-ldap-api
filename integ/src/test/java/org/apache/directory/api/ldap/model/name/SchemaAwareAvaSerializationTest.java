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
package org.apache.directory.api.ldap.model.name;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.Strings;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;


/**
 * Test the class AttributeTypeAndValue
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SchemaAwareAvaSerializationTest
{
    private static SchemaManager schemaManager;


    @BeforeClass
    public static void setup() throws Exception
    {
        schemaManager = new DefaultSchemaManager();
    }


    /**
     * Test serialization of a simple ATAV
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


    /**
     * Test serialization of a simple ATAV
     */
    @Test
    public void testStringAtavSerializationBytes() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] buffer = new byte[128];
        Ava atav = new Ava( schemaManager, "CN", "Test" );

        int pos1 = atav.serialize( buffer, 0 );

        Ava atav2 = new Ava( schemaManager );
        int pos2 = atav2.deserialize( buffer, 0 );

        assertEquals( pos1, pos2 );
        assertEquals( atav, atav2 );
    }


    @Test
    public void testBinaryAtavSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] normValue = Strings.getBytesUtf8( "Test" );

        Ava atav = new Ava( schemaManager, "userPKCS12", normValue );

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


    @Ignore
    @Test
    public void testBinaryAtavSerializationBytes() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] buffer = new byte[128];
        byte[] normValue = Strings.getBytesUtf8( "Test" );

        Ava atav = new Ava( schemaManager, "userPKCS12", normValue );

        int pos1 = atav.serialize( buffer, 0 );

        Ava atav2 = new Ava( schemaManager );
        int pos2 = atav2.deserialize( buffer, 0 );

        assertEquals( pos1, pos2 );
        assertEquals( atav, atav2 );
    }


    /**
     * Test serialization of a simple ATAV
     */
    @Test
    public void testNullAtavSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager );

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


    /**
     * Test serialization of a simple ATAV
     */
    @Test
    public void testNullAtavSerializationBytes() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] buffer = new byte[128];
        Ava atav = new Ava( schemaManager );

        try
        {
            atav.serialize( buffer, 0 );
            fail();
        }
        catch ( IOException ioe )
        {
            assertTrue( true );
        }
    }


    @Test
    public void testNullUpValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "dc", ( String ) null );

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
            assertEquals( "Cannot serialize a wrong ATAV, the value should not be null", message );
        }
    }


    @Test
    public void testNullUpValueSerializationBytes() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] buffer = new byte[128];
        Ava atav = new Ava( schemaManager, "dc", ( String ) null );

        try
        {
            atav.serialize( buffer, 0 );
            fail();
        }
        catch ( IOException ioe )
        {
            String message = ioe.getMessage();
            assertEquals( "Cannot serialize an wrong ATAV, the value should not be null", message );
        }
    }


    @Test
    public void testEmptyNormValueSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "DC", "" );

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
    public void testEmptyNormValueSerializationBytes() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] buffer = new byte[128];
        Ava atav = new Ava( schemaManager, "DC", "" );

        int pos1 = atav.serialize( buffer, 0 );

        Ava atav2 = new Ava( schemaManager );
        int pos2 = atav2.deserialize( buffer, 0 );

        assertEquals( pos1, pos2 );
        assertEquals( atav, atav2 );
    }


    /**
     * Test serialization of a simple ATAV
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


    /**
     * Test serialization of a simple ATAV
     */
    @Test
    public void testStringAtavStaticSerializationBytes() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] buffer = new byte[128];
        Ava atav = new Ava( schemaManager, "CN", "Test" );

        int pos1 = atav.serialize( buffer, 0 );

        Ava atav2 = new Ava( schemaManager );
        int pos2 = atav2.deserialize( buffer, 0 );

        assertEquals( pos1, pos2 );
        assertEquals( atav, atav2 );
    }


    @Test
    public void testBinaryAtavStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] upValue = Strings.getBytesUtf8( "  Test  " );

        Ava atav = new Ava( schemaManager, "userPKCS12", upValue );

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


    @Ignore
    @Test
    public void testBinaryAtavStaticSerializationBytes() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] buffer = new byte[128];
        byte[] upValue = Strings.getBytesUtf8( "  Test  " );

        Ava atav = new Ava( schemaManager, "userPKCS12", upValue );

        int pos1 = atav.serialize( buffer, 0 );

        Ava atav2 = new Ava( schemaManager );
        int pos2 = atav2.deserialize( buffer, 0 );

        assertEquals( pos1, pos2 );
        assertEquals( atav, atav2 );
    }


    /**
     * Test static serialization of a simple ATAV
     */
    @Test
    public void testNullAtavStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager );

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


    /**
     * Test static serialization of a simple ATAV
     */
    @Test
    public void testNullAtavStaticSerializationBytes() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] buffer = new byte[128];
        Ava atav = new Ava( schemaManager );

        try
        {
            atav.serialize( buffer, 0 );
            fail();
        }
        catch ( IOException ioe )
        {
            assertTrue( true );
        }
    }


    @Test(expected = IOException.class)
    public void testNullNormValueStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] buffer = new byte[128];
        Ava atav = new Ava( schemaManager, "DC", ( String ) null );

        atav.serialize( buffer, 0 );
        fail();
    }


    @Test(expected = IOException.class)
    public void testNullNormValueStaticSerializationBytes() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "DC", ( String ) null );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        atav.writeExternal( out );
        fail();
    }


    @Test
    public void testEmptyNormValueStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "DC", "" );

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
    public void testEmptyNormValueStaticSerializationBytes() throws LdapException, IOException, ClassNotFoundException
    {
        byte[] buffer = new byte[128];
        Ava atav = new Ava( schemaManager, "DC", "" );

        int pos1 = atav.serialize( buffer, 0 );

        Ava atav2 = new Ava( schemaManager );
        int pos2 = atav2.deserialize( buffer, 0 );

        assertEquals( pos1, pos2 );
        assertEquals( atav, atav2 );
    }


    @Ignore
    @Test
    public void testStringAtavSerializationPerf() throws IOException, LdapException,
        ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "CN", "Test" );
        Ava atav2 = new Ava( schemaManager );

        long t0 = System.currentTimeMillis();

        for ( int i = 0; i < 10000000; i++ )
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream out = new ObjectOutputStream( baos );

            atav.writeExternal( out );

            ObjectInputStream in = null;

            byte[] data = baos.toByteArray();
            in = new ObjectInputStream( new ByteArrayInputStream( data ) );

            atav2.readExternal( in );
        }

        long t1 = System.currentTimeMillis();

        System.out.println( "Delta ser slow = " + ( t1 - t0 ) );
    }


    @Ignore
    @Test
    public void testStringAtavSerializationBytesPerf() throws IOException, LdapException,
        ClassNotFoundException
    {
        Ava atav = new Ava( schemaManager, "CN", "Test" );
        Ava atav2 = new Ava( schemaManager );

        long t0 = System.currentTimeMillis();

        for ( int i = 0; i < 10000000; i++ )
        {
            byte[] buffer = new byte[128];
            atav.serialize( buffer, 0 );
            atav2.deserialize( buffer, 0 );
        }

        long t1 = System.currentTimeMillis();

        System.out.println( "Delta ser fast = " + ( t1 - t0 ) );
    }
}
