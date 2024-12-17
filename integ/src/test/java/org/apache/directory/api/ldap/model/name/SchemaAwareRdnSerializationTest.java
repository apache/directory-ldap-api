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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the Rdn Serialization
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class SchemaAwareRdnSerializationTest
{
    private static SchemaManager schemaManager;


    /**
     * Initialize OIDs maps for normalization
     * 
     * @throws Exception If the setup failed
     */
    @BeforeAll
    public static void setup() throws Exception
    {
        schemaManager = new DefaultSchemaManager();
    }


    @Test
    public void testRdnFullSerialization() throws IOException, LdapException, ClassNotFoundException
    {
        Rdn rdn1 = new Rdn( schemaManager, "gn=john + cn=doe" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn( schemaManager );
        rdn2.readExternal( in );

        assertEquals( rdn1, rdn2 );
    }


    @Test
    public void testRdnFullSerializationBytes() throws IOException, LdapException, ClassNotFoundException
    {
        byte[] buffer = new byte[256];
        Rdn rdn1 = new Rdn( schemaManager, "gn=john + cn=doe" );

        int pos1 = rdn1.serialize( buffer, 0 );

        Rdn rdn2 = new Rdn( schemaManager );
        int pos2 = rdn2.deserialize( buffer, 0 );

        assertEquals( pos1, pos2 );
        assertEquals( rdn1, rdn2 );
    }


    @Test
    public void testRdnEmptySerialization() throws IOException, LdapException, ClassNotFoundException
    {
        Rdn rdn1 = new Rdn( schemaManager );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn( schemaManager );
        rdn2.readExternal( in );

        assertEquals( rdn1, rdn2 );
    }


    @Test
    public void testRdnEmptySerializationBytes() throws IOException, LdapException, ClassNotFoundException
    {
        byte[] buffer = new byte[256];
        Rdn rdn1 = new Rdn( schemaManager );

        int pos1 = rdn1.serialize( buffer, 0 );

        Rdn rdn2 = new Rdn( schemaManager );
        int pos2 = rdn2.deserialize( buffer, 0 );

        assertEquals( pos1, pos2 );
        assertEquals( rdn1, rdn2 );
    }


    @Test
    public void testRdnSimpleSerialization() throws IOException, LdapException, ClassNotFoundException
    {
        Rdn rdn1 = new Rdn( schemaManager, "cn=Doe" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn( schemaManager );
        rdn2.readExternal( in );

        assertEquals( rdn1, rdn2 );
        assertEquals( "Doe", rdn2.getValue( "cn" ) );
        assertEquals( "Doe", rdn2.getValue() );
    }


    @Test
    public void testRdnSimpleSerializationBytes() throws IOException, LdapException, ClassNotFoundException
    {
        byte[] buffer = new byte[256];
        Rdn rdn1 = new Rdn( schemaManager, "cn=Doe" );

        int pos1 = rdn1.serialize( buffer, 0 );

        Rdn rdn2 = new Rdn( schemaManager );
        int pos2 = rdn2.deserialize( buffer, 0 );

        assertEquals( pos1, pos2 );
        assertEquals( rdn1, rdn2 );
        assertEquals( "Doe", rdn2.getValue( "cn" ) );
        assertEquals( "Doe", rdn2.getValue() );
    }


    @Disabled
    @Test
    public void testRdnFullSerializationPerf() throws IOException, LdapException, ClassNotFoundException
    {
        Rdn rdn1 = new Rdn( schemaManager, "gn=john + cn=doe" );
        Rdn rdn2 = new Rdn( schemaManager );

        long t0 = System.currentTimeMillis();

        for ( int i = 0; i < 5000000; i++ )
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream out = new ObjectOutputStream( baos );

            rdn1.writeExternal( out );

            ObjectInputStream in = null;

            byte[] data = baos.toByteArray();
            in = new ObjectInputStream( new ByteArrayInputStream( data ) );

            rdn2.readExternal( in );
        }

        long t1 = System.currentTimeMillis();

        System.out.println( "Delta ser slow = " + ( t1 - t0 ) );
    }


    @Disabled
    @Test
    public void testRdnFullSerializationBytesPerf() throws IOException, LdapException, ClassNotFoundException
    {
        Rdn rdn1 = new Rdn( schemaManager, "gn=john + cn=doe" );
        Rdn rdn2 = new Rdn( schemaManager );

        long t0 = System.currentTimeMillis();

        for ( int i = 0; i < 5000000; i++ )
        {
            byte[] buffer = new byte[256];
            rdn1.serialize( buffer, 0 );
            rdn2.deserialize( buffer, 0 );
        }

        long t1 = System.currentTimeMillis();

        System.out.println( "Delta ser fast = " + ( t1 - t0 ) );
    }
}
