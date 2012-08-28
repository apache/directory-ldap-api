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
package org.apache.directory.shared.ldap.entry;


import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.apache.directory.shared.ldap.model.entry.BinaryValue;
import org.apache.directory.shared.ldap.model.entry.StringValue;
import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.schema.AttributeType;
import org.apache.directory.shared.ldap.model.schema.SchemaManager;
import org.apache.directory.shared.ldap.schemamanager.impl.DefaultSchemaManager;
import org.apache.directory.shared.util.StringConstants;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the Value Serialization
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class SchemaAwareValueSerializationTest
{
    private static byte[] data = new byte[]
        { 0x01, 0x02, 0x03, 0x04 };
    private static BinaryValue bv1;
    private static BinaryValue bv2;
    private static BinaryValue bv3;
    private static BinaryValue bv1n;
    private static BinaryValue bv2n;
    private static BinaryValue bv3n;
    private static StringValue sv1;
    private static StringValue sv2;
    private static StringValue sv3;
    private static StringValue sv1n;
    private static StringValue sv2n;
    private static StringValue sv3n;

    private static SchemaManager schemaManager;
    private static AttributeType cn = null;
    private static AttributeType dc = null;
    private static AttributeType userCertificate = null;


    /**
     * Initialize OIDs maps for normalization
     */
    @BeforeClass
    public static void setup() throws Exception
    {
        schemaManager = new DefaultSchemaManager();
        cn = schemaManager.getAttributeType( "cn" );
        dc = schemaManager.getAttributeType( "dc" );
        userCertificate = schemaManager.getAttributeType( "userCertificate" );

        bv1 = new BinaryValue( userCertificate, data );
        bv2 = new BinaryValue( userCertificate, StringConstants.EMPTY_BYTES );
        bv3 = new BinaryValue( userCertificate, null );
        bv1n = new BinaryValue( userCertificate, data );
        bv2n = new BinaryValue( userCertificate, StringConstants.EMPTY_BYTES );
        bv3n = new BinaryValue( userCertificate, null );
        sv1 = new StringValue( cn, "test" );
        sv2 = new StringValue( dc, "" );
        sv3 = new StringValue( dc, ( String ) null );
        sv1n = new StringValue( cn, "test" );
        sv2n = new StringValue( dc, "" );
        sv3n = new StringValue( dc, ( String ) null );
    }


    @Test
    public void testBinaryValueWithDataSerialization() throws IOException, ClassNotFoundException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        bv1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        BinaryValue bvDeser = BinaryValue.deserialize( in );

        assertEquals( bv1, bvDeser );
    }


    @Test
    public void testBinaryValueWithEmptyDataSerialization() throws IOException, ClassNotFoundException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        bv2.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        BinaryValue bvDeser = BinaryValue.deserialize( in );

        assertEquals( bv2, bvDeser );
    }


    @Test
    public void testBinaryValueNoDataSerialization() throws IOException, ClassNotFoundException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        bv3.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        BinaryValue bvDeser = BinaryValue.deserialize( in );

        assertEquals( bv3, bvDeser );
    }


    @Test
    public void testStringValueWithDataSerialization() throws IOException, ClassNotFoundException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        sv1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        StringValue svDeser = StringValue.deserialize( in );

        assertEquals( sv1, svDeser );
    }


    @Test
    public void testStringValueWithEmptyDataSerialization() throws IOException, ClassNotFoundException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        sv2.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        StringValue svDeser = StringValue.deserialize( in );

        assertEquals( sv2, svDeser );
    }


    @Test
    public void testStringValueNoDataSerialization() throws IOException, ClassNotFoundException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        sv3.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        StringValue svDeser = StringValue.deserialize( in );

        assertEquals( sv3, svDeser );
    }


    @Test
    public void testBinaryValueWithDataNormalizedSerialization() throws IOException, LdapException,
        ClassNotFoundException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );
        bv1n.apply( userCertificate );

        bv1n.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        BinaryValue bvDeser = BinaryValue.deserialize( userCertificate, in );

        assertEquals( bv1n, bvDeser );
    }


    @Test
    public void testBinaryValueWithEmptyDataNormalizedSerialization() throws IOException, LdapException,
        ClassNotFoundException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );
        bv2n.apply( userCertificate );

        bv2n.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        BinaryValue bvDeser = BinaryValue.deserialize( userCertificate, in );

        assertEquals( bv2n, bvDeser );
    }


    @Test
    public void testBinaryValueNoDataNormalizedSerialization() throws IOException, LdapException,
        ClassNotFoundException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );
        bv3n.apply( userCertificate );

        bv3n.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        BinaryValue bvDeser = BinaryValue.deserialize( userCertificate, in );

        assertEquals( bv3n, bvDeser );
    }


    @Test
    public void testStringValueWithDataNormalizedSerialization() throws IOException, LdapException,
        ClassNotFoundException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );
        sv1n.apply( cn );

        sv1n.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        StringValue svDeser = StringValue.deserialize( cn, in );

        assertEquals( sv1n, svDeser );
    }


    @Test
    public void testStringValueWithEmptyDataNormalizedSerialization() throws IOException, LdapException,
        ClassNotFoundException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );
        sv2n.apply( dc );

        sv2n.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        StringValue svDeser = StringValue.deserialize( cn, in );

        assertEquals( sv2n, svDeser );
    }


    @Test
    public void testStringValueNoDataNormalizedSerialization() throws IOException, LdapException,
        ClassNotFoundException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );
        sv3n.apply( dc );

        sv3n.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        StringValue svDeser = StringValue.deserialize( cn, in );

        assertEquals( sv3n, svDeser );
    }
}
