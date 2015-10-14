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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the EntryAttribute Serialization
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class AttributeSerializationTest
{
    private static byte[] data1 = new byte[]
        { 0x01, 0x02, 0x03, 0x04 };
    private static byte[] data2 = new byte[]
        { 0x05, 0x06, 0x07, 0x08 };
    private static byte[] data3 = new byte[]
        { 0x09, 0x0A, 0x0B, 0x0C };


    @Test
    public void testEntryAttributeNoStringValueSerialization() throws IOException, ClassNotFoundException
    {
        Attribute attribute1 = new DefaultAttribute( "CN" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutput out = new ObjectOutputStream( baos );

        attribute1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Attribute attribute2 = new DefaultAttribute();
        attribute2.readExternal( in );

        assertEquals( attribute1, attribute2 );
    }


    @Test
    public void testEntryAttributeOneStringValueSerialization() throws IOException, ClassNotFoundException
    {
        Attribute attribute1 = new DefaultAttribute( "CN", "test" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        attribute1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Attribute attribute2 = new DefaultAttribute();
        attribute2.readExternal( in );

        assertEquals( attribute1, attribute2 );
    }


    @Test
    public void testEntryAttributeManyStringValuesSerialization() throws IOException, ClassNotFoundException
    {
        Attribute attribute1 = new DefaultAttribute( "CN", "test1", "test2", "test3" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        attribute1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Attribute attribute2 = new DefaultAttribute();
        attribute2.readExternal( in );

        assertEquals( attribute1, attribute2 );
    }


    @Test
    public void testEntryAttributeNoBinaryValueSerialization() throws IOException, ClassNotFoundException
    {
        Attribute attribute1 = new DefaultAttribute( "UserCertificate" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        attribute1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Attribute attribute2 = new DefaultAttribute();
        attribute2.readExternal( in );

        assertEquals( attribute1, attribute2 );
    }


    @Test
    public void testEntryAttributeOneBinaryValueSerialization() throws IOException, ClassNotFoundException
    {
        Attribute attribute1 = new DefaultAttribute( "UserCertificate", data1 );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        attribute1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Attribute attribute2 = new DefaultAttribute();
        attribute2.readExternal( in );

        assertEquals( attribute1, attribute2 );
    }


    @Test
    public void testEntryAttributeManyBinaryValuesSerialization() throws IOException, ClassNotFoundException
    {
        Attribute attribute1 = new DefaultAttribute( "UserCertificate", data1, data2, data3 );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        attribute1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Attribute attribute2 = new DefaultAttribute();
        attribute2.readExternal( in );

        assertEquals( attribute1, attribute2 );
    }
}
