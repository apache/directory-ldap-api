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
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Test the Rdn Serialization
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class RdnSerializationTest
{
    @Test
    public void testRdnFullSerialization() throws IOException, LdapException, ClassNotFoundException
    {
        Rdn rdn1 = new Rdn( "gn=john + cn=doe" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn();
        rdn2.readExternal( in );

        assertEquals( rdn1, rdn2 );
    }


    @Test
    public void testRdnEmptySerialization() throws IOException, LdapException, ClassNotFoundException
    {
        Rdn rdn1 = new Rdn();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn();
        rdn2.readExternal( in );

        assertEquals( rdn1, rdn2 );
    }


    @Test
    public void testRdnSimpleSerialization() throws IOException, LdapException, ClassNotFoundException
    {
        Rdn rdn1 = new Rdn( "cn=doe" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn1.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn();
        rdn2.readExternal( in );

        assertEquals( rdn1, rdn2 );
    }


    /**
     * Test serialization of an empty Rdn
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testEmptyRDNStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( "" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn();
        rdn2.readExternal( in );

        assertEquals( rdn, rdn2 );
    }


    @Test
    public void testNullRdnStaticSerialization() throws IOException, ClassNotFoundException, LdapInvalidDnException
    {
        Rdn rdn = new Rdn();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn();
        rdn2.readExternal( in );

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
    public void testSimpleRdnStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( "a=b" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn();
        rdn2.readExternal( in );

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
    public void testSimpleRdn2StaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( " ABC  = DEF " );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn();
        rdn2.readExternal( in );

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
    public void testSimpleRdnNoValueStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( " ABC  =" );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn();
        rdn2.readExternal( in );

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
    public void testSimpleRdnOneValueStaticSerialization() throws LdapException, IOException, ClassNotFoundException
    {
        Rdn rdn = new Rdn( " ABC  = def " );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn();
        rdn2.readExternal( in );

        assertEquals( rdn, rdn2 );
    }


    /**
     * Test serialization of a simple Rdn with three values
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSimpleRdnThreeValuesStaticSerialization() throws LdapException, IOException,
        ClassNotFoundException
    {
        Rdn rdn = new Rdn( " A = a + B = b + C = c " );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn();
        rdn2.readExternal( in );

        assertEquals( rdn, rdn2 );
    }


    /**
     * Test serialization of a simple Rdn with three unordered values
     * 
     * @throws LdapException If the test failed
     * @throws IOException If the test failed
     * @throws ClassNotFoundException If the test failed
     */
    @Test
    public void testSimpleRdnThreeValuesUnorderedStaticSerialization() throws LdapException, IOException,
        ClassNotFoundException
    {
        Rdn rdn = new Rdn( " B = b + A = a + C = c " );

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream( baos );

        rdn.writeExternal( out );

        ObjectInputStream in = null;

        byte[] data = baos.toByteArray();
        in = new ObjectInputStream( new ByteArrayInputStream( data ) );

        Rdn rdn2 = new Rdn();
        rdn2.readExternal( in );

        assertEquals( rdn, rdn2 );
    }
}
