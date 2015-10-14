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
package org.apache.directory.api.ldap.codec.controls.proxiedauthz;


import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;

import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.controls.ProxiedAuthz;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the ProxiedAuthzControlTest codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class ProxiedAuthzControlTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a ProxiedAuthzControl with a DN user
     */
    @Test
    public void testDecodeProxiedAuthzControlDnSuccess() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x14 );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= dn:dc=example,dc=com
                'd', 'n', ':', 'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm'
        } );
        bb.flip();

        ProxiedAuthzDecorator decorator = new ProxiedAuthzDecorator( codec );

        ProxiedAuthz proxiedAuthz = ( ProxiedAuthz ) decorator.decode( bb.array() );

        assertEquals( "dn:dc=example,dc=com", proxiedAuthz.getAuthzId() );
    }


    /**
     * Test the decoding of a ProxiedAuthzControl with a normal user
     */
    @Test
    public void testDecodeProxiedAuthzControlUSuccess() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0C );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= u:elecharny
                'u', ':', 'e', 'l', (byte)0xc3, (byte)0xa9, 'c', 'h', 'a', 'r', 'n', 'y'
        } );
        bb.flip();

        ProxiedAuthzDecorator decorator = new ProxiedAuthzDecorator( codec );

        ProxiedAuthz proxiedAuthz = ( ProxiedAuthz ) decorator.decode( bb.array() );

        assertEquals( "u:el\u00e9charny", proxiedAuthz.getAuthzId() );
    }


    /**
     * Test the decoding of a ProxiedAuthzControl with a anonymous user
     */
    @Test
    public void testDecodeProxiedAuthzControlAnonymousSuccess() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x00 );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= anonymous
        } );
        bb.flip();

        ProxiedAuthzDecorator decorator = new ProxiedAuthzDecorator( codec );

        ProxiedAuthz proxiedAuthz = ( ProxiedAuthz ) decorator.decode( bb.array() );

        assertEquals( "", proxiedAuthz.getAuthzId() );
    }
    
    
    /**
     * Test the decoding of a ProxiedAuthzControl with a wrong DN user
     */
    @Test( expected = RuntimeException.class)
    public void testDecodeProxiedAuthzControlWrongDn() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x10 );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= dn:dc=example,dc=com
                'd', 'n', ':', 'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c'
        } );
        bb.flip();

        ProxiedAuthzDecorator decorator = new ProxiedAuthzDecorator( codec );

        decorator.decode( bb.array() );
    }
    
    
    /**
     * Test the decoding of a ProxiedAuthzControl with a wrong user
     */
    @Test( expected = RuntimeException.class)
    public void testDecodeProxiedAuthzControlWrongAuthzId() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= dn:dc=example,dc=com
                'v', 'n', ':', 'w', 'r', 'o', 'n', 'g'
        } );
        bb.flip();

        ProxiedAuthzDecorator decorator = new ProxiedAuthzDecorator( codec );

        decorator.decode( bb.array() );
    }


    /**
     * Test encoding of a ProxiedAuthzControl.
     */
    @Test
    public void testEncodeProxiedDnAuthzControl() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x14 );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= dn:dc=example,dc=com
                  'd', 'n', ':', 'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm'
            } );

        String expected = Strings.dumpBytes( bb.array() );
        bb.flip();

        ProxiedAuthzDecorator decorator = new ProxiedAuthzDecorator( codec );

        ProxiedAuthz proxiedAuthz = ( ProxiedAuthz ) decorator.getDecorated();
        proxiedAuthz.setAuthzId( "dn:dc=example,dc=com" );
        bb = decorator.encode( ByteBuffer.allocate( decorator.computeLength() ) );
        String decoded = Strings.dumpBytes( bb.array() );
        assertEquals( expected, decoded );
    }


    /**
     * Test encoding of a ProxiedAuthzControl.
     */
    @Test
    public void testEncodeProxiedUserAuthzControl() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0C );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= u:elecharny
                'u', ':', 'e', 'l', (byte)0xc3, (byte)0xa9, 'c', 'h', 'a', 'r', 'n', 'y'
        } );

        String expected = Strings.dumpBytes( bb.array() );
        bb.flip();

        ProxiedAuthzDecorator decorator = new ProxiedAuthzDecorator( codec );

        ProxiedAuthz proxiedAuthz = ( ProxiedAuthz ) decorator.getDecorated();
        proxiedAuthz.setAuthzId( "u:el\u00e9charny" );
        bb = decorator.encode( ByteBuffer.allocate( decorator.computeLength() ) );
        String decoded = Strings.dumpBytes( bb.array() );
        assertEquals( expected, decoded );
    }


    /**
     * Test encoding of a ProxiedAuthzControl.
     */
    @Test
    public void testEncodeProxiedAnonymousAuthzControl() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x00 );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= anonymous
        } );

        String expected = Strings.dumpBytes( bb.array() );
        bb.flip();

        ProxiedAuthzDecorator decorator = new ProxiedAuthzDecorator( codec );

        ProxiedAuthz proxiedAuthz = ( ProxiedAuthz ) decorator.getDecorated();
        proxiedAuthz.setAuthzId( "" );
        bb = decorator.encode( ByteBuffer.allocate( decorator.computeLength() ) );
        String decoded = Strings.dumpBytes( bb.array() );
        assertEquals( expected, decoded );
    }
}
