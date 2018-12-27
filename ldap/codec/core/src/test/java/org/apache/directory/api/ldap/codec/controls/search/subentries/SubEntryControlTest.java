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
package org.apache.directory.api.ldap.codec.controls.search.subentries;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.controls.Subentries;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the SubEntryControlTest codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class SubEntryControlTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a SubEntryControl with a true visibility
     */
    @Test
    public void testDecodeSubEntryVisibilityTrue() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x03 );
        bb.put( new byte[]
            {
                0x01, 0x01, ( byte ) 0xFF // Visibility ::= BOOLEAN
            } );
        bb.flip();

        SubentriesFactory factory = ( SubentriesFactory ) codec.getRequestControlFactories().get( Subentries.OID );
        Subentries subentries = factory.newControl();
        factory.decodeValue( subentries, bb.array() );

        // Test reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, subentries );

        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SubEntryControl with a false visibility
     */
    @Test
    public void testDecodeSubEntryVisibilityFalse() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x03 );
        bb.put( new byte[]
            {
                0x01, 0x01, 0x00 // Visibility ::= BOOLEAN
            } );
        bb.flip();

        SubentriesFactory factory = ( SubentriesFactory ) codec.getRequestControlFactories().get( Subentries.OID );
        Subentries subentries = factory.newControl();
        factory.decodeValue( subentries, bb.array() );

        assertFalse( subentries.isVisible() );

        // Test reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, subentries );

        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SubEntryControl with an empty visibility
     */
    @Test( expected = DecoderException.class )
    public void testDecodeSubEntryEmptyVisibility() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );

        bb.put( new byte[]
            {
                0x01, 0x00 // Visibility ::= BOOLEAN
            } );

        bb.flip();

        // Allocate a LdapMessage Container
        SubentriesFactory factory = ( SubentriesFactory ) codec.getRequestControlFactories().get( Subentries.OID );
        Subentries subentries = factory.newControl();
        factory.decodeValue( subentries, bb.array() );
    }


    /**
     * Test the decoding of a bad SubEntryControl
     */
    @Test(expected = DecoderException.class)
    public void testDecodeSubEntryBad() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x03 );

        bb.put( new byte[]
            {
                0x02, 0x01, 0x01 // Visibility ::= BOOLEAN
            } );

        bb.flip();

        // Allocate a LdapMessage Container
        SubentriesFactory factory = ( SubentriesFactory ) codec.getRequestControlFactories().get( Subentries.OID );
        Subentries subentries = factory.newControl();
        factory.decodeValue( subentries, bb.array() );
    }
}
