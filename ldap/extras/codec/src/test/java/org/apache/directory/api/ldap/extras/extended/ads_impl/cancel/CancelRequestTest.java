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

package org.apache.directory.api.ldap.extras.extended.ads_impl.cancel;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Container;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.extended.ads_impl.cancel.CancelContainer;
import org.apache.directory.api.ldap.extras.extended.ads_impl.cancel.CancelDecoder;
import org.apache.directory.api.ldap.extras.extended.ads_impl.cancel.CancelRequestDecorator;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * TestCase for a Cancel Extended Operation request
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class CancelRequestTest extends AbstractCodecServiceTest
{
    /**
     * Test the normal Cancel message
     */
    @Test
    public void testDecodeCancel() throws DecoderException, EncoderException
    {
        Asn1Decoder cancelDecoder = new CancelDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x05 );

        stream.put( new byte[]
            {
                0x30, 0x03,
                  0x02, 0x01, 0x01
            } ).flip();

        // Allocate a Cancel Container
        Asn1Container cancelContainer = new CancelContainer();

        // Decode a Cancel message
        cancelDecoder.decode( stream, cancelContainer );

        CancelRequestDecorator cancel = ( ( CancelContainer ) cancelContainer ).getCancel();

        assertEquals( 1, cancel.getCancelId() );

        // Check the encoding
        ByteBuffer bb = cancel.encodeInternal();

        assertArrayEquals( stream.array(), bb.array() );
        
        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        CancelFactory factory = new CancelFactory( codec );
        factory.encodeValue( asn1Buffer, cancel );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test a Cancel message with no cancelId
     */
    @Test( expected=DecoderException.class )
    public void testDecodeCancelNoCancelId() throws DecoderException
    {
        Asn1Decoder cancelDecoder = new CancelDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x02 );

        stream.put( new byte[]
            {
                0x30, 0x00
            } ).flip();

        // Allocate a Cancel Container
        Asn1Container cancelContainer = new CancelContainer();

        // Decode a Cancel message
        cancelDecoder.decode( stream, cancelContainer );
    }


    /**
     * Test a Cancel message with an empty cancelId
     */
    @Test( expected=DecoderException.class )
    public void testDecodeCancelEmptyCancelId() throws DecoderException
    {
        Asn1Decoder cancelDecoder = new CancelDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x04 );

        stream.put( new byte[]
            {
                0x30, 0x02,
                  0x02, 0x00
            } ).flip();

        // Allocate a Cancel Container
        Asn1Container cancelContainer = new CancelContainer();

        // Decode a Cancel message
        cancelDecoder.decode( stream, cancelContainer );
    }


    /**
     * Test a Cancel message with a bad cancelId
     */
    @Test( expected=DecoderException.class )
    public void testDecodeCancelBadCancelId() throws DecoderException
    {
        Asn1Decoder cancelDecoder = new CancelDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x08 );

        stream.put( new byte[]
            {
                0x30, 0x06,
                  0x02, 0x04, 
                    ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF
            } ).flip();

        // Allocate a Cancel Container
        Asn1Container cancelContainer = new CancelContainer();

        // Decode a Cancel message

        cancelDecoder.decode( stream, cancelContainer );
    }


    /**
     * Test a Cancel message with more than one cancelId
     */
    @Test( expected=DecoderException.class )
    public void testDecodeCancelMoreThanOneCancelId() throws DecoderException
    {
        Asn1Decoder cancelDecoder = new CancelDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x08 );

        stream.put( new byte[]
            {
                0x30, 0x06,
                  0x02, 0x01, 0x01,
                  0x02, 0x01, 0x02
            } ).flip();

        // Allocate a Cancel Container
        Asn1Container cancelContainer = new CancelContainer();

        // Decode a Cancel message
        cancelDecoder.decode( stream, cancelContainer );
    }
}
