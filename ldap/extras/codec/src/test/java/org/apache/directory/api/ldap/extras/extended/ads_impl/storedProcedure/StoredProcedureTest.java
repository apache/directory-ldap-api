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

package org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoder;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure.StoredProcedureContainer;
import org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure.StoredProcedureDecoder;
import org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure.StoredProcedureRequestDecorator;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/*
 * TestCase for a Stored Procedure Extended Operation ASN.1 codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class StoredProcedureTest extends AbstractCodecServiceTest
{
    @Test
    public void testDecodeStoredProcedureNParams() throws DecoderException, EncoderException, IntegerDecoderException
    {
        Asn1Decoder storedProcedureDecoder = new StoredProcedureDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x44 );

        stream.put( new byte[]
            {
                0x30, 0x42,             // StoredProcedure ::= SEQUENCE {
                  0x04, 0x04,           //     language OCTET STRING,
                    'J', 'a', 'v', 'a',
                  0x04, 0x07,           //     procedure   OCET STRING,
                    'e', 'x', 'e', 'c', 'u', 't', 'e',
                  0x30, 0x31,           //     parameters SEQUENCE OF {
                    0x30, 0x08,         //         parameter SEQUENCE {
                      0x04, 0x03,       //             type OCTET STRING,
                        'i', 'n', 't',
                      0x04, 0x01, 0x01, //             value    OCTET STRING
                    0x30, 0x0F,         //         parameter SEQUENCE {
                      0x04, 0x07,       //             type OCTET STRING, 
                        'b', 'o', 'o', 'l', 'e', 'a', 'n',
                      0x04, 0x04,       //             value    OCTET STRING
                        't', 'r', 'u', 'e',
                    0x30, 0x14,         //         parameter SEQUENCE {
                      0x04, 0x06,       //             type OCTET STRING, 
                        'S', 't', 'r', 'i', 'n', 'g',
                      0x04, 0x0A,       //             value    OCTET STRING
                        'p', 'a', 'r', 'a', 'm', 'e', 't', 'e', 'r', '3'
        } );

        stream.flip();

        // Allocate a StoredProcedure Container
        StoredProcedureContainer storedProcedureContainer = new StoredProcedureContainer();

        // Decode a StoredProcedure message
        storedProcedureDecoder.decode( stream, storedProcedureContainer );

        StoredProcedureRequestDecorator storedProcedure = storedProcedureContainer.getStoredProcedure();

        assertEquals( "Java", storedProcedure.getLanguage() );

        assertEquals( "execute", storedProcedure.getProcedureSpecification() );

        assertEquals( 3, storedProcedure.size() );

        assertEquals( "int", Strings.utf8ToString( ( byte[] ) storedProcedure.getParameterType( 0 ) ) );
        assertEquals( 1, IntegerDecoder.parse( new BerValue( ( byte[] ) storedProcedure.getParameterValue( 0 ) ) ) );

        assertEquals( "boolean", Strings.utf8ToString( ( byte[] ) storedProcedure.getParameterType( 1 ) ) );
        assertEquals( "true", Strings.utf8ToString( ( byte[] ) storedProcedure.getParameterValue( 1 ) ) );

        assertEquals( "String", Strings.utf8ToString( ( byte[] ) storedProcedure.getParameterType( 2 ) ) );
        assertEquals( "parameter3", Strings.utf8ToString( ( byte[] ) storedProcedure.getParameterValue( 2 ) ) );

        // Check the encoding
        ByteBuffer bb = storedProcedure.encodeInternal();
        assertArrayEquals( stream.array(),  bb.array() );
        
        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        StoredProcedureFactory factory = new StoredProcedureFactory( codec );
        factory.encodeValue( asn1Buffer, storedProcedure );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeStoredProcedureNoParam() throws DecoderException, EncoderException
    {
        Asn1Decoder storedProcedureDecoder = new StoredProcedureDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x13 );

        stream.put( new byte[]
            {
                0x30, 0x11,             // StoredProcedure ::= SEQUENCE {
                  0x04, 0x04,           //     language OCTET STRING,
                    'J', 'a', 'v', 'a',
                  0x04, 0x07,           //     procedure   OCET STRING,
                    'e', 'x', 'e', 'c', 'u', 't', 'e',
                  0x30, 0x00            //     parameters SEQUENCE OF {
        } );

        stream.flip();

        // Allocate a StoredProcedure Container
        StoredProcedureContainer storedProcedureContainer = new StoredProcedureContainer();

        // Decode a StoredProcedure message
        storedProcedureDecoder.decode( stream, storedProcedureContainer );

        StoredProcedureRequestDecorator storedProcedure = storedProcedureContainer.getStoredProcedure();

        assertEquals( "Java", storedProcedure.getLanguage() );

        assertEquals( "execute", storedProcedure.getProcedureSpecification() );

        assertEquals( 0, storedProcedure.size() );

        // Check the encoding
        ByteBuffer bb = storedProcedure.encodeInternal();

        assertArrayEquals( stream.array(),  bb.array() );
        
        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        StoredProcedureFactory factory = new StoredProcedureFactory( codec );
        factory.encodeValue( asn1Buffer, storedProcedure );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeStoredProcedureOneParam() throws IntegerDecoderException, DecoderException, EncoderException
    {
        Asn1Decoder storedProcedureDecoder = new StoredProcedureDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x1D );

        stream.put( new byte[]
            {
                0x30, 0x1B,                 // StoredProcedure ::= SEQUENCE {
                  0x04, 0x04,               //     language OCTET STRING,
                    'J', 'a', 'v', 'a',
                  0x04, 0x07,               //     procedure   OCET STRING,
                    'e', 'x', 'e', 'c', 'u', 't', 'e',
                  0x30, 0x0A,               //     parameters SEQUENCE OF {
                    0x30, 0x08,             //         parameter SEQUENCE {
                      0x04, 0x03,           //             type OCTET STRING,
                        'i', 'n', 't',
                      0x04, 0x01, 0x01      //             value    OCTET STRING
        } );

        stream.flip();

        // Allocate a StoredProcedure Container
        StoredProcedureContainer storedProcedureContainer = new StoredProcedureContainer();

        // Decode a StoredProcedure message
        storedProcedureDecoder.decode( stream, storedProcedureContainer );

        StoredProcedureRequestDecorator storedProcedure = storedProcedureContainer.getStoredProcedure();

        assertEquals( "Java", storedProcedure.getLanguage() );

        assertEquals( "execute", storedProcedure.getProcedureSpecification() );

        assertEquals( 1, storedProcedure.size() );

        assertEquals( "int", Strings.utf8ToString( ( byte[] ) storedProcedure.getParameterType( 0 ) ) );
        assertEquals( 1, IntegerDecoder.parse( new BerValue( ( byte[] ) storedProcedure.getParameterValue( 0 ) ) ) );

        // Check the encoding

        ByteBuffer bb = storedProcedure.encodeInternal();

        assertArrayEquals( stream.array(),  bb.array() );
        
        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        StoredProcedureFactory factory = new StoredProcedureFactory( codec );
        factory.encodeValue( asn1Buffer, storedProcedure );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }
}
