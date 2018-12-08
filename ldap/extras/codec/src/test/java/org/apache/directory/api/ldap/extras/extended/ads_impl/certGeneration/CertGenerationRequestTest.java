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
package org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration.CertGenerationContainer;
import org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration.CertGenerationRequestDecorator;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * 
 * Test case for CertGenerate extended operation request.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class CertGenerationRequestTest extends AbstractCodecServiceTest
{

    /**
     * test the decode operation
     */
    @Test
    public void testCertGenrationDecode() throws DecoderException, EncoderException
    {
        String dn = "uid=admin,ou=system";
        String keyAlgo = "RSA";

        Asn1Decoder decoder = new Asn1Decoder();

        ByteBuffer bb = ByteBuffer.allocate( 0x46 );

        bb.put( new byte[]
            { 
                0x30, 0x44,             // CertGenerateObject ::= SEQUENCE {
                  0x04, 0x13,           //      target OCTET STRING,
                    'u', 'i', 'd', '=', 'a', 'd', 'm', 'i', 'n', ',', 
                    'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                  0x04, 0x13,           //      issuer OCTET STRING,
                    'u', 'i', 'd', '=', 'a', 'd', 'm', 'i', 'n', ',', 
                    'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                  0x04, 0x13,           //      subject OCTET STRING,
                    'u', 'i', 'd', '=', 'a', 'd', 'm', 'i', 'n', ',', 
                    'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                  0x04, 0x03,           //      keyAlgorithm OCTET STRING
                    'R', 'S', 'A'
            } );

        bb.flip();

        CertGenerationContainer container = new CertGenerationContainer();

        decoder.decode( bb, container );

        CertGenerationRequestDecorator req = container.getCertGenerationRequest();
        assertEquals( dn, req.getTargetDN() );
        assertEquals( dn, req.getIssuerDN() );
        assertEquals( dn, req.getSubjectDN() );
        assertEquals( keyAlgo, req.getKeyAlgorithm() );

        assertEquals( 0x46, req.computeLengthInternal() );

        // Check the encoding
        ByteBuffer encodedBuf = req.encodeInternal();

        assertArrayEquals( bb.array(), encodedBuf.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        CertGenerationFactory factory = new CertGenerationFactory( codec );
        factory.encodeValue( asn1Buffer, req );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test( expected=DecoderException.class )
    public void testCertGenerationDecodeEmptyTargetDN() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();

        ByteBuffer bb = ByteBuffer.allocate( 5 );

        bb.put( new byte[]
            { 
                0x30, 0x03, // CertGenerateObject ::= SEQUENCE {
                0x04, 0x01,
                  ' ' 
            } ); // empty targetDN value

        bb.flip();

        CertGenerationContainer container = new CertGenerationContainer();

        decoder.decode( bb, container );
    }


    @Test( expected=DecoderException.class )
    public void testCertGenerationDecodeInvalidTargetDN() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();

        ByteBuffer bb = ByteBuffer.allocate( 0x08 );

        bb.put( new byte[]
            { 
                0x30, 0x06,                 // CertGenerateObject ::= SEQUENCE {
                  0x04, 0x04,
                  '=', 's', 'y', 's' } );   // invalidtargetDN value

        bb.flip();

        CertGenerationContainer container = new CertGenerationContainer();

        decoder.decode( bb, container );
    }


    @Test( expected=DecoderException.class )
    public void testCertGenerationDecodeEmptyIssuerDN() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();

        ByteBuffer bb = ByteBuffer.allocate( 11 );

        bb.put( new byte[]
            { 
                0x30, 0x09,             // CertGenerateObject ::= SEQUENCE {
                  0x04, 0x04,           // target Dn string
                    'c', 'n', '=', 'x', 
                  0x04, 0x01,           // empty issuer Dn
                    ' ' 
            } ); 

        CertGenerationContainer container = new CertGenerationContainer();
        bb.flip();

        decoder.decode( bb, container );
    }


    @Test( expected=DecoderException.class )
    public void testCertGenerationDecodeInvalidIssuerDN() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();

        ByteBuffer bb = ByteBuffer.allocate( 11 );

        bb = ByteBuffer.allocate( 12 );

        bb.put( new byte[]
            { 
                0x30, 0x10,             // CertGenerateObject ::= SEQUENCE {
                  0x04, 0x04,           // target Dn string
                    'c', 'n', '=', 'x', 
                  0x04, 0x02,           // empty issuer Dn
                    '=', 'x' 
            } ); 

        bb.flip();

        CertGenerationContainer container = new CertGenerationContainer();

        decoder.decode( bb, container );
    }


    @Test( expected=DecoderException.class )
    public void testCertGenerationDecodeEmptySubjectDN() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();

        ByteBuffer bb = ByteBuffer.allocate( 17 );

        bb.put( new byte[]
            { 
                0x30, 0x15,                 // CertGenerateObject ::= SEQUENCE {
                  0x04, 0x04,               // target Dn string
                    'c', 'n', '=', 'x', 
                  0x04, 0x04,               // issuer Dn
                    'c', 'n', '=', 'x', 
                  0x04, 0x01,               // empty subject Dn
                    ' ' 
            } ); 

        CertGenerationContainer container = new CertGenerationContainer();
        bb.flip();

        decoder.decode( bb, container );
    }


    @Test( expected=DecoderException.class )
    public void testCertGenerationDecodeInvalidSubjectDN() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();

        ByteBuffer bb = ByteBuffer.allocate( 18 );

        bb.put( new byte[]
            { 
                0x30, 0x16,                 // CertGenerateObject ::= SEQUENCE {
                  0x04, 0x04,               // target Dn string
                    'c', 'n', '=', 'x', 
                  0x04, 0x04,               // issuer Dn
                    'c', 'n', '=', 'x', 
                  0x04, 0x02,               // invalid subject Dn
                    '=', 'x' 
            } );

        bb.flip();

        CertGenerationContainer container = new CertGenerationContainer();
        decoder.decode( bb, container );
    }


    @Test( expected=DecoderException.class )
    public void testDecodeEmptySequence() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();

        ByteBuffer bb = ByteBuffer.allocate( 2 );

        bb.put( new byte[]
            { 
                0x30, 0x00       // CertGenerateObject ::= SEQUENCE { 
            } );

        CertGenerationContainer container = new CertGenerationContainer();
        bb.flip();

        decoder.decode( bb, container );
        // The PDU with an empty sequence is not allowed
    }
}
