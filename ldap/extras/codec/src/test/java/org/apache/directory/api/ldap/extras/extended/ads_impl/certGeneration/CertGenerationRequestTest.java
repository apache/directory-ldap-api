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


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.extras.extended.certGeneration.CertGenerationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * 
 * Test case for CertGenerate extended operation request.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class CertGenerationRequestTest
{
    private static LdapApiService codec;

    @BeforeAll
    public static void init()
    {
        codec = new DefaultLdapCodecService();
        codec.registerExtendedRequest( new CertGenerationFactory( codec ) );
    }
    
    
    /**
     * test the decode operation
     */
    @Test
    public void testCertGenrationDecode() throws DecoderException, EncoderException
    {
        String dn = "uid=admin,ou=system";
        String keyAlgo = "RSA";

        byte[] bb = new byte[]
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
            };

        CertGenerationFactory factory = ( CertGenerationFactory ) codec.getExtendedRequestFactories().
            get( CertGenerationRequest.EXTENSION_OID );
        CertGenerationRequest certGenerationRequest = ( CertGenerationRequest ) factory.newRequest( bb );

        assertEquals( dn, certGenerationRequest.getTargetDN() );
        assertEquals( dn, certGenerationRequest.getIssuerDN() );
        assertEquals( dn, certGenerationRequest.getSubjectDN() );
        assertEquals( keyAlgo, certGenerationRequest.getKeyAlgorithm() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, certGenerationRequest );
        
        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testCertGenerationDecodeEmptyTargetDN() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x03,         // CertGenerateObject ::= SEQUENCE {
                  0x04, 0x01,       // empty targetDN value
                    ' ' 
            }; 

        CertGenerationFactory factory = ( CertGenerationFactory ) codec.getExtendedRequestFactories().
            get( CertGenerationRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }


    @Test
    public void testCertGenerationDecodeInvalidTargetDN() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x06,                 // CertGenerateObject ::= SEQUENCE {
                  0x04, 0x04,               // invalidtargetDN value
                    '=', 's', 'y', 's' 
            };   

        CertGenerationFactory factory = ( CertGenerationFactory ) codec.getExtendedRequestFactories().
            get( CertGenerationRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }


    @Test
    public void testCertGenerationDecodeEmptyIssuerDN() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x09,             // CertGenerateObject ::= SEQUENCE {
                  0x04, 0x04,           // target Dn string
                    'c', 'n', '=', 'x', 
                  0x04, 0x01,           // empty issuer Dn
                    ' ' 
            }; 

        CertGenerationFactory factory = ( CertGenerationFactory ) codec.getExtendedRequestFactories().
            get( CertGenerationRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }


    @Test
    public void testCertGenerationDecodeInvalidIssuerDN() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x10,             // CertGenerateObject ::= SEQUENCE {
                  0x04, 0x04,           // target Dn string
                    'c', 'n', '=', 'x', 
                  0x04, 0x02,           // empty issuer Dn
                    '=', 'x' 
            }; 

        CertGenerationFactory factory = ( CertGenerationFactory ) codec.getExtendedRequestFactories().
            get( CertGenerationRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }


    @Test
    public void testCertGenerationDecodeEmptySubjectDN() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x15,                 // CertGenerateObject ::= SEQUENCE {
                  0x04, 0x04,               // target Dn string
                    'c', 'n', '=', 'x', 
                  0x04, 0x04,               // issuer Dn
                    'c', 'n', '=', 'x', 
                  0x04, 0x01,               // empty subject Dn
                    ' ' 
            }; 

        CertGenerationFactory factory = ( CertGenerationFactory ) codec.getExtendedRequestFactories().
            get( CertGenerationRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }


    @Test
    public void testCertGenerationDecodeInvalidSubjectDN() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x16,                 // CertGenerateObject ::= SEQUENCE {
                  0x04, 0x04,               // target Dn string
                    'c', 'n', '=', 'x', 
                  0x04, 0x04,               // issuer Dn
                    'c', 'n', '=', 'x', 
                  0x04, 0x02,               // invalid subject Dn
                    '=', 'x' 
            };

        CertGenerationFactory factory = ( CertGenerationFactory ) codec.getExtendedRequestFactories().
            get( CertGenerationRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }


    @Test
    public void testDecodeEmptySequence() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x00       // CertGenerateObject ::= SEQUENCE { 
            };

        CertGenerationFactory factory = ( CertGenerationFactory ) codec.getExtendedRequestFactories().
            get( CertGenerationRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }
}
