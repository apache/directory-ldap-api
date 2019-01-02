/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.certGeneration.CertGenerationRequest;
import org.apache.directory.api.ldap.extras.extended.certGeneration.CertGenerationRequestImpl;
import org.apache.directory.api.ldap.extras.extended.certGeneration.CertGenerationResponse;
import org.apache.directory.api.ldap.extras.extended.certGeneration.CertGenerationResponseImpl;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;


/**
 * An {@link ExtendedOperationFactory} for creating certificate generation extended request response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CertGenerationFactory extends AbstractExtendedOperationFactory
{
    /**
     * Creates a new instance of CertGenerationFactory.
     *
     * @param codec The codec for this factory.
     */
    public CertGenerationFactory( LdapApiService codec )
    {
        super( codec, CertGenerationRequest.EXTENSION_OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CertGenerationRequest newRequest()
    {
        CertGenerationRequest certGenerationRequest = new CertGenerationRequestImpl();

        return certGenerationRequest;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CertGenerationRequest newRequest( byte[] encodedValue ) throws DecoderException
    {
        CertGenerationRequest certGenerationRequest = new CertGenerationRequestImpl();
        decodeValue( certGenerationRequest, encodedValue );

        return certGenerationRequest;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CertGenerationResponse newResponse()
    {
        return new CertGenerationResponseImpl();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( ExtendedRequest extendedRequest, byte[] requestValue ) throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.wrap( requestValue );
        CertGenerationRequestContainer container = new CertGenerationRequestContainer();
        container.setCertGenerationRequest( ( CertGenerationRequest ) extendedRequest ); 
        Asn1Decoder.decode( bb, container );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, ExtendedRequest extendedRequest )
    {
        int start  = buffer.getPos();
        CertGenerationRequest certGenerationRequest = ( CertGenerationRequest ) extendedRequest;
        
        // the key algorithm
        BerValue.encodeOctetString( buffer, certGenerationRequest.getKeyAlgorithm() );
        
        // The subject
        BerValue.encodeOctetString( buffer, certGenerationRequest.getSubjectDN() );

        // The issuer
        BerValue.encodeOctetString( buffer, certGenerationRequest.getIssuerDN() );
        
        // The target
        BerValue.encodeOctetString( buffer, certGenerationRequest.getTargetDN() );
        
        // The sequence
        BerValue.encodeSequence( buffer, start );
    }
}
