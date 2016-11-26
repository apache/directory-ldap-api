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
package org.apache.directory.api.ldap.codec.decorators;


import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.message.BindResponse;


/**
 * A decorator for the BindResponse message
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class BindResponseDecorator extends ResponseDecorator<BindResponse> implements BindResponse
{
    /** The encoded bindResponse length */
    private int bindResponseLength;


    /**
     * Makes a BindResponse a MessageDecorator.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage the decorated BindResponse
     */
    public BindResponseDecorator( LdapApiService codec, BindResponse decoratedMessage )
    {
        super( codec, decoratedMessage );
    }


    //-------------------------------------------------------------------------
    // The BindResponse methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getServerSaslCreds()
    {
        return getDecorated().getServerSaslCreds();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setServerSaslCreds( byte[] serverSaslCreds )
    {
        getDecorated().setServerSaslCreds( serverSaslCreds );
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------
    /**
     * Compute the BindResponse length 
     * <br>
     * BindResponse : 
     * <pre>
     * 0x61 L1 
     *   | 
     *   +--&gt; LdapResult
     *   +--&gt; [serverSaslCreds] 
     *   
     * L1 = Length(LdapResult) [ + Length(serverSaslCreds) ] 
     * Length(BindResponse) = Length(0x61) + Length(L1) + L1
     * </pre>
     */
    @Override
    public int computeLength()
    {
        BindResponse bindResponse = getDecorated();
        int ldapResultLength = ( ( LdapResultDecorator ) getLdapResult() ).computeLength();

        bindResponseLength = ldapResultLength;

        byte[] serverSaslCreds = bindResponse.getServerSaslCreds();

        if ( serverSaslCreds != null )
        {
            bindResponseLength += 1 + TLV.getNbBytes( serverSaslCreds.length ) + serverSaslCreds.length;
        }

        return 1 + TLV.getNbBytes( bindResponseLength ) + bindResponseLength;
    }


    /**
     * Encode the BindResponse message to a PDU.
     * <br>
     * BindResponse :
     * <pre>
     * LdapResult.encode 
     * [0x87 LL serverSaslCreds]
     * </pre>
     * 
     * @param buffer The buffer where to put the PDU
     * @return The encoded response
     * @throws EncoderException when encoding operations fail
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        BindResponse bindResponse = getDecorated();

        try
        {
            // The BindResponse Tag
            buffer.put( LdapCodecConstants.BIND_RESPONSE_TAG );
            buffer.put( TLV.getBytes( bindResponseLength ) );

            // The LdapResult
            ( ( LdapResultDecorator ) getLdapResult() ).encode( buffer );

            // The serverSaslCredential, if any
            byte[] serverSaslCreds = bindResponse.getServerSaslCreds();

            if ( serverSaslCreds != null )
            {
                buffer.put( ( byte ) LdapCodecConstants.SERVER_SASL_CREDENTIAL_TAG );

                buffer.put( TLV.getBytes( serverSaslCreds.length ) );

                if ( serverSaslCreds.length != 0 )
                {
                    buffer.put( serverSaslCreds );
                }
            }
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04005 ), boe );
        }

        return buffer;
    }
}
