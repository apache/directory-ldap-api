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
import org.apache.directory.api.ldap.model.message.CompareResponse;


/**
 * A decorator for the CompareResponse message
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CompareResponseDecorator extends ResponseDecorator<CompareResponse>
    implements CompareResponse
{
    /** The encoded compareResponse length */
    private int compareResponseLength;


    /**
     * Makes a CompareResponse a MessageDecorator.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage the decorated CompareResponse
     */
    public CompareResponseDecorator( LdapApiService codec, CompareResponse decoratedMessage )
    {
        super( codec, decoratedMessage );
    }


    //-------------------------------------------------------------------------
    // The CompareResponse methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isTrue()
    {
        return getDecorated().isTrue();
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------

    /**
     * Compute the CompareResponse length 
     * <br>
     * CompareResponse :
     * <pre>
     * 0x6F L1
     *  |
     *  +--&gt; LdapResult
     * 
     * L1 = Length(LdapResult)
     * 
     * Length(CompareResponse) = Length(0x6F) + Length(L1) + L1
     * </pre>
     */
    @Override
    public int computeLength()
    {
        compareResponseLength = ( ( LdapResultDecorator ) getLdapResult() ).computeLength();

        return 1 + TLV.getNbBytes( compareResponseLength ) + compareResponseLength;
    }


    /**
     * Encode the CompareResponse message to a PDU.
     * 
     * @param buffer The buffer where to put the PDU
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        try
        {
            // The CompareResponse Tag
            buffer.put( LdapCodecConstants.COMPARE_RESPONSE_TAG );
            buffer.put( TLV.getBytes( compareResponseLength ) );

            // The LdapResult
            ( ( LdapResultDecorator ) getLdapResult() ).encode( buffer );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04005 ), boe );
        }

        return buffer;
    }
}
