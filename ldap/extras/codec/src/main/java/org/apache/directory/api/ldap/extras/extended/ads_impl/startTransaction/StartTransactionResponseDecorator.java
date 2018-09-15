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
package org.apache.directory.api.ldap.extras.extended.ads_impl.startTransaction;


import org.apache.directory.api.ldap.codec.decorators.ExtendedResponseDecorator;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.startTransaction.StartTransactionResponse;
import org.apache.directory.api.ldap.extras.extended.startTransaction.StartTransactionResponseImpl;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for EndTransactionResponses.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StartTransactionResponseDecorator extends ExtendedResponseDecorator<StartTransactionResponse> implements StartTransactionResponse
{
    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( StartTransactionResponseDecorator.class );

    /** The startTransaction response */
    private StartTransactionResponse startTransactionResponse;

    /**
     * Creates a new instance of EndTransactionResponseDecorator.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage The decorated message
     */
    public StartTransactionResponseDecorator( LdapApiService codec, StartTransactionResponse decoratedMessage )
    {
        super( codec, decoratedMessage );
        startTransactionResponse = decoratedMessage;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getResponseValue()
    {
        if ( responseValue == null )
        {
            try
            {
                responseValue = encodeInternal().array();
            }
            catch ( EncoderException e )
            {
                LOG.error( I18n.err( I18n.ERR_08231_START_TRANSACTION_PAYLOAD_ENCODING_FAILED ), e );
                throw new RuntimeException( e );
            }
        }

        return responseValue;
    }


    /**
     * Compute the StartTransactionResponse extended operation length
     * <pre>
     * 0x04 L1 transactionId
     * </pre>
     * 
     * @return The extended operation's length
     */
    /* no qualifier */int computeLengthInternal()
    {
        if ( startTransactionResponse.getTransactionId() != null )
        {
            return 1 + TLV.getNbBytes( startTransactionResponse.getTransactionId().length )
                + startTransactionResponse.getTransactionId().length;
        }
        else
        {
            return 1 + 1;
        }
    }


    /**
     * Encodes the StartTransactionResponse extended operation.
     * 
     * @return A ByteBuffer that contains the encoded PDU
     * @throws EncoderException If anything goes wrong.
     */
    /* no qualifier */ByteBuffer encodeInternal() throws EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( computeLengthInternal() );

        BerValue.encode( bb, startTransactionResponse.getTransactionId() );

        return bb;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setResponseValue( byte[] responseValue )
    {
        this.responseValue = Strings.copy( responseValue );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getTransactionId()
    {
        return startTransactionResponse.getTransactionId();
    }
    
    
    /**
     * {@inheritDoc}
     */
    public void setTransactionId( byte[] transactionId )
    {
        ( ( StartTransactionResponseImpl ) getDecorated() ).setTransactionId( transactionId );
    }
}
