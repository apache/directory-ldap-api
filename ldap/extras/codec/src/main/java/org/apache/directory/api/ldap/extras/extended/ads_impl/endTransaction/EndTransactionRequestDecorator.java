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
package org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.decorators.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionRequest;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for EndTransaction request.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EndTransactionRequestDecorator extends ExtendedRequestDecorator<EndTransactionRequest> implements
    EndTransactionRequest
{
    private static final Logger LOG = LoggerFactory.getLogger( EndTransactionRequestDecorator.class );

    /** The internal EndTransaction request */
    private EndTransactionRequest endTransactionRequest;

    /** stores the length of the request*/
    private int requestLength = 0;


    /**
     * Creates a new instance of EndTransactionRequestDecorator.
     * 
     * @param codec The LDAP Service to use
     * @param decoratedMessage The canceled request
     */
    public EndTransactionRequestDecorator( LdapApiService codec, EndTransactionRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
        endTransactionRequest = decoratedMessage;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EndTransactionResponse getResultResponse()
    {
        return ( EndTransactionResponse ) endTransactionRequest.getResultResponse();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getCommit()
    {
        return endTransactionRequest.getCommit();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setCommit( boolean commit )
    {
        endTransactionRequest.setCommit( commit );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getTransactionId()
    {
        return endTransactionRequest.getTransactionId();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTransactionId( byte[] transactionId )
    {
        endTransactionRequest.setTransactionId( transactionId );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setRequestValue( byte[] requestValue )
    {
        EndTransactionRequestDecoder decoder = new EndTransactionRequestDecoder();

        try
        {
            if ( requestValue != null )
            {
                endTransactionRequest = decoder.decode( requestValue );

                this.requestValue = new byte[requestValue.length];
                System.arraycopy( requestValue, 0, this.requestValue, 0, requestValue.length );
            }
            else
            {
                this.requestValue = null;
            }
        }
        catch ( DecoderException e )
        {
            LOG.error( I18n.err( I18n.ERR_04165_PAYLOAD_DECODING_ERROR ), e );
            throw new RuntimeException( e );
        }
    }


    /**
     * Compute the EndTransactionRequest extended operation length
     * <pre>
     * 0x30 L1 
     *   | 
     *   +-- 0x01 0x01 commit 
     *   +-- 0x04 L2 identifier] 
     * </pre>
     */
    /* No qualifier */int computeLengthInternal()
    {
        requestLength = 0;
        
        if ( !endTransactionRequest.getCommit() )
        {
            requestLength = 1 + 1 + 1; // Commit
        }

        if ( endTransactionRequest.getTransactionId() != null )
        {
            int len = endTransactionRequest.getTransactionId().length;
            requestLength += 1 + TLV.getNbBytes( len ) + len;
        }

        return 1 + TLV.getNbBytes( requestLength ) + requestLength;
    }


    /**
     * Encodes the EndTransactionRequest extended operation.
     * 
     * @return A ByteBuffer that contains the encoded PDU
     * @throws org.apache.directory.api.asn1.EncoderException If anything goes wrong.
     */
    /* No qualifier */ByteBuffer encodeInternal() throws EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( computeLengthInternal() );

        bb.put( UniversalTag.SEQUENCE.getValue() );
        bb.put( TLV.getBytes( requestLength ) );
        
        // The commit flag, if it's not true
        if ( !getCommit() )
        {
            BerValue.encode( bb, false );
        }

        // The identifier
        byte[] identifier = endTransactionRequest.getTransactionId();

        if ( identifier != null )
        {
            BerValue.encode( bb, identifier  );
        }

        return bb;
    }
}
