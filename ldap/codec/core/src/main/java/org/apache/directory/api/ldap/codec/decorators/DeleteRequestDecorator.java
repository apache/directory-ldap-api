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
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;


/**
 * A decorator for the DeleteRequest message
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DeleteRequestDecorator extends SingleReplyRequestDecorator<DeleteRequest>
    implements DeleteRequest
{
    /** The bytes containing the Dn */
    private byte[] dnBytes;


    /**
     * Makes a DeleteRequest a MessageDecorator.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage the decorated DeleteRequest
     */
    public DeleteRequestDecorator( LdapApiService codec, DeleteRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
    }


    //-------------------------------------------------------------------------
    // The DeleteRequest methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getName()
    {
        return getDecorated().getName();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DeleteRequest setName( Dn name )
    {
        getDecorated().setName( name );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DeleteRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DeleteRequest addControl( Control control )
    {
        return ( DeleteRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DeleteRequest addAllControls( Control[] controls )
    {
        return ( DeleteRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DeleteRequest removeControl( Control control )
    {
        return ( DeleteRequest ) super.removeControl( control );
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------
    /**
     * Compute the DelRequest length
     * <br>
     * DelRequest :
     * <pre>
     * 0x4A L1 entry
     * 
     * L1 = Length(entry)
     * Length(DelRequest) = Length(0x4A) + Length(L1) + L1
     * </pre>
     */
    @Override
    public int computeLength()
    {
        dnBytes = Strings.getBytesUtf8( getName().getName() );
        int dnLength = dnBytes.length;

        // The entry
        return 1 + TLV.getNbBytes( dnLength ) + dnLength;
    }


    /**
     * Encode the DelRequest message to a PDU.
     * <br>
     * DelRequest :
     * <pre>
     * 0x4A LL entry
     * </pre>
     * 
     * @param buffer The buffer where to put the PDU
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        try
        {
            // The DelRequest Tag
            buffer.put( LdapCodecConstants.DEL_REQUEST_TAG );

            // The entry
            buffer.put( TLV.getBytes( dnBytes.length ) );
            buffer.put( dnBytes );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04005 ), boe );
        }

        return buffer;
    }
}
