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
import org.apache.directory.api.ldap.codec.api.MessageDecorator;
import org.apache.directory.api.ldap.model.message.IntermediateResponse;
import org.apache.directory.api.util.Strings;


/**
 * A decorator for the IntermediateResponse message
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class IntermediateResponseDecorator extends MessageDecorator<IntermediateResponse>
    implements IntermediateResponse
{
    /** The response name as a byte[] */
    private byte[] responseNameBytes;

    /** The encoded intermediateResponse length */
    private int intermediateResponseLength;
    
    /** The encoded value as a byte[] */
    private byte[] encodedValueBytes;


    /**
     * Makes a IntermediateResponse encodable.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage the decorated IntermediateResponse
     */
    public IntermediateResponseDecorator( LdapApiService codec, IntermediateResponse decoratedMessage )
    {
        super( codec, decoratedMessage );
    }


    //-------------------------------------------------------------------------
    // The IntermediateResponse methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public String getResponseName()
    {
        return getDecorated().getResponseName();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setResponseName( String oid )
    {
        getDecorated().setResponseName( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getResponseValue()
    {
        return getDecorated().getResponseValue();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setResponseValue( byte[] value )
    {
        getDecorated().setResponseValue( value );
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------
    /**
     * Compute the intermediateResponse length
     * <br>
     * intermediateResponse :
     * <pre>
     * 0x79 L1
     *  |
     * [+--&gt; 0x80 L2 name
     * [+--&gt; 0x81 L3 response]]
     * 
     * L1 = [ + Length(0x80) + Length(L2) + L2
     *      [ + Length(0x81) + Length(L3) + L3]]
     * 
     * Length(IntermediateResponse) = Length(0x79) + Length(L1) + L1
     * </pre>
     * 
     * @return The IntermediateResponse length
     */
    @Override
    public int computeLength()
    {
        intermediateResponseLength = 0;

        if ( !Strings.isEmpty( getResponseName() ) )
        {
            responseNameBytes = Strings.getBytesUtf8( getResponseName() );

            int responseNameLength = responseNameBytes.length;
            intermediateResponseLength += 1 + TLV.getNbBytes( responseNameLength ) + responseNameLength;
        }

        encodedValueBytes = getResponseValue();

        if ( encodedValueBytes != null )
        {
            intermediateResponseLength += 1 + TLV.getNbBytes( encodedValueBytes.length ) + encodedValueBytes.length;
        }

        return 1 + TLV.getNbBytes( intermediateResponseLength ) + intermediateResponseLength;
    }


    /**
     * Encode the IntermediateResponse message to a PDU. 
     * <br>
     * IntermediateResponse :
     * <pre>
     *   0x79 LL
     *     [0x80 LL response name]
     *     [0x81 LL responseValue]
     * </pre>
     * 
     * @param buffer The buffer where to put the PDU
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        try
        {
            // The ExtendedResponse Tag
            buffer.put( LdapCodecConstants.INTERMEDIATE_RESPONSE_TAG );
            buffer.put( TLV.getBytes( intermediateResponseLength ) );

            // The responseName, if any
            if ( ( responseNameBytes != null ) && ( responseNameBytes.length != 0 ) )
            {
                buffer.put( ( byte ) LdapCodecConstants.INTERMEDIATE_RESPONSE_NAME_TAG );
                buffer.put( TLV.getBytes( responseNameBytes.length ) );
                buffer.put( responseNameBytes );
            }

            // The encodedValue, if any
            if ( encodedValueBytes != null )
            {
                buffer.put( ( byte ) LdapCodecConstants.INTERMEDIATE_RESPONSE_VALUE_TAG );

                buffer.put( TLV.getBytes( encodedValueBytes.length ) );

                if ( encodedValueBytes.length != 0 )
                {
                    buffer.put( encodedValueBytes );
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
