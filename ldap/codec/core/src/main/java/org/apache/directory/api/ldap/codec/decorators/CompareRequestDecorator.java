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
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.entry.BinaryValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.message.CompareRequest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;


/**
 * A decorator for the CompareRequest message
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CompareRequestDecorator extends SingleReplyRequestDecorator<CompareRequest>
    implements CompareRequest
{
    /** The bytes of the attribute id used in the comparison */
    private byte[] attrIdBytes;

    /** The bytes of the attribute value used in the comparison */
    private byte[] attrValBytes;

    /** The compare request length */
    private int compareRequestLength;

    /** The attribute value assertion length */
    private int avaLength;


    /**
     * Makes a CompareRequest a MessageDecorator.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage the decorated CompareRequest
     */
    public CompareRequestDecorator( LdapApiService codec, CompareRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
    }


    //-------------------------------------------------------------------------
    // The CompareRequest methods
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
    public CompareRequest setName( Dn name )
    {
        getDecorated().setName( name );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Value<?> getAssertionValue()
    {
        return getDecorated().getAssertionValue();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest setAssertionValue( String value )
    {
        getDecorated().setAssertionValue( value );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest setAssertionValue( byte[] value )
    {
        getDecorated().setAssertionValue( value );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getAttributeId()
    {
        return getDecorated().getAttributeId();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest setAttributeId( String attrId )
    {
        getDecorated().setAttributeId( attrId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest addControl( Control control )
    {
        return ( CompareRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest addAllControls( Control[] controls )
    {
        return ( CompareRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest removeControl( Control control )
    {
        return ( CompareRequest ) super.removeControl( control );
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------
    /**
     * Compute the CompareRequest length
     * <br>
     * CompareRequest :
     * <pre>
     * 0x6E L1
     *   |
     *   +--&gt; 0x04 L2 entry
     *   +--&gt; 0x30 L3 (ava)
     *         |
     *         +--&gt; 0x04 L4 attributeDesc
     *         +--&gt; 0x04 L5 assertionValue
     * 
     * L3 = Length(0x04) + Length(L4) + L4 + Length(0x04) +
     *      Length(L5) + L5
     * Length(CompareRequest) = Length(0x6E) + Length(L1) + L1 +
     *      Length(0x04) + Length(L2) + L2 + Length(0x30) + Length(L3) + L3
     * </pre>
     * 
     * @return The CompareRequest PDU's length
     */
    @Override
    public int computeLength()
    {
        // The entry Dn
        Dn entry = getName();
        compareRequestLength = 1 + TLV.getNbBytes( Dn.getNbBytes( entry ) ) + Dn.getNbBytes( entry );

        // The attribute value assertion
        attrIdBytes = Strings.getBytesUtf8( getAttributeId() );
        avaLength = 1 + TLV.getNbBytes( attrIdBytes.length ) + attrIdBytes.length;

        org.apache.directory.api.ldap.model.entry.Value<?> assertionValue = getAssertionValue();

        if ( assertionValue instanceof BinaryValue )
        {
            attrValBytes = getAssertionValue().getBytes();
            avaLength += 1 + TLV.getNbBytes( attrValBytes.length ) + attrValBytes.length;
        }
        else
        {
            attrValBytes = Strings.getBytesUtf8( getAssertionValue().getString() );
            avaLength += 1 + TLV.getNbBytes( attrValBytes.length ) + attrValBytes.length;
        }

        compareRequestLength += 1 + TLV.getNbBytes( avaLength ) + avaLength;

        return 1 + TLV.getNbBytes( compareRequestLength ) + compareRequestLength;
    }


    /**
     * Encode the CompareRequest message to a PDU.
     * <pre>
     * CompareRequest :
     *   0x6E LL
     *     0x04 LL entry
     *     0x30 LL attributeValueAssertion
     *       0x04 LL attributeDesc
     *       0x04 LL assertionValue
     * </pre>
     * 
     * @param buffer The buffer where to put the PDU
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        try
        {
            // The CompareRequest Tag
            buffer.put( LdapCodecConstants.COMPARE_REQUEST_TAG );
            buffer.put( TLV.getBytes( compareRequestLength ) );

            // The entry
            BerValue.encode( buffer, Dn.getBytes( getName() ) );

            // The attributeValueAssertion sequence Tag
            buffer.put( UniversalTag.SEQUENCE.getValue() );
            buffer.put( TLV.getBytes( avaLength ) );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04005 ), boe );
        }

        // The attributeDesc
        BerValue.encode( buffer, attrIdBytes );

        // The assertionValue
        BerValue.encode( buffer, attrValBytes );

        return buffer;
    }
}
