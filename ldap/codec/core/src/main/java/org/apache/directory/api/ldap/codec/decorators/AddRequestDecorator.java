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
import java.util.LinkedList;
import java.util.List;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;


/**
 * A decorator for the AddRequest message
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class AddRequestDecorator extends SingleReplyRequestDecorator<AddRequest> implements
    AddRequest
{
    /** The add request length */
    private int addRequestLength;

    /** The Entry length */
    private int entryLength;

    /** The list of all attributes length */
    private List<Integer> attributesLength;

    /** The list of all attributes Id bytes */
    private List<byte[]> attributeIds;

    /** The list of all vals length */
    private List<Integer> valuesLength;

    /** The current attribute being decoded */
    private Attribute currentAttribute;

    /** The bytes containing the Dn */
    private byte[] dnBytes;


    /**
     * Makes a AddRequest a MessageDecorator.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage the decorated AddRequest
     */
    public AddRequestDecorator( LdapApiService codec, AddRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddRequest addControl( Control control )
    {
        return ( AddRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddRequest addAllControls( Control[] controls )
    {
        return ( AddRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddRequest removeControl( Control control )
    {
        return ( AddRequest ) super.removeControl( control );
    }


    //-------------------------------------------------------------------------
    // The AddRequest methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getEntryDn()
    {
        return getDecorated().getEntryDn();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddRequest setEntryDn( Dn entry )
    {
        getDecorated().setEntryDn( entry );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry getEntry()
    {
        return getDecorated().getEntry();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddRequest setEntry( Entry entry )
    {
        getDecorated().setEntry( entry );

        return this;
    }


    /**
     * Create a new attributeValue
     * 
     * @param type The attribute's name (called 'type' in the grammar)
     * @throws LdapException If the value is invalid
     */
    public void addAttributeType( String type ) throws LdapException
    {
        // do not create a new attribute if we have seen this attributeType before
        if ( getDecorated().getEntry().get( type ) != null )
        {
            currentAttribute = getDecorated().getEntry().get( type );
            return;
        }

        // fix this to use AttributeImpl(type.getString().toLowerCase())
        currentAttribute = new DefaultAttribute( type );
        getDecorated().getEntry().put( currentAttribute );
    }


    /**
     * @return Returns the currentAttribute type.
     */
    public String getCurrentAttributeType()
    {
        return currentAttribute.getUpId();
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If the value is invalid
     */
    public void addAttributeValue( String value ) throws LdapException
    {
        currentAttribute.add( value );
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If the value is invalid
     */
    public void addAttributeValue( Value<?> value ) throws LdapException
    {
        currentAttribute.add( value );
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If the value is invalid
     */
    public void addAttributeValue( byte[] value ) throws LdapException
    {
        currentAttribute.add( value );
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------
    /**
     * Compute the AddRequest length
     * <br>
     * AddRequest :
     * <pre>
     * 0x68 L1
     *  |
     *  +--&gt; 0x04 L2 entry
     *  +--&gt; 0x30 L3 (attributes)
     *        |
     *        +--&gt; 0x30 L4-1 (attribute)
     *        |     |
     *        |     +--&gt; 0x04 L5-1 type
     *        |     +--&gt; 0x31 L6-1 (values)
     *        |           |
     *        |           +--&gt; 0x04 L7-1-1 value
     *        |           +--&gt; ...
     *        |           +--&gt; 0x04 L7-1-n value
     *        |
     *        +--&gt; 0x30 L4-2 (attribute)
     *        |     |
     *        |     +--&gt; 0x04 L5-2 type
     *        |     +--&gt; 0x31 L6-2 (values)
     *        |           |
     *        |           +--&gt; 0x04 L7-2-1 value
     *        |           +--&gt; ...
     *        |           +--&gt; 0x04 L7-2-n value
     *        |
     *        +--&gt; ...
     *        |
     *        +--&gt; 0x30 L4-m (attribute)
     *              |
     *              +--&gt; 0x04 L5-m type
     *              +--&gt; 0x31 L6-m (values)
     *                    |
     *                    +--&gt; 0x04 L7-m-1 value
     *                    +--&gt; ...
     *                    +--&gt; 0x04 L7-m-n value
     * </pre>
     */
    @Override
    public int computeLength()
    {
        AddRequest addRequest = getDecorated();
        Entry entry = addRequest.getEntry();

        if ( entry == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04481_ENTRY_NULL_VALUE ) );
        }

        dnBytes = Strings.getBytesUtf8( entry.getDn().getName() );
        int dnLen = dnBytes.length;

        // The entry Dn
        addRequestLength = 1 + TLV.getNbBytes( dnLen ) + dnLen;

        // The attributes sequence
        entryLength = 0;

        if ( entry.size() != 0 )
        {
            attributesLength = new LinkedList<>();
            attributeIds = new LinkedList<>();
            valuesLength = new LinkedList<>();

            // Compute the attributes length
            for ( Attribute attribute : entry )
            {
                int localAttributeLength;
                int localValuesLength;

                // Get the type length
                byte[] attributeIdBytes = Strings.getBytesUtf8( attribute.getUpId() );
                attributeIds.add( attributeIdBytes );

                int idLength = attributeIdBytes.length;
                localAttributeLength = 1 + TLV.getNbBytes( idLength ) + idLength;

                // The values
                if ( attribute.size() != 0 )
                {
                    localValuesLength = 0;

                    for ( Value<?> value : attribute )
                    {
                        if ( value.getBytes() == null )
                        {
                            localValuesLength += 1 + 1;
                        }
                        else
                        {
                            int valueLength = value.getBytes().length;
                            localValuesLength += 1 + TLV.getNbBytes( valueLength ) + valueLength;
                        }
                    }

                    localAttributeLength += 1 + TLV.getNbBytes( localValuesLength ) + localValuesLength;
                }
                else
                {
                    // No value : we still have to store the encapsulating Sequence
                    localValuesLength = 1 + 1;
                    localAttributeLength += 1 + 1 + localValuesLength;
                }

                // add the attribute length to the attributes length
                entryLength += 1 + TLV.getNbBytes( localAttributeLength ) + localAttributeLength;

                attributesLength.add( localAttributeLength );
                valuesLength.add( localValuesLength );
            }
        }

        addRequestLength += 1 + TLV.getNbBytes( entryLength ) + entryLength;

        // Return the result.
        return 1 + TLV.getNbBytes( addRequestLength ) + addRequestLength;
    }


    /**
     * Encode the AddRequest message to a PDU.
     * <br>
     * AddRequest :
     * <pre>
     * 0x68 LL
     *   0x04 LL entry
     *   0x30 LL attributesList
     *     0x30 LL attributeList
     *       0x04 LL attributeDescription
     *       0x31 LL attributeValues
     *         0x04 LL attributeValue
     *         ...
     *         0x04 LL attributeValue
     *     ...
     *     0x30 LL attributeList
     *       0x04 LL attributeDescription
     *       0x31 LL attributeValue
     *         0x04 LL attributeValue
     *         ...
     *         0x04 LL attributeValue
     * </pre>
     * 
     * @param buffer The buffer where to put the PDU
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        try
        {
            // The AddRequest Tag
            buffer.put( LdapCodecConstants.ADD_REQUEST_TAG );
            buffer.put( TLV.getBytes( addRequestLength ) );

            // The entry
            BerValue.encode( buffer, dnBytes );

            // The attributes sequence
            buffer.put( UniversalTag.SEQUENCE.getValue() );
            buffer.put( TLV.getBytes( entryLength ) );

            // The partial attribute list
            Entry entry = getEntry();

            if ( entry.size() != 0 )
            {
                int attributeNumber = 0;

                // Compute the attributes length
                for ( Attribute attribute : entry )
                {
                    // The attributes list sequence
                    buffer.put( UniversalTag.SEQUENCE.getValue() );
                    int localAttributeLength = attributesLength.get( attributeNumber );
                    buffer.put( TLV.getBytes( localAttributeLength ) );

                    // The attribute type
                    BerValue.encode( buffer, attributeIds.get( attributeNumber ) );

                    // The values
                    buffer.put( UniversalTag.SET.getValue() );
                    int localValuesLength = valuesLength.get( attributeNumber );
                    buffer.put( TLV.getBytes( localValuesLength ) );

                    if ( attribute.size() != 0 )
                    {
                        for ( Value<?> value : attribute )
                        {
                            BerValue.encode( buffer, value.getBytes() );
                        }
                    }
                    else
                    {
                        BerValue.encode( buffer, Strings.EMPTY_BYTES );
                    }

                    // Go to the next attribute number
                    attributeNumber++;
                }
            }

            return buffer;
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( "The PDU buffer size is too small !", boe );
        }
    }
}
