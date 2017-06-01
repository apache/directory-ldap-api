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
import org.apache.directory.api.ldap.codec.api.MessageDecorator;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;


/**
 * A decorator for the SearchResultEntry message
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SearchResultEntryDecorator extends MessageDecorator<SearchResultEntry> implements SearchResultEntry
{
    /** A temporary storage for the byte[] representing the objectName */
    private byte[] objectNameBytes;

    /** The search result entry length */
    private int searchResultEntryLength;

    /** The partial attributes length */
    private int attributesLength;

    /** The list of all attributes length */
    private List<Integer> attributeLength;

    /** The list of all attributes Id bytes */
    private List<byte[]> attributeIds;

    /** The list of all values length */
    private List<Integer> valuesLength;

    /** The current attribute being processed */
    private Attribute currentAttribute;


    /**
     * Makes a SearchResultEntry encodable.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage the decorated SearchResultEntry
     */
    public SearchResultEntryDecorator( LdapApiService codec, SearchResultEntry decoratedMessage )
    {
        super( codec, decoratedMessage );
    }


    /**
     * @return The current attribute
     */
    public Attribute getCurrentAttribute()
    {
        return currentAttribute;
    }


    /**
     * Create a new attribute
     * 
     * @param type The attribute's type
     * @throws LdapException If the value is invalid
     */
    public void addAttribute( String type ) throws LdapException
    {
        currentAttribute = new DefaultAttribute( type );

        getDecorated().getEntry().put( currentAttribute );
    }


    /**
     * Create a new attribute
     * 
     * @param type The attribute's type
     * @throws LdapException If the value is invalid
     */
    public void addAttribute( byte[] type ) throws LdapException
    {
        currentAttribute = new DefaultAttribute( type );

        getDecorated().getEntry().put( currentAttribute );
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The added value
     * @throws LdapException If the value is invalid
     */
    public void addAttributeValue( Object value ) throws LdapException
    {
        if ( value instanceof String )
        {
            currentAttribute.add( ( String ) value );
        }
        else
        {
            currentAttribute.add( ( byte[] ) value );
        }
    }


    //-------------------------------------------------------------------------
    // The IntermediateResponse methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getObjectName()
    {
        return getDecorated().getObjectName();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setObjectName( Dn objectName )
    {
        getDecorated().setObjectName( objectName );
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
    public void setEntry( Entry entry )
    {
        getDecorated().setEntry( entry );
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------

    /**
     * Compute the SearchResultEntry length
     * <br>
     * SearchResultEntry :
     * <pre>
     * 0x64 L1
     *  |
     *  +--&gt; 0x04 L2 objectName
     *  +--&gt; 0x30 L3 (attributes)
     *        |
     *        +--&gt; 0x30 L4-1 (partial attributes list)
     *        |     |
     *        |     +--&gt; 0x04 L5-1 type
     *        |     +--&gt; 0x31 L6-1 (values)
     *        |           |
     *        |           +--&gt; 0x04 L7-1-1 value
     *        |           +--&gt; ...
     *        |           +--&gt; 0x04 L7-1-n value
     *        |
     *        +--&gt; 0x30 L4-2 (partial attributes list)
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
     *        +--&gt; 0x30 L4-m (partial attributes list)
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
        Dn dn = getObjectName();

        objectNameBytes = Strings.getBytesUtf8Ascii( dn.getName() );

        // The entry
        searchResultEntryLength = 1 + TLV.getNbBytes( objectNameBytes.length ) + objectNameBytes.length;

        // The attributes sequence
        attributesLength = 0;

        Entry entry = getEntry();

        if ( ( entry != null ) && ( entry.size() != 0 ) )
        {
            attributeLength = new LinkedList<>();
            attributeIds = new LinkedList<>();
            valuesLength = new LinkedList<>();

            // Store those lists in the object
            valuesLength = new LinkedList<>();

            // Compute the attributes length
            for ( Attribute attribute : entry )
            {
                int localAttributeLength;
                int localValuesLength = 0;

                // Get the type length
                byte[] attributeIdBytes = Strings.getBytesUtf8Ascii( attribute.getUpId() );
                attributeIds.add( attributeIdBytes );
                int idLength = attributeIdBytes.length;
                localAttributeLength = 1 + TLV.getNbBytes( idLength ) + idLength;

                if ( attribute.size() != 0 )
                {
                    // The values
                    if ( attribute.size() > 0 )
                    {
                        localValuesLength = 0;

                        for ( org.apache.directory.api.ldap.model.entry.Value<?> value : attribute )
                        {
                            byte[] binaryValue = value.getBytes();
                            localValuesLength += 1 + TLV.getNbBytes( binaryValue.length ) + binaryValue.length;
                        }

                        localAttributeLength += 1 + TLV.getNbBytes( localValuesLength ) + localValuesLength;
                    }
                    else
                    {
                        // We have to deal with the special case where
                        // we don't have a value.
                        // It will be encoded as an empty OCTETSTRING,
                        // so it will be two bytes long (0x04 0x00)
                        localAttributeLength += 1 + 1;
                    }
                }
                else
                {
                    // We have no values. We will just have an empty SET OF :
                    // 0x31 0x00
                    localAttributeLength += 1 + 1;
                }

                // add the attribute length to the attributes length
                attributesLength += 1 + TLV.getNbBytes( localAttributeLength ) + localAttributeLength;

                // Store the lengths of the encoded attributes and values
                attributeLength.add( localAttributeLength );
                valuesLength.add( localValuesLength );
            }
        }

        searchResultEntryLength += 1 + TLV.getNbBytes( attributesLength ) + attributesLength;

        // Return the result.
        return 1 + TLV.getNbBytes( searchResultEntryLength ) + searchResultEntryLength;
    }


    /**
     * Encode the SearchResultEntry message to a PDU.
     * <br>
     * SearchResultEntry :
     * <pre>
     * 0x64 LL
     *   0x04 LL objectName
     *   0x30 LL attributes
     *     0x30 LL partialAttributeList
     *       0x04 LL type
     *       0x31 LL vals
     *         0x04 LL attributeValue
     *         ...
     *         0x04 LL attributeValue
     *     ...
     *     0x30 LL partialAttributeList
     *       0x04 LL type
     *       0x31 LL vals
     *         0x04 LL attributeValue
     *         ...
     *         0x04 LL attributeValue
     * </pre>
     * 
     * @param buffer The buffer where to put the PDU
     * @return The PDU.
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        try
        {
            // The SearchResultEntry Tag
            buffer.put( LdapCodecConstants.SEARCH_RESULT_ENTRY_TAG );
            buffer.put( TLV.getBytes( searchResultEntryLength ) );

            // The objectName
            BerValue.encode( buffer, objectNameBytes );

            // The attributes sequence
            buffer.put( UniversalTag.SEQUENCE.getValue() );
            buffer.put( TLV.getBytes( attributesLength ) );

            // The partial attribute list
            Entry entry = getEntry();

            if ( ( entry != null ) && ( entry.size() != 0 ) )
            {
                int attributeNumber = 0;

                // Compute the attributes length
                for ( Attribute attribute : entry )
                {
                    // The partial attribute list sequence
                    buffer.put( UniversalTag.SEQUENCE.getValue() );
                    int localAttributeLength = attributeLength.get( attributeNumber );
                    buffer.put( TLV.getBytes( localAttributeLength ) );

                    // The attribute type
                    BerValue.encode( buffer, attributeIds.get( attributeNumber ) );

                    // The values
                    buffer.put( UniversalTag.SET.getValue() );
                    int localValuesLength = valuesLength.get( attributeNumber );
                    buffer.put( TLV.getBytes( localValuesLength ) );

                    if ( attribute.size() > 0 )
                    {
                        for ( Value<?> value : attribute )
                        {
                            BerValue.encode( buffer, value.getBytes() );
                        }
                    }

                    // Go to the next attribute number
                    attributeNumber++;
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
