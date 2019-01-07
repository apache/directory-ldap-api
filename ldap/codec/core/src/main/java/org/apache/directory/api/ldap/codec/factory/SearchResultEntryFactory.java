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
package org.apache.directory.api.ldap.codec.factory;

import java.util.Iterator;

import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;

/**
 * The SearchResultEntry factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class SearchResultEntryFactory extends ResponseFactory
{
    /** The static instance */
    public static final SearchResultEntryFactory INSTANCE = new SearchResultEntryFactory();

    private SearchResultEntryFactory()
    {
        super();
    }


    /**
     * Encode the values recursively
     *
     * <pre>
     * 0x04 LL attributeValue
     * ...
     * 0x04 LL attributeValue
     * </pre>
     *
     * @param codec The LdapApiService instance
     * @param buffer The buffer where to put the PDU
     * @param values The iterator on the values
     */
    private void encodeValues( Asn1Buffer buffer, Iterator<Value> values )
    {
        if ( values.hasNext() )
        {
            Value value = values.next();

            encodeValues( buffer, values );

            // The value
            if ( value.isHumanReadable() )
            {
                BerValue.encodeOctetString( buffer, value.getString() );
            }
            else
            {
                BerValue.encodeOctetString( buffer, value.getBytes() );
            }
        }
    }


    /**
     * Encode the attributes recursively
     *
     * <pre>
     *  0x30 LL partialAttributeList
     *    0x04 LL type
     *    0x31 LL vals
     *      0x04 LL attributeValue
     *      ...
     *      0x04 LL attributeValue
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param attributes The iterator on the attributes
     */
    private void encodeAttributes( Asn1Buffer buffer, Iterator<Attribute> attributes )
    {
        if ( attributes.hasNext() )
        {
            Attribute attribute = attributes.next();

            // Recursive call
            encodeAttributes( buffer, attributes );

            int start = buffer.getPos();

            // The values, recursively, if any
            if ( attribute.size() != 0 )
            {
                encodeValues( buffer, attribute.iterator() );
            }

            // The values set
            BerValue.encodeSet( buffer, start );

            // The attribute type
            BerValue.encodeOctetString( buffer, attribute.getUpId() );

            // Attribute sequence
            BerValue.encodeSequence( buffer, start );
        }
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
     * @param message the SearchResultEntry to encode
     */
    @Override
    public void encodeReverse( LdapApiService codec, Asn1Buffer buffer, Message message )
    {
        int start = buffer.getPos();

        SearchResultEntry searchResultEntry = ( SearchResultEntry ) message;

        // The partial attribute list
        Entry entry = searchResultEntry.getEntry();

        // The attributes, recursively, if we have any
        if ( ( entry != null ) && ( entry.size() != 0 ) )
        {
            encodeAttributes( buffer, entry.iterator() );
        }

        // The attributes sequence
        BerValue.encodeSequence( buffer, start );

        // The objectName
        BerValue.encodeOctetString( buffer, searchResultEntry.getObjectName().getName() );

        // The SearchResultEntry tag
        BerValue.encodeSequence( buffer, LdapCodecConstants.SEARCH_RESULT_ENTRY_TAG, start );
    }
}
