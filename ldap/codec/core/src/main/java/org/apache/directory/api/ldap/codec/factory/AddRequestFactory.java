/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
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
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.util.CollectionUtils;
import org.apache.directory.api.util.Strings;

/**
 * The AddRequest factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class AddRequestFactory implements Messagefactory
{
    /** The static instance */
    public static final AddRequestFactory INSTANCE = new AddRequestFactory();

    /**
     * A default private constructor
     */
    private AddRequestFactory()
    {
        // Nothing to do
    }


    /**
     * Encode an entry's Attribute's values. It's done in reverse order, to have the
     * last value encoded first in the reverse buffer.
     * <br>
     * The values are encoded this way :
     * <pre>
     * 0x31 LL attributeValues
     *   0x04 LL attributeValue
     *   ...
     *   0x04 LL attributeValue
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param iterator The iterator built on top of the values
     */
    private void encodeValueReverse( Asn1Buffer buffer, Iterator<Value> iterator )
    {
        iterator = CollectionUtils.reverse( iterator );
        while ( iterator.hasNext() )
        {
            Value value = iterator.next();

            // Encode the value
            BerValue.encodeOctetString( buffer, value.getBytes() );
        }
    }


    /**
     * Encode the attributes, starting from the end. We iterate through the list
     * of attributes in reverse order. The last attribute will be encoded first, when
     * the end of the list will be reached, which is what we went, as we encode from
     * the end.
     * <br>
     * An attribute is encoded this way:
     * <pre>
     *     0x30 LL attribute
     *       0x04 LL attributeType
     *       0x31 LL attributeValues
     *         0x04 LL attributeValue
     *         ...
     *         0x04 LL attributeValue
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param iterator The iterator built on top of the attributes
     */
    private void encodeAttributeReverse( Asn1Buffer buffer, Iterator<Attribute> iterator )
    {
        iterator = CollectionUtils.reverse( iterator );
        while ( iterator.hasNext() )
        {
            Attribute attribute = iterator.next();

            // Remind the current position
            int start = buffer.getPos();

            // The attributes values
            if ( attribute.size() == 0 )
            {
                BerValue.encodeOctetString( buffer, Strings.EMPTY_BYTES );
            }
            else
            {
                encodeValueReverse( buffer, attribute.iterator() );
            }

            // Then the values' SET
            BerValue.encodeSet( buffer, start );

            // The attribute type
            BerValue.encodeOctetString( buffer, attribute.getUpId() );

            // The attribute sequence
            BerValue.encodeSequence( buffer, start );
        }
    }

    /**
     * Encode the AddRequest message to a PDU.
     * <br>
     * AddRequest :
     * <pre>
     * 0x68 LL
     *   0x04 LL entry
     *   0x30 LL attributesList
     *     0x30 LL attribute
     *       0x04 LL attributeDescription
     *       0x31 LL attributeValues
     *         0x04 LL attributeValue
     *         ...
     *         0x04 LL attributeValue
     *     ...
     *     0x30 LL attribute
     *       0x04 LL attributeDescription
     *       0x31 LL attributeValue
     *         0x04 LL attributeValue
     *         ...
     *         0x04 LL attributeValue
     * </pre>
     *
     * @param codec The LdapApiService instance
     * @param buffer The buffer where to put the PDU
     * @param message the AbandonRequest to encode
     */
    @Override
    public void encodeReverse( LdapApiService codec, Asn1Buffer buffer, Message message )
    {
        int start = buffer.getPos();
        AddRequest addRequest = ( AddRequest ) message;

        // The partial attribute list
        Entry entry = addRequest.getEntry();

        if ( entry.size() != 0 )
        {
            // Encode the attributes
            encodeAttributeReverse( buffer, entry.iterator() );
        }

        // The attributes sequence
        BerValue.encodeSequence( buffer, start );

        // The entry DN
        BerValue.encodeOctetString( buffer, entry.getDn().getName() );

        // The AddRequest Tag
        BerValue.encodeSequence( buffer, LdapCodecConstants.ADD_REQUEST_TAG, start );
    }
}
