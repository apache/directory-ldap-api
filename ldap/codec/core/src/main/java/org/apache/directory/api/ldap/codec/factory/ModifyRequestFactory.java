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

import java.util.Collection;
import java.util.Iterator;

import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.util.Strings;

/**
 * The ModifyRequest factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class ModifyRequestFactory implements Messagefactory
{
    /** The static instance */
    public static final ModifyRequestFactory INSTANCE = new ModifyRequestFactory();

    private ModifyRequestFactory()
    {
        // Nothing to do
    }


    /**
     * Encode the values, recursively
     * <pre>
     * 0x04 LL attributeValue
     * ...
     * 0x04 LL attributeValue
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param values the values to encode
     */
    private void encodeValues( Asn1Buffer buffer, Iterator<Value> values )
    {
        if ( values.hasNext() )
        {
            Value value = values.next();

            // Recurse on the values
            encodeValues( buffer, values );

            // The value
            if ( value.isHumanReadable() )
            {
                BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( value.getValue() ) );
            }
            else
            {
                BerValue.encodeOctetString( buffer, value.getBytes() );
            }
        }
    }

    /**
     * Recursively encode the modifications, starting from the last one.
     * <pre>
     * 0x30 LL modification sequence
     *   0x0A 0x01 operation
     *   0x30 LL modification
     *     0x04 LL type
     *     0x31 LL vals
     *       0x04 LL attributeValue
     *       ...
     *       0x04 LL attributeValue
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param modifications the modifications to encode
     */
    private void encodeModifications( Asn1Buffer buffer, Iterator<Modification> modifications )
    {
        if ( modifications.hasNext() )
        {
            Modification modification = modifications.next();

            // Recurse
            encodeModifications( buffer, modifications );

            int start = buffer.getPos();

            // The Attribute
            Attribute attribute = modification.getAttribute();

            // The values, if any
            if ( modification.getAttribute().size() != 0 )
            {
                encodeValues( buffer, modification.getAttribute().iterator() );
            }

            // the value set
            BerValue.encodeSet( buffer, start );

            // The attribute type
            BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( attribute.getUpId() ) );

            // The attribute sequence
            BerValue.encodeSequence( buffer, start );

            // The operation
            BerValue.encodeEnumerated( buffer, modification.getOperation().getValue() );

            // The modification sequence
            BerValue.encodeSequence( buffer, start );
        }
    }

    /**
     * Encode the ModifyRequest message to a PDU.
     * <br>
     * ModifyRequest :
     * <pre>
     * 0x66 LL
     *   0x04 LL object
     *   0x30 LL modifications
     *     0x30 LL modification sequence
     *       0x0A 0x01 operation
     *       0x30 LL modification
     *         0x04 LL type
     *         0x31 LL vals
     *           0x04 LL attributeValue
     *           ...
     *           0x04 LL attributeValue
     *     ...
     *     0x30 LL modification sequence
     *       0x0A 0x01 operation
     *       0x30 LL modification
     *         0x04 LL type
     *         0x31 LL vals
     *           0x04 LL attributeValue
     *           ...
     *           0x04 LL attributeValue
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param message the ModifyRequest to encode
     */
    @Override
    public void encodeReverse( Asn1Buffer buffer, Message message )
    {
        int start = buffer.getPos();
        ModifyRequest modifyRequest = ( ModifyRequest ) message;

        // The modifications, if any
        Collection<Modification> modifications = modifyRequest.getModifications();

        if ( ( modifications != null ) && ( !modifications.isEmpty() ) )
        {
            encodeModifications( buffer, modifications.iterator() );

            // The modifications sequence
            BerValue.encodeSequence( buffer, start );
        }

        // The entry DN
        BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( modifyRequest.getName().getName() ) );

        // The ModifyRequest tag
        BerValue.encodeSequence( buffer, LdapCodecConstants.MODIFY_REQUEST_TAG, start );
    }
}
