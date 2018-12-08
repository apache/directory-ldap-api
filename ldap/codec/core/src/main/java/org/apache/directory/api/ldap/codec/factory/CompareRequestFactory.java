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

import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.message.CompareRequest;
import org.apache.directory.api.ldap.model.message.Message;

/**
 * The CompareRequest factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class CompareRequestFactory implements Messagefactory
{
    /** The static instance */
    public static final CompareRequestFactory INSTANCE = new CompareRequestFactory();

    private CompareRequestFactory()
    {
        // Nothing to do
    }

    /**
     * Encode the CompareRequest message to a PDU.
     * <br>
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
     * @param message the CompareRequest to encode
     */
    @Override
    public void encodeReverse( Asn1Buffer buffer, Message message )
    {
        int pos = buffer.getPos();
        CompareRequest compareMessage = ( CompareRequest ) message;

        // The assertionValue
        BerValue.encodeOctetString( buffer, compareMessage.getAssertionValue().getBytes() );

        // The attributeDesc
        BerValue.encodeOctetString( buffer, compareMessage.getAttributeId() );

        // The attributeValueAssertion sequence Tag
        BerValue.encodeSequence( buffer, pos );

        // The entry DN
        BerValue.encodeOctetString( buffer, compareMessage.getName().getName() );

        // The CompareRequest Tag
        BerValue.encodeSequence( buffer, LdapCodecConstants.COMPARE_REQUEST_TAG, pos );
    }
}
