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

import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.SearchResultReference;

/**
 * The SearchResultReference factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class SearchResultReferenceFactory extends ResponseFactory
{
    /** The static instance */
    public static final SearchResultReferenceFactory INSTANCE = new SearchResultReferenceFactory();

    /**
     * A default private constructor
     */
    private SearchResultReferenceFactory()
    {
        super();
    }


    /**
     * Encode the SearchResultReference message to a PDU.
     * <br>
     * SearchResultReference :
     * <pre>
     * 0x73 LL
     *   0x04 LL reference
     *   [0x04 LL reference]*
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param message the SearchResultReference to encode
     */
    @Override
    public void encodeReverse( LdapApiService codec, Asn1Buffer buffer, Message message )
    {
        int start = buffer.getPos();

        SearchResultReference searchResultReference = ( SearchResultReference ) message;

        // The referrals, if any
        Referral referral = searchResultReference.getReferral();

        if ( referral != null )
        {
            // Each referral
            encodeReferralUrls( buffer, referral.getLdapUrls().iterator() );
        }

        // The SearchResultEntry tag
        BerValue.encodeSequence( buffer, LdapCodecConstants.SEARCH_RESULT_REFERENCE_TAG, start );
    }
}
