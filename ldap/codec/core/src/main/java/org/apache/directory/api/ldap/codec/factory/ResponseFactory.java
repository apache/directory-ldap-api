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
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.util.Strings;

/**
 * The Response factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class ResponseFactory implements Messagefactory
{
    // A default success bytes sequence
    private static final byte[] DEFAULT_SUCCESS = new byte[]
        { 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00 };

    private static final byte[] EMPTY_MATCHED_DN = new byte[]
        { 0x04, 0x00 };

    /**
     * Creates a new instance of ResponseFactory.
     */
    protected ResponseFactory()
    {
        // Nothing to do
    }


    /**
     * Encode referral's URLs recursively
     *
     * @param buffer The buffer that will contain the encoded urls
     * @param urls The urls to encode
     */
    private void encodeReferralUrls( Asn1Buffer buffer, Iterator<String> urls )
    {
        if ( urls.hasNext() )
        {
            String url = urls.next();

            encodeReferralUrls( buffer, urls );

            BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( url ) );
        }
    }


    /**
     * Encode the LdapResult element
     * <br>
     * LdapResult :
     * <pre>
     *   0x0A 01 resultCode (0..80)
     *   0x04 L1 matchedDN (L1 = Length(matchedDN))
     *   0x04 L2 errorMessage (L2 = Length(errorMessage))
     *   [0x83 L3] referrals
     *     |
     *     +--&gt; 0x04 L4 referral
     *     +--&gt; 0x04 L5 referral
     *     +--&gt; ...
     *     +--&gt; 0x04 Li referral
     *     +--&gt; ...
     *     +--&gt; 0x04 Ln referral
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param ldapResult The LdapResult instance
     */
    protected void encodeLdapResultReverse( Asn1Buffer buffer, LdapResult ldapResult )
    {
        if ( ldapResult.isDefaultSuccess() )
        {
            // The length of a default success PDU : 0xA0 0x01 0x00 0x04 0x00 0x04 0x00
            buffer.put( DEFAULT_SUCCESS );

            return;
        }

        // Referrals, if any
        Referral referral = ldapResult.getReferral();

        if ( referral != null )
        {
            Collection<String> urls = referral.getLdapUrls();

            if ( ( urls != null ) && !urls.isEmpty() )
            {
                encodeReferralUrls( buffer, urls.iterator() );
            }
        }

        // The errorMessage
        BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( ldapResult.getDiagnosticMessage() ) );

        // The matchedDN
        if ( ldapResult.getMatchedDn() != null )
        {
            BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( ldapResult.getMatchedDn().getName() ) );
        }
        else
        {
            buffer.put( EMPTY_MATCHED_DN );
        }

        // The result code
        BerValue.encodeEnumerated( buffer, ldapResult.getResultCode().getValue() );
    }
}
