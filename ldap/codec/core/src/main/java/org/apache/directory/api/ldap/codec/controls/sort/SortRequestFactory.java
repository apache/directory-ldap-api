/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.codec.controls.sort;


import java.util.Iterator;
import java.util.List;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractControlFactory;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.controls.SortKey;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.message.controls.SortRequestImpl;
import org.apache.directory.api.util.Strings;


/**
 * A {@link ControlFactory} for SortRequestControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class SortRequestFactory extends AbstractControlFactory<SortRequest>
{
    /** ASN.1 BER tag for the forward ordering rule */
    public static final int ORDERING_RULE_TAG = 0x80;

    /** ASN.1 BER tag for the backward ordering rule */
    public static final int REVERSE_ORDER_TAG = 0x81;

    /** 
     * Creates a new instance of SortRequestFactory.
     *
     * @param codec The LDAP codec.
     */
    public SortRequestFactory( LdapApiService codec )
    {
        super( codec, SortRequest.OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SortRequest newControl()
    {
        return new SortRequestImpl();
    }


    /**
     *
     * Encode the SortKeys recursively
     *
     * @param buffer the buffer that will contain the encoded value
     * @param sortKeys The Sortkeys to encode
     */
    private void encodeSortKeys( Asn1Buffer buffer, Iterator<SortKey> sortKeys )
    {
        if ( sortKeys.hasNext() )
        {
            SortKey sortKey = sortKeys.next();

            // Recurse
            encodeSortKeys( buffer, sortKeys );

            int start = buffer.getPos();

            // The reverseOrder flag
            if ( sortKey.isReverseOrder() )
            {
                BerValue.encodeBoolean( buffer, ( byte ) REVERSE_ORDER_TAG, true );
            }

            // The matchingRule ID, if any
            if ( sortKey.getMatchingRuleId() != null )
            {
                BerValue.encodeOctetString( buffer, ( byte ) ORDERING_RULE_TAG,
                    Strings.getBytesUtf8Ascii( sortKey.getMatchingRuleId() ) );
            }

            // The attributeType
            BerValue.encodeOctetString( buffer, sortKey.getAttributeTypeDesc() );

            // The sequence
            BerValue.encodeSequence( buffer, start );
        }
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, Control control )
    {
        SortRequest sortRequest = ( SortRequest ) control;

        int start = buffer.getPos();

        // Iterate on all the sort keys
        List<SortKey> sortKeys = sortRequest.getSortKeys();

        encodeSortKeys( buffer, sortKeys.iterator() );

        // The overall sequence
        BerValue.encodeSequence( buffer, start );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( Control control, byte[] controlBytes ) throws DecoderException
    {
        decodeValue( new SortRequestContainer( control ), control, controlBytes );
    }
}
