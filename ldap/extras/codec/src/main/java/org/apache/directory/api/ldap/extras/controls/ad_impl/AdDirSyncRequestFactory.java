/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.extras.controls.ad_impl;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractControlFactory;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncRequest;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncRequestImpl;
import org.apache.directory.api.ldap.model.message.Control;


/**
 * A {@link ControlFactory} which creates {@link AdDirSyncRequest} controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class AdDirSyncRequestFactory extends AbstractControlFactory<AdDirSyncRequest>
{
    /**
     * Creates a new instance of AdDirSyncRequestFactory.
     *
     * @param codec The codec for this factory.
     */
    public AdDirSyncRequestFactory( LdapApiService codec )
    {
        super( codec, AdDirSyncRequest.OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AdDirSyncRequest newControl()
    {
        return new AdDirSyncRequestImpl();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, Control control )
    {
        AdDirSyncRequest adDirSync = ( AdDirSyncRequest ) control;
        int start = buffer.getPos();

        // Encode the cookie
        BerValue.encodeOctetString( buffer, adDirSync.getCookie() );

        // Encode the MaxAttributeCount
        BerValue.encodeInteger( buffer, adDirSync.getMaxAttributeCount() );

        // Encode the ParentFirst value
        BerValue.encodeInteger( buffer, adDirSync.getParentsFirst() );

        // Encode the SEQ
        BerValue.encodeSequence( buffer, start );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( Control control, byte[] controlBytes ) throws DecoderException
    {
        decodeValue( new AdDirSyncRequestContainer( control ), control, controlBytes );
    }
}
