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
package org.apache.directory.api.ldap.extras.controls.ad_impl;


import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncResponse;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncResponseFlag;
import org.apache.directory.api.ldap.model.message.Control;


/**
 * A {@link ControlFactory} which creates {@link AdDirSyncResponse} controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class AdDirSyncResponseFactory implements ControlFactory<AdDirSyncResponse>
{
    /** The codec for this factory */
    private LdapApiService codec;


    /**
     * Creates a new instance of AdDirSyncResponseFactory.
     *
     * @param codec The codec for this factory.
     */
    public AdDirSyncResponseFactory( LdapApiService codec )
    {
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return AdDirSyncResponse.OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<AdDirSyncResponse> newCodecControl()
    {
        return new AdDirSyncResponseDecorator( codec );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<AdDirSyncResponse> newCodecControl( AdDirSyncResponse control )
    {
        return new AdDirSyncResponseDecorator( codec, control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, Control control )
    {
        AdDirSyncResponse adDirSync = ( AdDirSyncResponse ) control;
        int start = buffer.getPos();

        // Encode the cookie
        BerValue.encodeOctetString( buffer, adDirSync.getCookie() );

        // Encode the MaxReturnLength/
        BerValue.encodeInteger( buffer, adDirSync.getMaxReturnLength() );

        // Encode the flags
        BerValue.encodeInteger( buffer, AdDirSyncResponseFlag.getBitmask( adDirSync.getFlags() ) );

        // Encode the SEQ
        BerValue.encodeSequence( buffer, start );
    }
}
