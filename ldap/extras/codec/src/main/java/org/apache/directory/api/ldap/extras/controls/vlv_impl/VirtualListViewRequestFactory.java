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

package org.apache.directory.api.ldap.extras.controls.vlv_impl;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractControlFactory;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequestImpl;
import org.apache.directory.api.ldap.model.message.Control;


/**
 * A {@link ControlFactory} for {@link VirtualListViewRequest} controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class VirtualListViewRequestFactory extends AbstractControlFactory<VirtualListViewRequest>
{
    /**
     * Creates a new instance of VirtualListViewRequestFactory.
     *
     * @param codec The codec for this factory.
     */
    public VirtualListViewRequestFactory( LdapApiService codec )
    {
        super( codec, VirtualListViewRequest.OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public VirtualListViewRequest newControl()
    {
        return new VirtualListViewRequestImpl( );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, Control control )
    {
        int start = buffer.getPos();
        VirtualListViewRequest vlvRequest = ( VirtualListViewRequest ) control;
        
        // The contextID
        if ( vlvRequest.getContextId() != null )
        {
            BerValue.encodeOctetString( buffer, vlvRequest.getContextId() );
        }
        
        if ( vlvRequest.hasOffset() )
        {
            int offsetStart = buffer.getPos();

            // The contentCount
            BerValue.encodeInteger( buffer, vlvRequest.getContentCount() );
            
            // The offset
            BerValue.encodeInteger( buffer, vlvRequest.getOffset() );

            // The byOffset tag
            BerValue.encodeSequence( buffer, ( byte ) VirtualListViewerTags.BY_OFFSET_TAG.getValue(), offsetStart );
        }
        else
        {
            // The assertion value
            BerValue.encodeOctetString( buffer, 
                ( byte ) VirtualListViewerTags.ASSERTION_VALUE_TAG.getValue(), 
                vlvRequest.getAssertionValue() );
        }
        
        // after count
        BerValue.encodeInteger( buffer, vlvRequest.getAfterCount() );
        
        // before count
        BerValue.encodeInteger( buffer, vlvRequest.getBeforeCount() );
        
        // The sequence
        BerValue.encodeSequence( buffer, start );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( Control control, byte[] controlBytes ) throws DecoderException
    {
        decodeValue( new VirtualListViewRequestContainer( control ), control, controlBytes );
    }
}
