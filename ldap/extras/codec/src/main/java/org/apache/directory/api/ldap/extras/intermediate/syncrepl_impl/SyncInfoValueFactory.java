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
package org.apache.directory.api.ldap.extras.intermediate.syncrepl_impl;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Container;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.IntermediateOperationFactory;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl.SyncInfoValue;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl.SyncInfoValueImpl;
import org.apache.directory.api.ldap.model.message.IntermediateResponse;


/**
 * A {@link IntermediateOperationFactory} which creates {@link SyncInfoValue} instances.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class SyncInfoValueFactory implements IntermediateOperationFactory
{
    /**
     * Creates a new instance of SyncInfoValueFactory.
     *
     * @param codec The codec for this factory.
     */
    public SyncInfoValueFactory()
    {
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return SyncInfoValue.OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SyncInfoValue newResponse()
    {
        return new SyncInfoValueImpl();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SyncInfoValue newResponse( byte[] responseValue )
    {
        SyncInfoValue syncInfoValue = new SyncInfoValueImpl();
        
        try
        {
            decodeValue( syncInfoValue, responseValue );
        }
        catch ( DecoderException de )
        {
            
        }

        return syncInfoValue;
    }


    @Override
    public void encodeValue( Asn1Buffer buffer, IntermediateResponse intermediateResponse )
    {
        int start = buffer.getPos();
        SyncInfoValue syncInfoValue = ( SyncInfoValue ) intermediateResponse;
        
        switch ( syncInfoValue.getSyncInfoValueType() )
        {
            case NEW_COOKIE:
                // The cookie
                BerValue.encodeOctetString( buffer, 
                    ( byte ) SyncInfoValueTags.NEW_COOKIE_TAG.getValue(),
                    syncInfoValue.getCookie() );
                break;
                
            case REFRESH_DELETE:
                // The refreshDone flag if false
                if ( !syncInfoValue.isRefreshDone() )
                {
                    BerValue.encodeBoolean( buffer, false );
                }
                
                // The cookie, if any
                if ( syncInfoValue.getCookie() != null )
                {
                    BerValue.encodeOctetString( buffer, syncInfoValue.getCookie() );
                }
                
                // The sequence
                BerValue.encodeSequence( buffer, 
                    ( byte ) SyncInfoValueTags.REFRESH_DELETE_TAG.getValue(), start );
                break;
                
            case REFRESH_PRESENT:
                // The refreshDone flag if false
                if ( !syncInfoValue.isRefreshDone() )
                {
                    BerValue.encodeBoolean( buffer, false );
                }
                
                // The cookie, if any
                if ( syncInfoValue.getCookie() != null )
                {
                    BerValue.encodeOctetString( buffer, syncInfoValue.getCookie() );
                }
                
                // The sequence
                BerValue.encodeSequence( buffer, 
                    ( byte ) SyncInfoValueTags.REFRESH_PRESENT_TAG.getValue(), start );
                break;
                
            case SYNC_ID_SET:
                // The syncUUID set
                if ( !syncInfoValue.getSyncUUIDs().isEmpty() )
                {
                    for ( int i = syncInfoValue.getSyncUUIDs().size(); i > 0; i-- )
                    {
                        BerValue.encodeOctetString( buffer, syncInfoValue.getSyncUUIDs().get( i - 1 ) );
                    }
                }

                // The set
                BerValue.encodeSet( buffer, start );

                // The refreshDeletes flag if false
                if ( syncInfoValue.isRefreshDeletes() )
                {
                    BerValue.encodeBoolean( buffer, true );
                }
                
                // The cookie, if any
                if ( syncInfoValue.getCookie() != null )
                {
                    BerValue.encodeOctetString( buffer, syncInfoValue.getCookie() );
                }
                
                // The sequence
                BerValue.encodeSequence( buffer, 
                    ( byte ) SyncInfoValueTags.SYNC_ID_SET_TAG.getValue(), start );
                break;
                
            default:
                break;
        }
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( IntermediateResponse intermediateResponse, byte[] responseValue ) throws DecoderException
    {
        ByteBuffer buffer = ByteBuffer.wrap( responseValue );
        SyncInfoValueContainer container = new SyncInfoValueContainer( ( SyncInfoValue ) intermediateResponse );
        new Asn1Decoder().decode( buffer, ( Asn1Container ) container );
    }
}
