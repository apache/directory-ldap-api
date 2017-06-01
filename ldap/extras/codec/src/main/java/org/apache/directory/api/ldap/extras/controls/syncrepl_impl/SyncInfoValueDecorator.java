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
package org.apache.directory.api.ldap.extras.controls.syncrepl_impl;


import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.asn1.Asn1Object;
import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ControlDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncInfoValue.SyncInfoValue;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncInfoValue.SyncInfoValueImpl;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncInfoValue.SynchronizationInfoEnum;
import org.apache.directory.api.util.Strings;


/**
 * A syncInfoValue object, as defined in RFC 4533
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SyncInfoValueDecorator extends ControlDecorator<SyncInfoValue> implements SyncInfoValue
{
    /** The syncUUIDs cumulative length */
    private int syncUUIDsLength;

    /** An instance of this decoder */
    private static final Asn1Decoder DECODER = new Asn1Decoder();

    /** The global length for this control */
    private int syncInfoValueLength;


    /**
     * The constructor for this codec. Dont't forget to set the type.
     * 
     * @param codec The LDAP Service to use
     */
    public SyncInfoValueDecorator( LdapApiService codec )
    {
        super( codec, new SyncInfoValueImpl() );
    }


    /**
     * The constructor for this codec. Dont't forget to set the type.
     * 
     * @param codec The LDAP Service to use
     * @param control The SyncInfoValue to decorate
     */
    public SyncInfoValueDecorator( LdapApiService codec, SyncInfoValue control )
    {
        super( codec, control );
    }


    /**
     * The constructor for this codec.
     * 
     * @param codec The LDAP Service to use
     * @param type The kind of syncInfo we will store. Can be newCookie,
     * refreshPresent, refreshDelete or syncIdSet
     */
    public SyncInfoValueDecorator( LdapApiService codec, SynchronizationInfoEnum type )
    {
        this( codec );

        setType( type );
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public SynchronizationInfoEnum getType()
    {
        return getDecorated().getType();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setType( SynchronizationInfoEnum type )
    {
        this.getDecorated().setType( type );

        // Initialize the arrayList if needed
        if ( ( type == SynchronizationInfoEnum.SYNC_ID_SET ) && ( getDecorated().getSyncUUIDs() == null ) )
        {
            getDecorated().setSyncUUIDs( new ArrayList<byte[]>() );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getCookie()
    {
        return getDecorated().getCookie();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setCookie( byte[] cookie )
    {
        // Copy the bytes
        if ( !Strings.isEmpty( cookie ) )
        {
            byte[] copy = new byte[cookie.length];
            System.arraycopy( cookie, 0, copy, 0, cookie.length );
            getDecorated().setCookie( copy );
        }
        else
        {
            getDecorated().setCookie( null );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isRefreshDone()
    {
        return getDecorated().isRefreshDone();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setRefreshDone( boolean refreshDone )
    {
        getDecorated().setRefreshDone( refreshDone );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isRefreshDeletes()
    {
        return getDecorated().isRefreshDeletes();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setRefreshDeletes( boolean refreshDeletes )
    {
        getDecorated().setRefreshDeletes( refreshDeletes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<byte[]> getSyncUUIDs()
    {
        return getDecorated().getSyncUUIDs();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setSyncUUIDs( List<byte[]> syncUUIDs )
    {
        getDecorated().setSyncUUIDs( syncUUIDs );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void addSyncUUID( byte[] syncUUID )
    {
        getDecorated().addSyncUUID( syncUUID );
    }


    /**
     * Compute the SyncInfoValue length.
     * <br>
     * SyncInfoValue :
     * <pre>
     * 0xA0 L1 abcd                   // newCookie
     * 0xA1 L2                        // refreshDelete
     *   |
     *  [+--&gt; 0x04 L3 abcd]           // cookie
     *  [+--&gt; 0x01 0x01 (0x00|0xFF)   // refreshDone
     * 0xA2 L4                        // refreshPresent
     *   |
     *  [+--&gt; 0x04 L5 abcd]           // cookie
     *  [+--&gt; 0x01 0x01 (0x00|0xFF)   // refreshDone
     * 0xA3 L6                        // syncIdSet
     *   |
     *  [+--&gt; 0x04 L7 abcd]           // cookie
     *  [+--&gt; 0x01 0x01 (0x00|0xFF)   // refreshDeletes
     *   +--&gt; 0x31 L8                 // SET OF syncUUIDs
     *          |
     *         [+--&gt; 0x04 L9 abcd]    // syncUUID
     * </pre>
     * 
     * @return The computed length
     **/
    @Override
    public int computeLength()
    {
        // The mode length
        syncInfoValueLength = 0;

        switch ( getType() )
        {
            case NEW_COOKIE:
                if ( getCookie() != null )
                {
                    syncInfoValueLength = 1 + TLV.getNbBytes( getCookie().length ) + getCookie().length;
                }
                else
                {
                    syncInfoValueLength = 1 + 1;
                }

                valueLength = syncInfoValueLength;

                // Call the super class to compute the global control length
                return valueLength;

            case REFRESH_DELETE:
            case REFRESH_PRESENT:
                if ( getCookie() != null )
                {
                    syncInfoValueLength = 1 + TLV.getNbBytes( getCookie().length ) + getCookie().length;
                }

                // The refreshDone flag, only if not true, as it default to true
                if ( !isRefreshDone() )
                {
                    syncInfoValueLength += 1 + 1 + 1;
                }

                valueLength = 1 + TLV.getNbBytes( syncInfoValueLength ) + syncInfoValueLength;

                // Call the super class to compute the global control length
                return valueLength;

            case SYNC_ID_SET:
                if ( getCookie() != null )
                {
                    syncInfoValueLength = 1 + TLV.getNbBytes( getCookie().length ) + getCookie().length;
                }

                // The refreshDeletes flag, default to false
                if ( isRefreshDeletes() )
                {
                    syncInfoValueLength += 1 + 1 + 1;
                }

                // The syncUUIDs if any
                syncUUIDsLength = 0;

                if ( !getSyncUUIDs().isEmpty() )
                {
                    for ( byte[] syncUUID : getSyncUUIDs() )
                    {
                        int uuidLength = 1 + TLV.getNbBytes( syncUUID.length ) + syncUUID.length;

                        syncUUIDsLength += uuidLength;
                    }
                }

                syncInfoValueLength += 1 + TLV.getNbBytes( syncUUIDsLength ) + syncUUIDsLength;
                valueLength = 1 + TLV.getNbBytes( syncInfoValueLength ) + syncInfoValueLength;

                // Call the super class to compute the global control length
                return valueLength;

            default:

        }

        return 1 + TLV.getNbBytes( syncInfoValueLength ) + syncInfoValueLength;
    }


    /**
     * Encode the SyncInfoValue control
     *
     * @param buffer The encoded sink
     * @return A ByteBuffer that contains the encoded PDU
     * @throws EncoderException If anything goes wrong.
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04023 ) );
        }

        switch ( getType() )
        {
            case NEW_COOKIE:
                // The first case : newCookie
                buffer.put( ( byte ) SyncInfoValueTags.NEW_COOKIE_TAG.getValue() );

                // As the OCTET_STRING is absorbed by the Application tag,
                // we have to store the L and V separately
                if ( ( getCookie() == null ) || ( getCookie().length == 0 ) )
                {
                    buffer.put( ( byte ) 0 );
                }
                else
                {
                    buffer.put( TLV.getBytes( getCookie().length ) );
                    buffer.put( getCookie() );
                }

                break;

            case REFRESH_DELETE:
                // The second case : refreshDelete
                buffer.put( ( byte ) SyncInfoValueTags.REFRESH_DELETE_TAG.getValue() );
                buffer.put( TLV.getBytes( syncInfoValueLength ) );

                // The cookie, if any
                if ( getCookie() != null )
                {
                    BerValue.encode( buffer, getCookie() );
                }

                // The refreshDone flag
                if ( !isRefreshDone() )
                {
                    BerValue.encode( buffer, isRefreshDone() );
                }

                break;

            case REFRESH_PRESENT:
                // The third case : refreshPresent
                buffer.put( ( byte ) SyncInfoValueTags.REFRESH_PRESENT_TAG.getValue() );
                buffer.put( TLV.getBytes( syncInfoValueLength ) );

                // The cookie, if any
                if ( getCookie() != null )
                {
                    BerValue.encode( buffer, getCookie() );
                }

                // The refreshDone flag
                if ( !isRefreshDone() )
                {
                    BerValue.encode( buffer, isRefreshDone() );
                }

                break;

            case SYNC_ID_SET:
                // The last case : syncIdSet
                buffer.put( ( byte ) SyncInfoValueTags.SYNC_ID_SET_TAG.getValue() );
                buffer.put( TLV.getBytes( syncInfoValueLength ) );

                // The cookie, if any
                if ( getCookie() != null )
                {
                    BerValue.encode( buffer, getCookie() );
                }

                // The refreshDeletes flag if not false
                if ( isRefreshDeletes() )
                {
                    BerValue.encode( buffer, isRefreshDeletes() );
                }

                // The syncUUIDs
                buffer.put( UniversalTag.SET.getValue() );
                buffer.put( TLV.getBytes( syncUUIDsLength ) );

                // Loop on the UUIDs if any
                if ( !getSyncUUIDs().isEmpty() )
                {
                    for ( byte[] syncUUID : getSyncUUIDs() )
                    {
                        BerValue.encode( buffer, syncUUID );
                    }
                }

                break;

            default:
                throw new IllegalArgumentException( "Unexpected SynchronizationInfo: " + getType() );
        }

        return buffer;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getValue()
    {
        if ( value == null )
        {
            try
            {
                computeLength();
                ByteBuffer buffer = ByteBuffer.allocate( valueLength );

                switch ( getType() )
                {
                    case NEW_COOKIE:
                        // The first case : newCookie
                        buffer.put( ( byte ) SyncInfoValueTags.NEW_COOKIE_TAG.getValue() );

                        // As the OCTET_STRING is absorbed by the Application tag,
                        // we have to store the L and V separately
                        if ( ( getCookie() == null ) || ( getCookie().length == 0 ) )
                        {
                            buffer.put( ( byte ) 0 );
                        }
                        else
                        {
                            buffer.put( TLV.getBytes( getCookie().length ) );
                            buffer.put( getCookie() );
                        }

                        break;

                    case REFRESH_DELETE:
                        // The second case : refreshDelete
                        buffer.put( ( byte ) SyncInfoValueTags.REFRESH_DELETE_TAG.getValue() );
                        buffer.put( TLV.getBytes( syncInfoValueLength ) );

                        // The cookie, if any
                        if ( getCookie() != null )
                        {
                            BerValue.encode( buffer, getCookie() );
                        }

                        // The refreshDone flag
                        if ( !isRefreshDone() )
                        {
                            BerValue.encode( buffer, isRefreshDone() );
                        }

                        break;

                    case REFRESH_PRESENT:
                        // The third case : refreshPresent
                        buffer.put( ( byte ) SyncInfoValueTags.REFRESH_PRESENT_TAG.getValue() );
                        buffer.put( TLV.getBytes( syncInfoValueLength ) );

                        // The cookie, if any
                        if ( getCookie() != null )
                        {
                            BerValue.encode( buffer, getCookie() );
                        }

                        // The refreshDone flag
                        if ( !isRefreshDone() )
                        {
                            BerValue.encode( buffer, isRefreshDone() );
                        }

                        break;

                    case SYNC_ID_SET:
                        // The last case : syncIdSet
                        buffer.put( ( byte ) SyncInfoValueTags.SYNC_ID_SET_TAG.getValue() );
                        buffer.put( TLV.getBytes( syncInfoValueLength ) );

                        // The cookie, if any
                        if ( getCookie() != null )
                        {
                            BerValue.encode( buffer, getCookie() );
                        }

                        // The refreshDeletes flag if not false
                        if ( isRefreshDeletes() )
                        {
                            BerValue.encode( buffer, isRefreshDeletes() );
                        }

                        // The syncUUIDs
                        buffer.put( UniversalTag.SET.getValue() );
                        buffer.put( TLV.getBytes( syncUUIDsLength ) );

                        // Loop on the UUIDs if any
                        if ( !getSyncUUIDs().isEmpty() )
                        {
                            for ( byte[] syncUUID : getSyncUUIDs() )
                            {
                                BerValue.encode( buffer, syncUUID );
                            }
                        }

                        break;

                    default:
                        throw new IllegalArgumentException( "Unexpected SynchronizationInfo: " + getType() );
                }

                value = buffer.array();
            }
            catch ( EncoderException e )
            {
                return null;
            }
        }

        return value;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Asn1Object decode( byte[] controlBytes ) throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.wrap( controlBytes );
        SyncInfoValueContainer container = new SyncInfoValueContainer( getCodecService(), this );
        DECODER.decode( bb, container );
        return this;
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        return getDecorated().toString();
    }
}
