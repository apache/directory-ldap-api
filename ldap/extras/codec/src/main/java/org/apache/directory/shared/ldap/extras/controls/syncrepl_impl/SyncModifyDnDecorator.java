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
package org.apache.directory.shared.ldap.extras.controls.syncrepl_impl;


import java.nio.ByteBuffer;

import org.apache.directory.shared.asn1.Asn1Object;
import org.apache.directory.shared.asn1.DecoderException;
import org.apache.directory.shared.asn1.EncoderException;
import org.apache.directory.shared.asn1.ber.Asn1Decoder;
import org.apache.directory.shared.asn1.ber.tlv.TLV;
import org.apache.directory.shared.asn1.ber.tlv.UniversalTag;
import org.apache.directory.shared.asn1.ber.tlv.Value;
import org.apache.directory.shared.asn1.util.Asn1StringUtils;
import org.apache.directory.shared.i18n.I18n;
import org.apache.directory.shared.ldap.codec.api.LdapApiService;
import org.apache.directory.shared.ldap.codec.api.ControlDecorator;
import org.apache.directory.shared.ldap.extras.controls.SyncModifyDn;
import org.apache.directory.shared.ldap.extras.controls.SyncModifyDnImpl;
import org.apache.directory.shared.ldap.extras.controls.SyncModifyDnType;


/**
 * A SyncModifyDnControl object, to send the parameters used in a MODIFYDN operation
 * that was carried out on a syncrepl provider server.
 *
 * The consumer will use the values present in this control to perform the same operation
 * on its local data, which helps in avoiding huge number of updates to the consumer.
 *
 * NOTE: syncrepl, defined in RFC 4533, doesn't mention about this approach, this is a special
 *       extension provided by Apache Directory Server
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SyncModifyDnDecorator extends ControlDecorator<SyncModifyDn> implements SyncModifyDn
{
    /** global length for the control */
    private int syncModDnSeqLength;

    private int renameLen = 0;
    private int moveAndRenameLen = 0;

    /** An instance of this decoder */
    private Asn1Decoder decoder = new Asn1Decoder();


    public SyncModifyDnDecorator( LdapApiService codec )
    {
        super( codec, new SyncModifyDnImpl() );
    }


    public SyncModifyDnDecorator( LdapApiService codec, SyncModifyDnType type )
    {
        this( codec );
        getDecorated().setModDnType( type );
    }


    public SyncModifyDnDecorator( LdapApiService codec, SyncModifyDn control )
    {
        super( codec, control );
    }


    /**
     * Compute the SyncStateValue length.
     *
     * SyncStateValue :
     * 0x30 L1
     *  |
     *  +--> 0x04 L2 uid=jim...       (entryDn)
     * [+--> 0x04 L3 ou=system...     (newSuperior)
     * [+--> 0x04 L4 uid=jack...      (newRdn)
     * [+--> 0x04 0x01 [0x00|0x01]... (deleteOldRdn)
     *
     */
    @Override
    public int computeLength()
    {
        String entryDn = getDecorated().getEntryDn();
        String newSuperiorDn = getDecorated().getNewSuperiorDn();
        String newRdn = getDecorated().getNewRdn();
        
        syncModDnSeqLength = 1 + TLV.getNbBytes( entryDn.length() ) + entryDn.length();

        switch ( getDecorated().getModDnType() )
        {
            case MOVE:
                int moveLen = 1 + TLV.getNbBytes( newSuperiorDn.length() ) + newSuperiorDn.length();
                syncModDnSeqLength += moveLen; //1 + TLV.getNbBytes( moveLen ) + moveLen;
                break;

            case RENAME:
                renameLen = 1 + TLV.getNbBytes( newRdn.length() ) + newRdn.length();

                // deleteOldRdn
                renameLen += 1 + 1 + 1;

                syncModDnSeqLength += 1 + TLV.getNbBytes( renameLen ) + renameLen;
                break;

            case MOVEANDRENAME:
                moveAndRenameLen = 1 + TLV.getNbBytes( newSuperiorDn.length() ) + newSuperiorDn.length();
                moveAndRenameLen += 1 + TLV.getNbBytes( newRdn.length() ) + newRdn.length();
                // deleteOldRdn
                moveAndRenameLen += 1 + 1 + 1;

                syncModDnSeqLength += 1 + TLV.getNbBytes( moveAndRenameLen ) + moveAndRenameLen;
                break;
        }

        valueLength = 1 + TLV.getNbBytes( syncModDnSeqLength ) + syncModDnSeqLength;

        return valueLength;
    }


    /**
     * Encode the SyncStateValue control
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

        // Encode the SEQ
        buffer.put( UniversalTag.SEQUENCE.getValue() );
        buffer.put( TLV.getBytes( syncModDnSeqLength ) );

        String entryDn = getDecorated().getEntryDn();
        String newSuperiorDn = getDecorated().getNewSuperiorDn();
        String newRdn = getDecorated().getNewRdn();
        
        // the entryDn
        Value.encode( buffer, entryDn );

        switch ( getDecorated().getModDnType() )
        {
            case MOVE:
                buffer.put( ( byte ) SyncModifyDnTags.MOVE_TAG.getValue() );
                buffer.put( TLV.getBytes( newSuperiorDn.length() ) );
                buffer.put( Asn1StringUtils.getBytesUtf8( newSuperiorDn ) );
                break;

            case RENAME:
                buffer.put( ( byte ) SyncModifyDnTags.RENAME_TAG.getValue() );
                buffer.put( TLV.getBytes( renameLen ) );
                Value.encode( buffer, newRdn );
                Value.encode( buffer, getDecorated().isDeleteOldRdn() );
                break;

            case MOVEANDRENAME:
                buffer.put( ( byte ) SyncModifyDnTags.MOVEANDRENAME_TAG.getValue() );
                buffer.put( TLV.getBytes( moveAndRenameLen ) );
                Value.encode( buffer, newSuperiorDn );
                Value.encode( buffer, newRdn );
                Value.encode( buffer, getDecorated().isDeleteOldRdn() );
                break;
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

                // Encode the SEQ
                buffer.put( UniversalTag.SEQUENCE.getValue() );
                buffer.put( TLV.getBytes( syncModDnSeqLength ) );

                String entryDn = getDecorated().getEntryDn();
                String newSuperiorDn = getDecorated().getNewSuperiorDn();
                String newRdn = getDecorated().getNewRdn();
                
                // the entryDn
                Value.encode( buffer, entryDn );

                switch ( getDecorated().getModDnType() )
                {
                    case MOVE:
                        buffer.put( ( byte ) SyncModifyDnTags.MOVE_TAG.getValue() );
                        buffer.put( TLV.getBytes( newSuperiorDn.length() ) );
                        buffer.put( Asn1StringUtils.getBytesUtf8( newSuperiorDn ) );
                        break;

                    case RENAME:
                        buffer.put( ( byte ) SyncModifyDnTags.RENAME_TAG.getValue() );
                        buffer.put( TLV.getBytes( renameLen ) );
                        Value.encode( buffer, newRdn );
                        Value.encode( buffer, getDecorated().isDeleteOldRdn() );
                        break;

                    case MOVEANDRENAME:
                        buffer.put( ( byte ) SyncModifyDnTags.MOVEANDRENAME_TAG.getValue() );
                        buffer.put( TLV.getBytes( moveAndRenameLen ) );
                        Value.encode( buffer, newSuperiorDn );
                        Value.encode( buffer, newRdn );
                        Value.encode( buffer, getDecorated().isDeleteOldRdn() );
                        break;
                }

                value = buffer.array();
            }
            catch ( Exception e )
            {
                return null;
            }
        }

        return value;
    }


    /**
     * {@inheritDoc}
     */
    public String getEntryDn()
    {
        return getDecorated().getEntryDn();
    }


    /**
     * {@inheritDoc}
     */
    public void setEntryDn( String entryDn )
    {
        getDecorated().setEntryDn( entryDn );
    }


    /**
     * {@inheritDoc}
     */
    public String getNewSuperiorDn()
    {
        return getDecorated().getNewSuperiorDn();
    }


    /**
     * {@inheritDoc}
     */
    public void setNewSuperiorDn( String newSuperiorDn )
    {
        getDecorated().setNewSuperiorDn( newSuperiorDn );
    }


    /**
     * {@inheritDoc}
     */
    public String getNewRdn()
    {
        return getDecorated().getNewRdn();
    }


    /**
     * {@inheritDoc}
     */
    public void setNewRdn( String newRdn )
    {
        getDecorated().setNewRdn( newRdn );
    }


    /**
     * {@inheritDoc}
     */
    public boolean isDeleteOldRdn()
    {
        return getDecorated().isDeleteOldRdn();
    }


    /**
     * {@inheritDoc}
     */
    public void setDeleteOldRdn( boolean deleteOldRdn )
    {
        getDecorated().setDeleteOldRdn( deleteOldRdn );
    }


    /**
     * {@inheritDoc}
     */
    public SyncModifyDnType getModDnType()
    {
        return getDecorated().getModDnType();
    }


    /**
     * {@inheritDoc}
     */
    public void setModDnType( SyncModifyDnType modDnType )
    {
        if( getDecorated().getModDnType() != null )
        {
            throw new IllegalStateException( "cannot overwrite the existing modDnType value" );
        }
        getDecorated().setModDnType( modDnType );
    }


    /**
     * {@inheritDoc}
     */
    public Asn1Object decode( byte[] controlBytes ) throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.wrap( controlBytes );
        SyncModifyDnContainer container = new SyncModifyDnContainer( this );
        decoder.decode( bb, container );
        return this;
    }
}
