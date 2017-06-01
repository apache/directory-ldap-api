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
package org.apache.directory.api.ldap.codec.decorators;


import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ModifyDnRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.util.Strings;


/**
 * A decorator for the ModifyDnRequest message
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ModifyDnRequestDecorator extends SingleReplyRequestDecorator<ModifyDnRequest>
    implements ModifyDnRequest
{
    /** The modify Dn request length */
    private int modifyDnRequestLength;


    /**
     * Makes a ModifyDnRequest encodable.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage the decorated ModifyDnRequest
     */
    public ModifyDnRequestDecorator( LdapApiService codec, ModifyDnRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
    }


    //-------------------------------------------------------------------------
    // The ModifyDnResponse methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getName()
    {
        return getDecorated().getName();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest setName( Dn name )
    {
        getDecorated().setName( name );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Rdn getNewRdn()
    {
        return getDecorated().getNewRdn();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest setNewRdn( Rdn newRdn )
    {
        getDecorated().setNewRdn( newRdn );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getDeleteOldRdn()
    {
        return getDecorated().getDeleteOldRdn();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest setDeleteOldRdn( boolean deleteOldRdn )
    {
        getDecorated().setDeleteOldRdn( deleteOldRdn );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getNewSuperior()
    {
        return getDecorated().getNewSuperior();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest setNewSuperior( Dn newSuperior )
    {
        getDecorated().setNewSuperior( newSuperior );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isMove()
    {
        return getDecorated().isMove();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest addControl( Control control )
    {
        return ( ModifyDnRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest addAllControls( Control[] controls )
    {
        return ( ModifyDnRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest removeControl( Control control )
    {
        return ( ModifyDnRequest ) super.removeControl( control );
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------

    /**
     * Compute the ModifyDNRequest length
     * <br>
     * ModifyDNRequest :
     * <pre>
     * 0x6C L1
     *  |
     *  +--&gt; 0x04 L2 entry
     *  +--&gt; 0x04 L3 newRDN
     *  +--&gt; 0x01 0x01 (true/false) deleteOldRDN (3 bytes)
     * [+--&gt; 0x80 L4 newSuperior ] 
     * 
     * L2 = Length(0x04) + Length(Length(entry)) + Length(entry) 
     * L3 = Length(0x04) + Length(Length(newRDN)) + Length(newRDN) 
     * L4 = Length(0x80) + Length(Length(newSuperior)) + Length(newSuperior)
     * L1 = L2 + L3 + 3 [+ L4] 
     * 
     * Length(ModifyDNRequest) = Length(0x6C) + Length(L1) + L1
     * </pre>
     * 
     * @return The PDU's length of a ModifyDN Request
     */
    @Override
    public int computeLength()
    {
        int newRdnlength = Strings.getBytesUtf8( getNewRdn().getName() ).length;

        // deleteOldRDN
        modifyDnRequestLength = 1 + TLV.getNbBytes( Dn.getNbBytes( getName() ) )
            + Dn.getNbBytes( getName() ) + 1 + TLV.getNbBytes( newRdnlength ) + newRdnlength + 1 + 1
            + 1;

        if ( getNewSuperior() != null )
        {
            modifyDnRequestLength += 1 + TLV.getNbBytes( Dn.getNbBytes( getNewSuperior() ) )
                + Dn.getNbBytes( getNewSuperior() );
        }

        return 1 + TLV.getNbBytes( modifyDnRequestLength ) + modifyDnRequestLength;
    }


    /**
     * Encode the ModifyDNRequest message to a PDU. 
     * <br>
     * ModifyDNRequest :
     * <pre>
     * 0x6C LL
     *   0x04 LL entry
     *   0x04 LL newRDN
     *   0x01 0x01 deleteOldRDN
     *   [0x80 LL newSuperior]
     * </pre>
     * 
     * @param buffer The buffer where to put the PDU
     * @return The PDU.
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        try
        {
            // The ModifyDNRequest Tag
            buffer.put( LdapCodecConstants.MODIFY_DN_REQUEST_TAG );
            buffer.put( TLV.getBytes( modifyDnRequestLength ) );

            // The entry

            BerValue.encode( buffer, Dn.getBytes( getName() ) );

            // The newRDN
            BerValue.encode( buffer, getNewRdn().getName() );

            // The flag deleteOldRdn
            BerValue.encode( buffer, getDeleteOldRdn() );

            // The new superior, if any
            if ( getNewSuperior() != null )
            {
                // Encode the reference
                buffer.put( ( byte ) LdapCodecConstants.MODIFY_DN_REQUEST_NEW_SUPERIOR_TAG );

                int newSuperiorLength = Dn.getNbBytes( getNewSuperior() );

                buffer.put( TLV.getBytes( newSuperiorLength ) );

                if ( newSuperiorLength != 0 )
                {
                    buffer.put( Dn.getBytes( getNewSuperior() ) );
                }
            }
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04005 ), boe );
        }

        return buffer;
    }
}
