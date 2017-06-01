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
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;


/**
 * A decorator for the BindRequest message
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class BindRequestDecorator extends SingleReplyRequestDecorator<BindRequest> implements BindRequest
{
    /** The bind request length */
    private int bindRequestLength;

    /** The SASL Mechanism length */
    private int saslMechanismLength;

    /** The SASL credentials length */
    private int saslCredentialsLength;

    /** The bytes containing the Dn */
    private byte[] dnBytes;

    /** The bytes containing the Name */
    private byte[] nameBytes;

    /** The bytes containing the SaslMechanism */
    private byte[] mechanismBytes;


    /**
     * Makes a BindRequest a MessageDecorator.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage the decorated BindRequests.
     */
    public BindRequestDecorator( LdapApiService codec, BindRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest addControl( Control control )
    {
        return ( BindRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest addAllControls( Control[] controls )
    {
        return ( BindRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest removeControl( Control control )
    {
        return ( BindRequest ) super.removeControl( control );
    }


    //-------------------------------------------------------------------------
    // The BindRequest methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isSimple()
    {
        return getDecorated().isSimple();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getSimple()
    {
        return getDecorated().getSimple();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setSimple( boolean isSimple )
    {
        getDecorated().setSimple( isSimple );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getCredentials()
    {
        return getDecorated().getCredentials();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setCredentials( String credentials )
    {
        getDecorated().setCredentials( credentials );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setCredentials( byte[] credentials )
    {
        getDecorated().setCredentials( credentials );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getName()
    {
        return getDecorated().getName();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setName( String name )
    {
        getDecorated().setName( name );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getDn()
    {
        return getDecorated().getDn();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setDn( Dn dn )
    {
        getDecorated().setDn( dn );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isVersion3()
    {
        return getDecorated().isVersion3();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getVersion3()
    {
        return getDecorated().getVersion3();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setVersion3( boolean isVersion3 )
    {
        getDecorated().setVersion3( isVersion3 );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getSaslMechanism()
    {
        return getDecorated().getSaslMechanism();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setSaslMechanism( String saslMechanism )
    {
        getDecorated().setSaslMechanism( saslMechanism );

        return this;
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------
    /**
     * Compute the BindRequest length
     * <br>
     * BindRequest :
     * <pre>
     * 0x60 L1
     *   |
     *   +--&gt; 0x02 0x01 (1..127) version
     *   +--&gt; 0x04 L2 name
     *   +--&gt; authentication
     * 
     * L2 = Length(name)
     * L3/4 = Length(authentication)
     * Length(BindRequest) = Length(0x60) + Length(L1) + L1 + Length(0x02) + 1 + 1 +
     *      Length(0x04) + Length(L2) + L2 + Length(authentication)
     * </pre>
     */
    @Override
    public int computeLength()
    {
        // Initialized with version
        bindRequestLength = 1 + 1 + 1;

        Dn dn = getDn();

        if ( !Dn.isNullOrEmpty( dn ) )
        {
            // A DN has been provided
            dnBytes = Strings.getBytesUtf8( dn.getName() );
            int dnLength = dnBytes.length;

            bindRequestLength += 1 + TLV.getNbBytes( dnLength ) + dnLength;
        }
        else
        {
            // No DN has been provided, let's use the name as a string instead
            String name = getName();

            if ( Strings.isEmpty( name ) )
            {
                name = "";
            }

            nameBytes = Strings.getBytesUtf8( name );

            bindRequestLength += 1 + TLV.getNbBytes( nameBytes.length ) + nameBytes.length;
        }

        byte[] credentials = getCredentials();

        // The authentication
        if ( isSimple() )
        {
            // Compute a SimpleBind operation
            if ( credentials != null )
            {
                bindRequestLength += 1 + TLV.getNbBytes( credentials.length ) + credentials.length;
            }
            else
            {
                bindRequestLength += 1 + 1;
            }
        }
        else
        {
            mechanismBytes = Strings.getBytesUtf8( getSaslMechanism() );
            saslMechanismLength = 1 + TLV.getNbBytes( mechanismBytes.length ) + mechanismBytes.length;

            if ( credentials != null )
            {
                saslCredentialsLength = 1 + TLV.getNbBytes( credentials.length ) + credentials.length;
            }

            int saslLength = 1 + TLV.getNbBytes( saslMechanismLength + saslCredentialsLength ) + saslMechanismLength
                + saslCredentialsLength;

            bindRequestLength += saslLength;
        }

        // Return the result.
        return 1 + TLV.getNbBytes( bindRequestLength ) + bindRequestLength;
    }


    /**
     * Encode the BindRequest message to a PDU.
     * <br>
     * BindRequest :
     * <pre>
     * 0x60 LL
     *   0x02 LL version         0x80 LL simple
     *   0x04 LL name           /
     *   authentication.encode()
     *                          \ 0x83 LL mechanism [0x04 LL credential]
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
            // The BindRequest Tag
            buffer.put( LdapCodecConstants.BIND_REQUEST_TAG );
            buffer.put( TLV.getBytes( bindRequestLength ) );

        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04005 ), boe );
        }

        // The version (LDAP V3 only)
        BerValue.encode( buffer, 3 );

        Dn dn = getDn();

        if ( !Dn.isNullOrEmpty( dn ) )
        {
            // A DN has been provided
            BerValue.encode( buffer, dnBytes );
        }
        else
        {
            // No DN has been provided, let's use the name as a string instead
            BerValue.encode( buffer, nameBytes );
        }

        byte[] credentials = getCredentials();

        // The authentication
        if ( isSimple() )
        {
            // Simple authentication
            try
            {
                // The simpleAuthentication Tag
                buffer.put( ( byte ) LdapCodecConstants.BIND_REQUEST_SIMPLE_TAG );

                if ( credentials != null )
                {
                    buffer.put( TLV.getBytes( credentials.length ) );

                    if ( credentials.length != 0 )
                    {
                        buffer.put( credentials );
                    }
                }
                else
                {
                    buffer.put( ( byte ) 0 );
                }
            }
            catch ( BufferOverflowException boe )
            {
                String msg = I18n.err( I18n.ERR_04005 );
                throw new EncoderException( msg, boe );
            }
        }
        else
        {
            // SASL Bind
            try
            {
                // The saslAuthentication Tag
                buffer.put( ( byte ) LdapCodecConstants.BIND_REQUEST_SASL_TAG );

                buffer.put( TLV
                    .getBytes( saslMechanismLength + saslCredentialsLength ) );

                BerValue.encode( buffer, mechanismBytes );

                if ( credentials != null )
                {
                    BerValue.encode( buffer, credentials );
                }
            }
            catch ( BufferOverflowException boe )
            {
                String msg = I18n.err( I18n.ERR_04005 );
                throw new EncoderException( msg, boe );
            }
        }

        return buffer;
    }
}
