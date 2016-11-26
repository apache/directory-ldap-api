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
package org.apache.directory.api.ldap.codec.controls.proxiedauthz;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.Asn1Object;
import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ControlDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.controls.ProxiedAuthz;
import org.apache.directory.api.ldap.model.message.controls.ProxiedAuthzImpl;
import org.apache.directory.api.util.Strings;


/**
 * An ProxiedAuthz implementation, that wraps and decorates the Control with codec
 * specific functionality.
 *
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ProxiedAuthzDecorator extends ControlDecorator<ProxiedAuthz> implements ProxiedAuthz
{
    /** A temporary storage for the authzId */
    private byte[] authzIdBytes = null;


    /**
     * Creates a new instance of ProxiedAuthzDecoder wrapping a newly created
     * ProxiedAuthz Control object.
     * 
     * @param codec The LDAP service instance
     */
    public ProxiedAuthzDecorator( LdapApiService codec )
    {
        super( codec, new ProxiedAuthzImpl() );
    }


    /**
     * Creates a new instance of ProxiedAuthzDecorator wrapping the supplied
     * ProxiedAuthz Control.
     *
     * @param codec The LDAP service instance
     * @param control The ProxiedAuthz Control to be decorated.
     */
    public ProxiedAuthzDecorator( LdapApiService codec, ProxiedAuthz control )
    {
        super( codec, control );
    }


    /**
     * Internally used to not have to cast the decorated Control.
     *
     * @return the decorated Control.
     */
    private ProxiedAuthz getProxiedAuthz()
    {
        return getDecorated();
    }


    /**
     * Compute the ProxiedAuthzControl length 
     * <pre>
     *  0x04 L1 authzId]
     * </pre>
     *  
     * @return the control length.
     */
    @Override
    public int computeLength()
    {
        int valueLength = 0;

        if ( getAuthzId() != null )
        {
            authzIdBytes = Strings.getBytesUtf8( getAuthzId() );
            valueLength = authzIdBytes.length;
        }

        return valueLength;
    }


    /**
     * Encodes the ProxiedAuthz control.
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

        if ( getAuthzId() != null )
        {
            buffer.put( authzIdBytes );
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

                if ( authzIdBytes != null )
                {
                    BerValue.encode( buffer, authzIdBytes );
                }
                else
                {
                    BerValue.encode( buffer, Strings.EMPTY_BYTES );
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
    @Override
    public String getAuthzId()
    {
        return getProxiedAuthz().getAuthzId();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setAuthzId( String authzId )
    {
        getProxiedAuthz().setAuthzId( authzId );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Asn1Object decode( byte[] controlBytes ) throws DecoderException
    {
        getProxiedAuthz().setAuthzId( Strings.utf8ToString( controlBytes ) );

        return this;
    }
}
