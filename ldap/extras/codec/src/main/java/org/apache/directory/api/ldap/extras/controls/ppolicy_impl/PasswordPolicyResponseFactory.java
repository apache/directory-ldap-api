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
package org.apache.directory.api.ldap.extras.controls.ppolicy_impl;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractControlFactory;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyResponse;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyResponseImpl;
import org.apache.directory.api.ldap.model.message.Control;


/**
 * A {@link ControlFactory} which creates {@link PasswordPolicyResponse} controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class PasswordPolicyResponseFactory extends AbstractControlFactory<PasswordPolicyResponse>
{
    /**
     * Creates a new instance of PasswordPolicyResponseFactory.
     *
     * @param codec The LDAP Service to use
     */
    public PasswordPolicyResponseFactory( LdapApiService codec )
    {
        super( codec, PasswordPolicyResponse.OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PasswordPolicyResponse newControl()
    {
        return new PasswordPolicyResponseImpl();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, Control control )
    {
        int start = buffer.getPos();
        PasswordPolicyResponse ppResponse = ( PasswordPolicyResponse ) control;
        
        if ( ( ppResponse.getTimeBeforeExpiration() >= 0 ) || ( ppResponse.getGraceAuthNRemaining() >= 0 ) 
            || ( ppResponse.getPasswordPolicyError() != null ) )
        {
            if ( ppResponse.getPasswordPolicyError() != null )
            {
                BerValue.encodeEnumerated( 
                    buffer,
                    ( byte ) PasswordPolicyTags.PPOLICY_ERROR_TAG.getValue(),
                    ppResponse.getPasswordPolicyError().getValue() );
            }

            boolean warning = false;
            int startWarning = buffer.getPos();

            if ( ppResponse.getGraceAuthNRemaining() >= 0 )
            {
                BerValue.encodeInteger( buffer, 
                    ( byte ) PasswordPolicyTags.GRACE_AUTHNS_REMAINING_TAG.getValue(),
                    ppResponse.getGraceAuthNRemaining() );
                
                warning = true;
            }
            else if ( ppResponse.getTimeBeforeExpiration() >= 0 )
            {
                BerValue.encodeInteger( buffer, 
                    ( byte ) PasswordPolicyTags.TIME_BEFORE_EXPIRATION_TAG.getValue(),
                    ppResponse.getTimeBeforeExpiration() );
                
                warning = true;
            }
            
            if ( warning )
            {
                BerValue.encodeSequence( buffer, 
                    ( byte ) PasswordPolicyTags.PPOLICY_WARNING_TAG.getValue(), startWarning );
            }
        }
        
        // The sequence
        BerValue.encodeSequence( buffer, start );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( Control control, byte[] controlBytes ) throws DecoderException
    {
        decodeValue( new PasswordPolicyResponseContainer( control ), control, controlBytes );
    }
}
