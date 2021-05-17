/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.extras.controls.passwordExpired_impl;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.AbstractControlFactory;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.passwordExpired.PasswordExpiredResponse;
import org.apache.directory.api.ldap.extras.controls.passwordExpired.PasswordExpiredResponseImpl;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.util.Strings;

/**
 * A {@link ControlFactory} which creates {@link PasswordExpiredResponse} controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordExpiredResponseFactory extends AbstractControlFactory<PasswordExpiredResponse>
{
    /**
     * Creates a new instance of PasswordExpiredResponseFactory.
     *
     * @param codec The LDAP codec.
     */
    public PasswordExpiredResponseFactory( LdapApiService codec )
    {
        super( codec, PasswordExpiredResponse.OID );
    }
    

    /**
     * {@inheritDoc}
     */
    @Override
    public PasswordExpiredResponse newControl() 
    {
        return new PasswordExpiredResponseImpl();
    }
    

    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( Control control, byte[] controlBytes ) throws DecoderException 
    {
        try 
        {
            if ( !Strings.utf8ToString( controlBytes ).equals( "0" ) )
            {
                throw new DecoderException( I18n.err( I18n.ERR_08110_BAD_PASSWORD_EXPIRED_VALUE, Strings.dumpBytes( controlBytes ) ) );
            }
        }
        catch ( RuntimeException re ) 
        {
            throw new DecoderException( re.getMessage() );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, Control control )
    {
        // Always '0'
        buffer.put( ( byte ) 0x30 );
    }
}
