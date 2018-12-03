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
package org.apache.directory.api.ldap.extras.controls.ppolicy_impl;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.Asn1Object;
import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.ldap.codec.api.ControlDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyRequest;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyRequestImpl;


/**
 * PasswordPolicyRequest decorator.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordPolicyRequestDecorator extends ControlDecorator<PasswordPolicyRequest> implements PasswordPolicyRequest
{
    /**
     * Creates a new instance of PasswordPolicyRequestDecorator.
     * 
     * @param codec The LDAP Service to use
     */
    public PasswordPolicyRequestDecorator( LdapApiService codec )
    {
        super( codec, new PasswordPolicyRequestImpl() );
    }


    /**
     * Creates a new instance of PasswordPolicyRequestDecorator.
     * 
     * @param codec The LDAP Service to use
     * @param policy The asswordPolicy to use
     */
    public PasswordPolicyRequestDecorator( LdapApiService codec, PasswordPolicyRequest policy )
    {
        super( codec, policy );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setValue( byte[] value )
    {
        super.setValue( value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "  PasswordPolicyRequest control :\n" );
        sb.append( "   oid          : '" ).append( getOid() ).append( '\n' );


        return sb.toString();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Asn1Object decode( byte[] controlBytes ) throws DecoderException
    {
        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int computeLength()
    {
        return 0;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        return buffer;
    }
}
