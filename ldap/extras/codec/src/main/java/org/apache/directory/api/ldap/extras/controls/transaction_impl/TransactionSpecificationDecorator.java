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
package org.apache.directory.api.ldap.extras.controls.transaction_impl;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.Asn1Object;
import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.ldap.codec.api.ControlDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.transaction.TransactionSpecification;

/**
 * TransactionSpecification decorator.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class TransactionSpecificationDecorator extends ControlDecorator<TransactionSpecification> implements TransactionSpecification
{
    /**
     * Create a new instance of TransactionSpecificationDecorator
     * 
     * @param codec  The LDAP Service to use
     * @param decoratedControl The control to decorate
     */
    public TransactionSpecificationDecorator( LdapApiService codec, TransactionSpecification decoratedControl )
    {
        super( codec, decoratedControl );
    }
    

    /**
     * {@inheritDoc}
     */
    @Override
    public Asn1Object decode( byte[] controlBytes ) throws DecoderException
    {
        // Nothing to decode, the byte array is copied as is in identifier
        setIdentifier( controlBytes );
        
        return this;
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public int computeLength()
    {
        byte[] identifier = getDecorated().getIdentifier();
        
        if ( identifier != null )
        {
            return identifier.length;
        }
        else
        {
            return -1;
        }
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        byte[] identifier = getDecorated().getIdentifier();
        
        if ( identifier != null )
        {
            ByteBuffer encoded = ByteBuffer.allocate( identifier.length );
            
            encoded.put( identifier );
            
            return encoded;
        }
        else
        {
            return ByteBuffer.allocate( 0 );
        }
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getIdentifier()
    {
        return getDecorated().getIdentifier();
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public void setIdentifier( byte[] identifier )
    {
        getDecorated().setIdentifier( identifier );
    }
}
