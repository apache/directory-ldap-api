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
package org.apache.directory.api.dsmlv2.request;


import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.dom4j.Element;


/**
 * DSML Decorator for BindRequest
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class BindRequestDsml
    extends AbstractResultResponseRequestDsml<BindRequest, BindResponse>
    implements BindRequest
{
    /**
     * Creates a new getDecoratedMessage() of AuthRequestDsml.
     * 
     * @param codec The LDAP Service to use
     */
    public BindRequestDsml( LdapApiService codec )
    {
        super( codec, new BindRequestImpl() );
    }


    /**
     * Creates a new getDecoratedMessage() of AuthRequestDsml.
     *
     * @param codec The LDAP Service to use
     * @param ldapMessage the message to decorate
     */
    public BindRequestDsml( LdapApiService codec, BindRequest ldapMessage )
    {
        super( codec, ldapMessage );
    }


    /**
     * {@inheritDoc}
     */
    public MessageTypeEnum getType()
    {
        return getDecorated().getType();
    }


    /**
     * {@inheritDoc}
     */
    public Element toDsml( Element root )
    {
        Element element = super.toDsml( root );

        BindRequest request = getDecorated();

        // Principal
        Dn dn = request.getDn();

        if ( !Dn.isNullOrEmpty( dn ) )
        {
            // A DN has been provided

            element.addAttribute( "principal", dn.getName() );
        }
        else
        {
            // No DN has been provided, let's use the name as a string instead

            String name = request.getName();

            element.addAttribute( "principal", name );
        }

        return element;
    }


    /**
     * {@inheritDoc}
     */
    public MessageTypeEnum getResponseType()
    {
        return getDecorated().getResponseType();
    }


    /**
     * {@inheritDoc}
     */
    public boolean isSimple()
    {
        return getDecorated().isSimple();
    }


    /**
     * {@inheritDoc}
     */
    public boolean getSimple()
    {
        return getDecorated().getSimple();
    }


    /**
     * {@inheritDoc}
     */
    public BindRequest setSimple( boolean isSimple )
    {
        getDecorated().setSimple( isSimple );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public byte[] getCredentials()
    {
        return getDecorated().getCredentials();
    }


    /**
     * {@inheritDoc}
     */
    public BindRequest setCredentials( String credentials )
    {
        getDecorated().setCredentials( credentials );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public BindRequest setCredentials( byte[] credentials )
    {
        getDecorated().setCredentials( credentials );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public String getName()
    {
        return getDecorated().getName();
    }


    /**
     * {@inheritDoc}
     */
    public BindRequest setName( String name )
    {
        getDecorated().setName( name );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public Dn getDn()
    {
        return getDecorated().getDn();
    }


    /**
     * {@inheritDoc}
     */
    public BindRequest setDn( Dn dn )
    {
        getDecorated().setDn( dn );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public boolean isVersion3()
    {
        return getDecorated().isVersion3();
    }


    /**
     * {@inheritDoc}
     */
    public boolean getVersion3()
    {
        return getDecorated().getVersion3();
    }


    /**
     * {@inheritDoc}
     */
    public BindRequest setVersion3( boolean isVersion3 )
    {
        getDecorated().setVersion3( isVersion3 );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public String getSaslMechanism()
    {
        return getDecorated().getSaslMechanism();
    }


    /**
     * {@inheritDoc}
     */
    public BindRequest setSaslMechanism( String saslMechanism )
    {
        getDecorated().setSaslMechanism( saslMechanism );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public BindRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public BindRequest addControl( Control control )
    {
        return ( BindRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    public BindRequest addAllControls( Control[] controls )
    {
        return ( BindRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    public BindRequest removeControl( Control control )
    {
        return ( BindRequest ) super.removeControl( control );
    }
}
