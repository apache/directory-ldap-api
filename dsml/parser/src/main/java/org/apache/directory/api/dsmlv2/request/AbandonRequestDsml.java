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
import org.apache.directory.api.ldap.model.message.AbandonRequest;
import org.apache.directory.api.ldap.model.message.AbandonRequestImpl;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.dom4j.Element;


/**
 * DSML Decorator for AbandonRequest
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AbandonRequestDsml extends AbstractRequestDsml<AbandonRequest>
    implements AbandonRequest
{
    /**
     * Creates a new instance of AbandonRequestDsml.
     * 
     * @param codec The LDAP Service to use
     */
    public AbandonRequestDsml( LdapApiService codec )
    {
        super( codec, new AbandonRequestImpl() );
    }


    /**
     * Creates a new instance of AbandonRequestDsml.
     *
     * @param codec The LDAP Service to use
     * @param ldapMessage the message to decorate
     */
    public AbandonRequestDsml( LdapApiService codec, AbandonRequest ldapMessage )
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

        // AbandonID
        if ( getDecorated().getAbandoned() != 0 )
        {
            element.addAttribute( "abandonID", Integer.toString( getDecorated().getAbandoned() ) );
        }

        return element;
    }


    /**
     * Get the abandoned message ID
     * 
     * @return Returns the abandoned MessageId.
     */
    public int getAbandonedMessageId()
    {
        return getDecorated().getAbandoned();
    }


    /**
     * Set the abandoned message ID
     * 
     * @param abandonedMessageId The abandoned messageID to set.
     * @return The modified AbandonRequest instance
     */
    public AbandonRequest setAbandonedMessageId( int abandonedMessageId )
    {
        getDecorated().setAbandoned( abandonedMessageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public int getAbandoned()
    {
        return getDecorated().getAbandoned();
    }


    /**
     * {@inheritDoc}
     */
    public AbandonRequest setAbandoned( int requestId )
    {
        getDecorated().setAbandoned( requestId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public AbandonRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public AbandonRequest addControl( Control control )
    {
        return ( AbandonRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    public AbandonRequest addAllControls( Control[] controls )
    {
        return ( AbandonRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    public AbandonRequest removeControl( Control control )
    {
        return ( AbandonRequest ) super.removeControl( control );
    }
}
