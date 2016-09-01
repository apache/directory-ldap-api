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
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteRequestImpl;
import org.apache.directory.api.ldap.model.message.DeleteResponse;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.dom4j.Element;


/**
 * DSML Decorator for DeleteRequest
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DelRequestDsml
    extends AbstractResultResponseRequestDsml<DeleteRequest, DeleteResponse>
    implements DeleteRequest
{
    /**
     * Creates a new getDecoratedMessage() of DelRequestDsml.
     * 
     * @param codec The LDAP Service to use
     */
    public DelRequestDsml( LdapApiService codec )
    {
        super( codec, new DeleteRequestImpl() );
    }


    /**
     * Creates a new getDecoratedMessage() of DelRequestDsml.
     *
     * @param codec The LDAP Service to use
     * @param ldapMessage the message to decorate
     */
    public DelRequestDsml( LdapApiService codec, DeleteRequest ldapMessage )
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

        // Dn
        if ( getDecorated().getName() != null )
        {
            element.addAttribute( "dn", getDecorated().getName().getName() );
        }

        return element;
    }


    /**
     * Get the entry to be deleted
     * 
     * @return Returns the entry.
     */
    public Dn getEntry()
    {
        return getDecorated().getName();
    }


    /**
     * Set the entry to be deleted
     * 
     * @param entry The entry to set.
     */
    public void setEntry( Dn entry )
    {
        getDecorated().setName( entry );
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
    public Dn getName()
    {
        return getDecorated().getName();
    }


    /**
     * {@inheritDoc}
     */
    public DeleteRequest setName( Dn name )
    {
        getDecorated().setName( name );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public DeleteRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public DeleteRequest addControl( Control control )
    {
        return ( DeleteRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    public DeleteRequest addAllControls( Control[] controls )
    {
        return ( DeleteRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    public DeleteRequest removeControl( Control control )
    {
        return ( DeleteRequest ) super.removeControl( control );
    }
}
