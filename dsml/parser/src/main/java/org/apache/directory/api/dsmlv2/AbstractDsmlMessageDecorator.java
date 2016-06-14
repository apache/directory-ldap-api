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
package org.apache.directory.api.dsmlv2;


import java.util.HashMap;
import java.util.Map;

import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;


/**
 * An abstract DSML Message decorator base class.
 *
 * @param <M> The message to decorate
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractDsmlMessageDecorator<M extends Message>
    implements DsmlDecorator<M>, Message
{
    /** The LDAP message codec */
    private final LdapApiService codec;

    /** The LDAP message */
    private final M message;

    /** Map of message controls using OID Strings for keys and Control values */
    private final Map<String, Control> controls;

    /** The current control */
    private DsmlControl<? extends Control> currentControl;


    /**
     * Create a new instance of AbstractDsmlMessageDecorator
     * 
     * @param codec The codec to use
     * @param message The message to decorate
     */
    public AbstractDsmlMessageDecorator( LdapApiService codec, M message )
    {
        this.codec = codec;
        this.message = message;
        controls = new HashMap<String, Control>();
    }


    /**
     * Get the current Control Object
     * 
     * @return The current Control Object
     */
    public DsmlControl<? extends Control> getCurrentControl()
    {
        return currentControl;
    }


    /**
     * @return The codec to use to encode or decode this message
     */
    public LdapApiService getCodecService()
    {
        return codec;
    }


    /**
     * {@inheritDoc}
     */
    public MessageTypeEnum getType()
    {
        return message.getType();
    }


    /**
     * {@inheritDoc}
     */
    public Map<String, Control> getControls()
    {
        return controls;
    }


    /**
     * {@inheritDoc}
     */
    public Control getControl( String oid )
    {
        return controls.get( oid );
    }


    /**
     * {@inheritDoc}
     */
    public boolean hasControl( String oid )
    {
        return controls.containsKey( oid );
    }


    /**
     * {@inheritDoc}
     */
    public Message addControl( Control control )
    {
        Control decorated;
        DsmlControl<? extends Control> decorator;

        if ( control instanceof DsmlControl )
        {
            decorator = ( DsmlControl<?> ) control;
            decorated = decorator.getDecorated();
        }
        else
        {
            decorator = new DsmlControl<Control>( codec, codec.newControl( control ) );
            decorated = control;
        }

        message.addControl( decorated );
        controls.put( control.getOid(), decorator );
        currentControl = decorator;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public Message addAllControls( Control[] controlsToAdd )
    {
        for ( Control control : controlsToAdd )
        {
            addControl( control );
        }

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public Message removeControl( Control control )
    {
        controls.remove( control.getOid() );
        message.removeControl( control );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public int getMessageId()
    {
        return message.getMessageId();
    }


    /**
     * {@inheritDoc}
     */
    public Object get( Object key )
    {
        return message.get( key );
    }


    /**
     * {@inheritDoc}
     */
    public Object put( Object key, Object value )
    {
        return message.put( key, value );
    }


    /**
     * {@inheritDoc}
     */
    public Message setMessageId( int messageId )
    {
        message.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public M getDecorated()
    {
        return message;
    }
}
