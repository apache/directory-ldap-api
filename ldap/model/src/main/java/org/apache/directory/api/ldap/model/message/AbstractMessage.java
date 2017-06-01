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
package org.apache.directory.api.ldap.model.message;


import java.util.Collections;
import java.util.HashMap;
import java.util.Map;


/**
 * Abstract message base class.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractMessage implements Message
{
    /** Map of message controls using OID Strings for keys and Control values */
    protected final Map<String, Control> controls;

    /** The session unique message sequence identifier */
    private int id;

    /** The message type enumeration */
    private final MessageTypeEnum type;

    /** Transient Message Parameter Hash */
    private final Map<Object, Object> parameters;


    /**
     * Completes the instantiation of a Message.
     * 
     * @param id the seq id of the message
     * @param type the type of the message
     */
    protected AbstractMessage( final int id, final MessageTypeEnum type )
    {
        this.id = id;
        this.type = type;
        controls = new HashMap<>();
        parameters = new HashMap<>();
    }


    /**
     * Gets the session unique message sequence id for this message. Requests
     * and their responses if any have the same message id. Clients at the
     * initialization of a session start with the first message's id set to 1
     * and increment it with each transaction.
     * 
     * @return the session unique message id.
     */
    @Override
    public int getMessageId()
    {
        return id;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Message setMessageId( int id )
    {
        this.id = id;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, Control> getControls()
    {
        return Collections.unmodifiableMap( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Control getControl( String oid )
    {
        return controls.get( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasControl( String oid )
    {
        return controls.containsKey( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Message addControl( Control control )
    {
        controls.put( control.getOid(), control );

        return this;
    }


    /**
     * Deletes a control removing it from this Message.
     * 
     * @param control the control to remove.
     */
    @Override
    public Message removeControl( Control control )
    {
        controls.remove( control.getOid() );

        return this;
    }


    /**
     * Gets the LDAP message type code associated with this Message. Each
     * request and response type has a unique message type code defined by the
     * protocol in <a href="http://www.faqs.org/rfcs/rfc2251.html">RFC 2251</a>.
     * 
     * @return the message type code.
     */
    @Override
    public MessageTypeEnum getType()
    {
        return type;
    }


    /**
     * Gets a message scope parameter. Message scope parameters are temporary
     * variables associated with a message and are set locally to be used to
     * associate housekeeping information with a request or its processing.
     * These parameters are never transmitted nor received, think of them as
     * transient data associated with the message or its processing. These
     * transient parameters are not locked down so modifications can occur
     * without firing LockExceptions even when this Lockable is in the locked
     * state.
     * 
     * @param key the key used to access a message parameter.
     * @return the transient message parameter value.
     */
    @Override
    public Object get( Object key )
    {
        return parameters.get( key );
    }


    /**
     * Sets a message scope parameter. These transient parameters are not locked
     * down so modifications can occur without firing LockExceptions even when
     * this Lockable is in the locked state.
     * 
     * @param key the parameter key
     * @param value the parameter value
     * @return the old value or null
     */
    @Override
    public Object put( Object key, Object value )
    {
        return parameters.put( key, value );
    }


    /**
     * Checks to see if two messages are equivalent. Messages equivalence does
     * not factor in parameters accessible through the get() and put()
     * operations, nor do they factor in the Lockable properties of the Message.
     * Only the type, controls, and the messageId are evaluated for equality.
     * 
     * @param obj the object to compare this Message to for equality
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( obj == this )
        {
            return true;
        }

        if ( ( obj == null ) || !( obj instanceof Message ) )
        {
            return false;
        }

        Message msg = ( Message ) obj;

        if ( msg.getMessageId() != id )
        {
            return false;
        }

        if ( msg.getType() != type )
        {
            return false;
        }

        Map<String, Control> controlMap = msg.getControls();

        if ( controlMap.size() != controls.size() )
        {
            return false;
        }

        for ( String key : controls.keySet() )
        {
            if ( !controlMap.containsKey( key ) )
            {
                return false;
            }
        }

        return true;
    }


    /**
     * @see Object#hashCode()
     * @return the instance's hash code 
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        hash = hash * 17 + id;
        hash = hash * 17 + ( type == null ? 0 : type.hashCode() );
        hash = hash * 17 + ( parameters == null ? 0 : parameters.hashCode() );
        hash = hash * 17 + ( controls == null ? 0 : controls.hashCode() );

        return hash;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Message addAllControls( Control[] controls )
    {
        for ( Control c : controls )
        {
            this.controls.put( c.getOid(), c );
        }

        return this;
    }


    /**
     * Get a String representation of a LdapMessage
     * 
     * @param message The message to print
     * @return A LdapMessage String
     */
    public String toString( String message )
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "MessageType : " ).append( type ).append( '\n' );
        sb.append( "Message ID : " ).append( id ).append( '\n' );

        sb.append( message );

        if ( controls != null )
        {
            for ( Control control : controls.values() )
            {
                sb.append( control );
            }
        }

        return sb.toString();
    }
}
