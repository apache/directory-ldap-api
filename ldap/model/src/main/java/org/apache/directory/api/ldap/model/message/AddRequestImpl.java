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


import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;


/**
 * Lockable add request implementation.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AddRequestImpl extends AbstractAbandonableRequest implements AddRequest
{
    static final long serialVersionUID = 7534132448349520346L;

    /** A MultiMap of the new entry's attributes and their values */
    private Entry entry;

    private AddResponse response;

    /** The current attribute being decoded */
    private Attribute currentAttribute;


    // ------------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------------

    /**
     * Creates an AddRequest implementation to create a new entry.
     */
    public AddRequestImpl()
    {
        super( -1, MessageTypeEnum.ADD_REQUEST );
        entry = new DefaultEntry();
    }


    /**
     * Create a new attributeValue
     * 
     * @param type The attribute's name (called 'type' in the grammar)
     * @throws LdapException If the type can't be added
     */
    public void addAttributeType( String type ) throws LdapException
    {
        // do not create a new attribute if we have seen this attributeType before
        if ( entry.get( type ) != null )
        {
            currentAttribute = entry.get( type );
            return;
        }

        // fix this to use AttributeImpl(type.getString().toLowerCase())
        currentAttribute = new DefaultAttribute( type );
        entry.put( currentAttribute );
    }


    /**
     * @return Returns the currentAttribute type.
     */
    public String getCurrentAttributeType()
    {
        return currentAttribute.getId();
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If the value can't be added
     */
    public void addAttributeValue( String value ) throws LdapException
    {
        currentAttribute.add( value );
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If the value can't be added
     */
    public void addAttributeValue( Value<?> value ) throws LdapException
    {
        currentAttribute.add( value );
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If the value can't be added
     */
    public void addAttributeValue( byte[] value ) throws LdapException
    {
        currentAttribute.add( value );
    }


    // ------------------------------------------------------------------------
    // AddRequest Interface Method Implementations
    // ------------------------------------------------------------------------

    /**
     * Gets the distinguished name of the entry to add.
     * 
     * @return the Dn of the added entry.
     */
    @Override
    public Dn getEntryDn()
    {
        return entry.getDn();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddRequest setEntryDn( Dn dn )
    {
        entry.setDn( dn );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry getEntry()
    {
        return entry;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddRequest setEntry( Entry entry )
    {
        this.entry = entry;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddRequest addControl( Control control )
    {
        return ( AddRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddRequest addAllControls( Control[] controls )
    {
        return ( AddRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddRequest removeControl( Control control )
    {
        return ( AddRequest ) super.removeControl( control );
    }


    // ------------------------------------------------------------------------
    // SingleReplyRequest Interface Method Implementations
    // ------------------------------------------------------------------------

    /**
     * Gets the protocol response message type for this request which produces
     * at least one response.
     * 
     * @return the message type of the response.
     */
    @Override
    public MessageTypeEnum getResponseType()
    {
        return MessageTypeEnum.ADD_RESPONSE;
    }


    /**
     * The result containing response for this request.
     * 
     * @return the result containing response for this request
     */
    @Override
    public AddResponse getResultResponse()
    {
        if ( response == null )
        {
            response = new AddResponseImpl( getMessageId() );
        }

        return response;
    }


    /**
     * Checks to see if an object is equivalent to this AddRequest. First
     * there's a quick test to see if the obj is the same object as this one -
     * if so true is returned. Next if the super method fails false is returned.
     * Then the name of the entry is compared - if not the same false is
     * returned. Lastly the attributes of the entry are compared. If they are
     * not the same false is returned otherwise the method exists returning
     * true.
     * 
     * @param obj the object to test for equality to this
     * @return true if the obj is equal to this AddRequest, false otherwise
     */
    @Override
    public boolean equals( Object obj )
    {
        // Short circuit
        if ( this == obj )
        {
            return true;
        }

        // Check the object class. If null, it will exit.
        if ( !( obj instanceof AddRequest ) )
        {
            return false;
        }

        if ( !super.equals( obj ) )
        {
            return false;
        }

        AddRequest req = ( AddRequest ) obj;

        // Check the entry
        if ( entry == null )
        {
            return req.getEntry() == null;
        }
        else
        {
            return entry.equals( req.getEntry() );
        }
    }


    /**
     * @see Object#hashCode()
     * @return the instance's hash code 
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        hash = hash * 17 + ( entry == null ? 0 : entry.hashCode() );
        hash = hash * 17 + ( response == null ? 0 : response.hashCode() );
        hash = hash * 17 + super.hashCode();

        return hash;
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    Add Request :\n" );

        if ( entry == null )
        {
            sb.append( "            No entry\n" );
        }
        else
        {
            sb.append( entry.toString() );
        }

        return super.toString( sb.toString() );
    }
}
