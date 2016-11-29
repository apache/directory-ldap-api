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


import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.StringConstants;


/**
 * Lockable ModifyRequest implementation.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ModifyRequestImpl extends AbstractAbandonableRequest implements ModifyRequest
{
    static final long serialVersionUID = -505803669028990304L;

    /** Dn of the entry to modify or PDU's <b>object</b> field */
    private Dn name;

    /** Sequence of modifications or PDU's <b>modification</b> sequence field */
    private List<Modification> mods = new ArrayList<>();

    /** The associated response */
    private ModifyResponse response;


    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------
    /**
     * Creates a ModifyRequest implementing object used to modify the
     * attributes of an entry.
     */
    public ModifyRequestImpl()
    {
        super( -1, MessageTypeEnum.MODIFY_REQUEST );
    }


    // ------------------------------------------------------------------------
    // ModifyRequest Interface Method Implementations
    // ------------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<Modification> getModifications()
    {
        return Collections.unmodifiableCollection( mods );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getName()
    {
        return name;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest setName( Dn name )
    {
        this.name = name;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest addModification( Modification mod )
    {
        mods.add( mod );

        return this;
    }


    private void addModification( ModificationOperation modOp, String attributeName, byte[]... attributeValue )
    {
        Attribute attr = new DefaultAttribute( attributeName, attributeValue );
        addModification( attr, modOp );
    }


    private void addModification( ModificationOperation modOp, String attributeName, String... attributeValue )
    {
        Attribute attr = new DefaultAttribute( attributeName, attributeValue );
        addModification( attr, modOp );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest addModification( Attribute attr, ModificationOperation modOp )
    {
        mods.add( new DefaultModification( modOp, attr ) );

        return this;
    }


    /**
     *{@inheritDoc}
     */
    @Override
    public ModifyRequest add( String attributeName, String... attributeValue )
    {
        addModification( ModificationOperation.ADD_ATTRIBUTE, attributeName, attributeValue );

        return this;
    }


    /**
     * @see #add(String, String...)
     */
    public ModifyRequest add( String attributeName, byte[]... attributeValue )
    {
        addModification( ModificationOperation.ADD_ATTRIBUTE, attributeName, attributeValue );

        return this;
    }


    /**
     *{@inheritDoc}
     */
    @Override
    public ModifyRequest add( Attribute attr )
    {
        addModification( attr, ModificationOperation.ADD_ATTRIBUTE );

        return this;
    }


    /**
     * @see #replace(String, String...)
     */
    @Override
    public ModifyRequest replace( String attributeName )
    {
        addModification( ModificationOperation.REPLACE_ATTRIBUTE, attributeName, StringConstants.EMPTY_STRINGS );

        return this;
    }


    /**
     *{@inheritDoc}
     */
    @Override
    public ModifyRequest replace( String attributeName, String... attributeValue )
    {
        addModification( ModificationOperation.REPLACE_ATTRIBUTE, attributeName, attributeValue );

        return this;
    }


    /**
     * @see #replace(String, String...)
     */
    public ModifyRequest replace( String attributeName, byte[]... attributeValue )
    {
        addModification( ModificationOperation.REPLACE_ATTRIBUTE, attributeName, attributeValue );

        return this;
    }


    /**
     *{@inheritDoc}
     */
    @Override
    public ModifyRequest replace( Attribute attr )
    {
        addModification( attr, ModificationOperation.REPLACE_ATTRIBUTE );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest removeModification( Modification mod )
    {
        mods.remove( mod );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest remove( String attributeName, String... attributeValue )
    {
        addModification( ModificationOperation.REMOVE_ATTRIBUTE, attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest remove( String attributeName, byte[]... attributeValue )
    {
        addModification( ModificationOperation.REMOVE_ATTRIBUTE, attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest remove( Attribute attr )
    {
        addModification( attr, ModificationOperation.REMOVE_ATTRIBUTE );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest remove( String attributerName )
    {
        addModification( new DefaultModification( ModificationOperation.REMOVE_ATTRIBUTE, attributerName ) );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest addControl( Control control )
    {
        return ( ModifyRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest addAllControls( Control[] controls )
    {
        return ( ModifyRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest removeControl( Control control )
    {
        return ( ModifyRequest ) super.removeControl( control );
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
        return MessageTypeEnum.MODIFY_RESPONSE;
    }


    /**
     * The result containing response for this request.
     * 
     * @return the result containing response for this request
     */
    @Override
    public ModifyResponse getResultResponse()
    {
        if ( response == null )
        {
            response = new ModifyResponseImpl( getMessageId() );
        }

        return response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        if ( name != null )
        {
            hash = hash * 17 + name.hashCode();
        }
        hash = hash * 17 + mods.size();
        for ( int i = 0; i < mods.size(); i++ )
        {
            hash = hash * 17 + ( ( DefaultModification ) mods.get( i ) ).hashCode();
        }
        hash = hash * 17 + super.hashCode();

        return hash;
    }


    /**
     * Checks to see if ModifyRequest stub equals another by factoring in checks
     * for the name and modification items of the request.
     * 
     * @param obj
     *            the object to compare this ModifyRequest to
     * @return true if obj equals this ModifyRequest, false otherwise
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( obj == this )
        {
            return true;
        }

        if ( !super.equals( obj ) )
        {
            return false;
        }

        ModifyRequest req = ( ModifyRequest ) obj;

        if ( name != null && req.getName() == null )
        {
            return false;
        }

        if ( name == null && req.getName() != null )
        {
            return false;
        }

        if ( name != null && req.getName() != null && !name.equals( req.getName() ) )
        {
            return false;
        }

        if ( req.getModifications().size() != mods.size() )
        {
            return false;
        }

        Iterator<Modification> list = req.getModifications().iterator();

        for ( int i = 0; i < mods.size(); i++ )
        {
            Modification item = list.next();

            if ( item == null )
            {
                if ( mods.get( i ) != null )
                {
                    return false;
                }
            }
            else

            if ( !item.equals( mods.get( i ) ) )
            {
                return false;
            }
        }

        return true;
    }


    /**
     * Get a String representation of a ModifyRequest
     * 
     * @return A ModifyRequest String
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    Modify Request\n" );
        sb.append( "        Object : '" ).append( name ).append( "'\n" );

        if ( mods != null )
        {

            for ( int i = 0; i < mods.size(); i++ )
            {

                DefaultModification modification = ( DefaultModification ) mods.get( i );

                sb.append( "            Modification[" ).append( i ).append( "]\n" );
                sb.append( "                Operation : " );

                switch ( modification.getOperation() )
                {
                    case ADD_ATTRIBUTE:
                        sb.append( " add\n" );
                        break;

                    case REPLACE_ATTRIBUTE:
                        sb.append( " replace\n" );
                        break;

                    case REMOVE_ATTRIBUTE:
                        sb.append( " delete\n" );
                        break;

                    default:
                        throw new IllegalArgumentException( "Unexpected ModificationOperation "
                            + modification.getOperation() );
                }

                sb.append( "                Modification\n" );
                sb.append( modification.getAttribute() );
            }
        }

        // The controls
        sb.append( super.toString() );

        return super.toString( sb.toString() );
    }
}
