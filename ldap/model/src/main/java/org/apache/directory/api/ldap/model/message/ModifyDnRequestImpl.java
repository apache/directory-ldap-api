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


import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;


/**
 * ModifyDNRequest implementation.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ModifyDnRequestImpl extends AbstractAbandonableRequest implements ModifyDnRequest
{
    static final long serialVersionUID = 1233507339633051696L;

    /** PDU's modify Dn candidate <b>entry</b> distinguished name property */
    private Dn name;

    /** PDU's <b>newrdn</b> relative distinguished name property */
    private Rdn newRdn;

    /** PDU's <b>newSuperior</b> distinguished name property */
    private Dn newSuperior;

    /** PDU's <b>deleteOldRdn</b> flag */
    private boolean deleteOldRdn = false;

    /** The associated response */
    private ModifyDnResponse response;


    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------
    /**
     * Creates a ModifyDnRequest implementing object used to perform a
     * dn change on an entry potentially resulting in an entry move.
     */
    public ModifyDnRequestImpl()
    {
        super( -1, MessageTypeEnum.MODIFYDN_REQUEST );
    }


    // -----------------------------------------------------------------------
    // ModifyDnRequest Interface Method Implementations
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getDeleteOldRdn()
    {
        return deleteOldRdn;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest setDeleteOldRdn( boolean deleteOldRdn )
    {
        this.deleteOldRdn = deleteOldRdn;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isMove()
    {
        return newSuperior != null;
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
    public ModifyDnRequest setName( Dn name )
    {
        this.name = name;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Rdn getNewRdn()
    {
        return newRdn;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest setNewRdn( Rdn newRdn )
    {
        this.newRdn = newRdn;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getNewSuperior()
    {
        return newSuperior;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest setNewSuperior( Dn newSuperior )
    {
        this.newSuperior = newSuperior;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest addControl( Control control )
    {
        return ( ModifyDnRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest addAllControls( Control[] controls )
    {
        return ( ModifyDnRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnRequest removeControl( Control control )
    {
        return ( ModifyDnRequest ) super.removeControl( control );
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
        return MessageTypeEnum.MODIFYDN_RESPONSE;
    }


    /**
     * The result containing response for this request.
     * 
     * @return the result containing response for this request
     */
    @Override
    public ModifyDnResponse getResultResponse()
    {
        if ( response == null )
        {
            response = new ModifyDnResponseImpl( getMessageId() );
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
        hash = hash * 17 + ( deleteOldRdn ? 0 : 1 );

        if ( newRdn != null )
        {
            hash = hash * 17 + newRdn.hashCode();
        }
        if ( newSuperior != null )
        {
            hash = hash * 17 + newSuperior.hashCode();
        }
        hash = hash * 17 + super.hashCode();

        return hash;
    }


    /**
     * Checks to see of an object equals this ModifyDnRequest stub. The equality
     * presumes all ModifyDnRequest specific properties are the same.
     * 
     * @param obj the object to compare with this stub
     * @return true if the obj is equal to this stub, false otherwise
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

        ModifyDnRequest req = ( ModifyDnRequest ) obj;

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

        if ( deleteOldRdn != req.getDeleteOldRdn() )
        {
            return false;
        }

        if ( newRdn != null && req.getNewRdn() == null )
        {
            return false;
        }

        if ( newRdn == null && req.getNewRdn() != null )
        {
            return false;
        }

        if ( newRdn != null && req.getNewRdn() != null && !newRdn.equals( req.getNewRdn() ) )
        {
            return false;
        }

        if ( newSuperior != null && req.getNewSuperior() == null )
        {
            return false;
        }

        if ( newSuperior == null && req.getNewSuperior() != null )
        {
            return false;
        }

        return ( newSuperior == null ) || ( req.getNewSuperior() == null ) || newSuperior.equals( req
            .getNewSuperior() );
    }


    /**
     * Get a String representation of a ModifyDNRequest
     * 
     * @return A ModifyDNRequest String
     */
    @Override
    public String toString()
    {

        StringBuilder sb = new StringBuilder();

        sb.append( "    ModifyDN Response\n" );
        sb.append( "        Entry : '" ).append( name ).append( "'\n" );
        if ( newRdn != null )
        {
            sb.append( "        New Rdn : '" ).append( newRdn.toString() ).append( "'\n" );
        }
        sb.append( "        Delete old Rdn : " ).append( deleteOldRdn ).append( "\n" );

        if ( newSuperior != null )
        {
            sb.append( "        New superior : '" ).append( newSuperior.toString() ).append( "'\n" );
        }

        // The controls
        sb.append( super.toString() );

        return super.toString( sb.toString() );
    }
}
