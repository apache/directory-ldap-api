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


import org.apache.directory.api.i18n.I18n;


/**
 * Implementation of an AbandonRequest message.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AbandonRequestImpl extends AbstractRequest implements AbandonRequest
{
    /** Sequence identifier of the outstanding request message to abandon */
    private int abandonId;


    /**
     * Creates an AbandonRequest implementation for an outstanding request.
     */
    public AbandonRequestImpl()
    {
        super( -1, TYPE, false );
    }


    /**
     * Creates an AbandonRequest implementation for an outstanding request.
     * 
     * @param abdandonnedId the sequence identifier of the AbandonRequest message.
     */
    public AbandonRequestImpl( final int abdandonnedId )
    {
        super( -1, TYPE, false );
        abandonId = abdandonnedId;
    }


    /**
     * Gets the id of the request operation to terminate.
     * 
     * @return the id of the request message to abandon
     */
    @Override
    public int getAbandoned()
    {
        return abandonId;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AbandonRequest setAbandoned( int abandonId )
    {
        this.abandonId = abandonId;

        return this;
    }


    /**
     * RFC 2251 [Section 4.11]: Abandon, Bind, Unbind, and StartTLS operations
     * cannot be abandoned.
     */
    public void abandon()
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_04185 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AbandonRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AbandonRequest addControl( Control control )
    {
        return ( AbandonRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AbandonRequest addAllControls( Control[] controls )
    {
        return ( AbandonRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AbandonRequest removeControl( Control control )
    {
        return ( AbandonRequest ) super.removeControl( control );
    }


    /**
     * Checks for equality first by asking the super method which should compare
     * all but the Abandoned request's Id. It then compares this to determine
     * equality.
     * 
     * @param obj the object to test for equality to this AbandonRequest
     * @return true if the obj equals this request, false otherwise
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( this == obj )
        {
            return true;
        }

        if ( ( obj == null ) || !( obj instanceof AbandonRequest ) )
        {
            return false;
        }

        if ( !super.equals( obj ) )
        {
            return false;
        }

        AbandonRequest req = ( AbandonRequest ) obj;

        return req.getAbandoned() == abandonId;
    }


    /**
     * @see Object#hashCode()
     * @return the instance's hash code 
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        hash = hash * 17 + abandonId;
        hash = hash * 17 + super.hashCode();

        return hash;
    }


    /**
     * Return a String representing an AbandonRequest
     * 
     * @return A String representing the AbandonRequest
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    Abandon Request :\n" );
        sb.append( "        Message Id : " ).append( abandonId );

        // The controls
        sb.append( super.toString() );

        return sb.toString();
    }
}
