/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
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


/**
 * ExtendedRequest implementation.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractExtendedRequest extends AbstractRequest implements ExtendedRequest
{
    /** Declares the Serial Version Uid */
    static final long serialVersionUID = 7916990159044177480L;

    /** Extended request's Object Identifier or <b>requestName</b> */
    protected String oid;

    /** The associated response */
    private ExtendedResponse response;


    /**
     * Creates an ExtendedRequest implementing object used to perform
     * extended protocol operation on the server.
     */
    public AbstractExtendedRequest()
    {
        super( -1, MessageTypeEnum.EXTENDED_REQUEST, true );
    }


    /**
     * Creates an ExtendedRequest implementing object used to perform
     * extended protocol operation on the server.
     * 
     * @param id the sequential message identifier
     */
    public AbstractExtendedRequest( int id )
    {
        super( id, MessageTypeEnum.EXTENDED_REQUEST, true );
    }


    // -----------------------------------------------------------------------
    // ExtendedRequest Interface Method Implementations
    // -----------------------------------------------------------------------

    /**
     * Gets the Object Identifier corresponding to the extended request type.
     * This is the <b>requestName</b> portion of the ext. req. PDU.
     * 
     * @return the dotted-decimal representation as a String of the OID
     */
    @Override
    public String getRequestName()
    {
        return oid;
    }


    /**
     * Sets the Object Identifier corresponding to the extended request type.
     * 
     * @param newOid the dotted-decimal representation as a String of the OID
     */
    @Override
    public ExtendedRequest setRequestName( String newOid )
    {
        this.oid = newOid;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedRequest addControl( Control control )
    {
        return ( ExtendedRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedRequest addAllControls( Control[] controls )
    {
        return ( ExtendedRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedRequest removeControl( Control control )
    {
        return ( ExtendedRequest ) super.removeControl( control );
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
        return MessageTypeEnum.EXTENDED_RESPONSE;
    }


    /**
     * The result containing response for this request.
     * 
     * @return the result containing response for this request
     */
    @Override
    public abstract ExtendedResponse getResultResponse();


    /**
     * Get the extended response
     * 
     * @return the response
     */
    public ExtendedResponse getResponse()
    {
        return response;
    }


    /**
     * Set the extended response
     * 
     * @param response the response to set
     */
    public void setResponse( ExtendedResponse response )
    {
        this.response = response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        
        if ( oid != null )
        {
            hash = hash * 17 + oid.hashCode();
        }
        
        hash = hash * 17 + super.hashCode();

        return hash;
    }


    /**
     * Checks to see if an object equals this ExtendedRequest.
     * 
     * @param obj the object to be checked for equality
     * @return true if the obj equals this ExtendedRequest, false otherwise
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

        if ( !( obj instanceof ExtendedRequest ) )
        {
            return false;
        }

        ExtendedRequest req = ( ExtendedRequest ) obj;
        
        String requestName = req.getRequestName();

        if ( oid == null )
        {
            if ( requestName != null )
            {
                return false;
            }
        }
        else
        {
            if ( requestName == null )
            {
                return false;
            }
            else if ( !oid.equals( requestName ) )
            {
                return false;
            }
        }

        return true;
    }


    /**
     * Get a String representation of an Extended Request
     * 
     * @return an Extended Request String
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    Extended request\n" );
        sb.append( "        Request name : '" ).append( oid ).append( "'\n" );

        // The controls
        sb.append( super.toString() );

        return super.toString( sb.toString() );
    }
}
