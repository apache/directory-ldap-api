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

import java.util.Arrays;

import org.apache.directory.api.util.Strings;

/**
 * ExtendedResponse basic implementation.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class OpaqueExtendedResponse extends AbstractResultResponse implements ExtendedResponse
{
    static final long serialVersionUID = 7916990159044177480L;

    /** Extended response's Object Identifier or <b>responseName</b> */
    private String oid;
    
    /** Extended response value as an opaque byte array */
    private byte[] responseValue;


    /**
     * Creates an ExtendedResponse implementing object used to perform
     * extended protocol operation on the server.
     */
    public OpaqueExtendedResponse()
    {
        super( -1, MessageTypeEnum.EXTENDED_RESPONSE );
    }


    // -----------------------------------------------------------------------
    // ExtendedRequest Interface Method Implementations
    // -----------------------------------------------------------------------

    /**
     * Gets the Object Identifier corresponding to the extended response type.
     * This is the <b>responseName</b> portion of the ext. req. PDU.
     * 
     * @return the dotted-decimal representation as a String of the OID
     */
    @Override
    public String getResponseName()
    {
        return oid;
    }


    /**
     * Sets the Object Identifier corresponding to the extended response type.
     * 
     * @param newOid the dotted-decimal representation as a String of the OID
     */
    @Override
    public void setResponseName( String newOid )
    {
        this.oid = newOid;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse addControl( Control control )
    {
        return ( ExtendedResponse ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse addAllControls( Control[] controls )
    {
        return ( ExtendedResponse ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse removeControl( Control control )
    {
        return ( ExtendedResponse ) super.removeControl( control );
    }


    // ------------------------------------------------------------------------
    // SingleReplyRequest Interface Method Implementations
    // ------------------------------------------------------------------------

    /**
     * @return the response value
     */
    public byte[] getResponseValue()
    {
        return responseValue;
    }


    /**
     * @param responseValue the responseValue to set
     */
    public void setResponseValue( byte[] responseValue )
    {
        this.responseValue = responseValue;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        
        hash = hash * 17 + super.hashCode();

        if ( oid != null )
        {
            hash = hash * 17 + oid.hashCode();
        }
        
        if ( responseValue != null )
        {
            for ( byte b : responseValue )
            { 
                hash = hash * 17 + b;
            }
        }

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

        if ( !( obj instanceof OpaqueExtendedResponse ) )
        {
            return false;
        }

        OpaqueExtendedResponse extendedRequest = ( OpaqueExtendedResponse ) obj;

        if ( ( ( oid != null ) && !oid.equals( extendedRequest.oid ) )
            || ( ( oid == null ) && ( extendedRequest.oid != null ) ) )
        {
            return false;
        }

        return Arrays.equals( responseValue, extendedRequest.responseValue );
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

        sb.append( "    Extended response\n" );
        sb.append( "        Response name :  '" ).append( oid ).append( "'\n" );
        sb.append( "        Response value : '" ).append( Strings.dumpBytes( responseValue ) ).append( "'\n" );

        return super.toString( sb.toString() );
    }
}
