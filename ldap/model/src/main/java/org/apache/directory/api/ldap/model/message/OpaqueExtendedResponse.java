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

import java.util.Arrays;

import org.apache.directory.api.util.Strings;

/**
 * ExtendedResponse basic implementation.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class OpaqueExtendedResponse extends AbstractExtendedResponse
{
    static final long serialVersionUID = 7916990159044177480L;

    /** Extended response value as an opaque byte array */
    private byte[] responseValue;


    /**
     * Creates an ExtendedResponse implementing object used to perform
     * extended protocol operation on the server.
     */
    public OpaqueExtendedResponse()
    {
        super( -1 );
    }


    /**
     * Creates an ExtendedResponse implementing object used to perform
     * extended protocol operation on the server.
     * 
     * @param messageId the messageID
     */
    public OpaqueExtendedResponse( int messageId )
    {
        super( messageId );
    }


    /**
     * Creates an ExtendedResponse implementing object used to perform
     * extended protocol operation on the server.
     * 
     * @param responseName The extended response OID
     */
    public OpaqueExtendedResponse( String responseName )
    {
        super( -1, responseName );
    }


    /**
     * Creates an ExtendedResponse implementing object used to perform
     * extended protocol operation on the server.
     * 
     * @param messageId the messageID
     * @param responseName The extended response OID
     */
    public OpaqueExtendedResponse( int messageId, String responseName )
    {
        super( messageId, responseName );
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

        if ( responseName != null )
        {
            hash = hash * 17 + responseName.hashCode();
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

        if ( ( ( responseName != null ) && !responseName.equals( extendedRequest.responseName ) )
            || ( ( responseName == null ) && ( extendedRequest.responseName != null ) ) )
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
        sb.append( "        Response name :  '" ).append( responseName ).append( "'\n" );
        sb.append( "        Response value : '" ).append( Strings.dumpBytes( responseValue ) ).append( "'\n" );

        return super.toString( sb.toString() );
    }
}
