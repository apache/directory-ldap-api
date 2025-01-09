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
 * IntermediateResponse implementation
 * 
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 */
public class IntermediateResponseImpl extends AbstractResultResponse implements IntermediateResponse
{
    /** Declares the Serial Version Uid */
    static final long serialVersionUID = -6646752766410531060L;

    /** ResponseName for the intermediate response */
    protected String responseName;

    /** Intermediate response message type enumeration value */
    private static final MessageTypeEnum TYPE = MessageTypeEnum.INTERMEDIATE_RESPONSE;

    /** Response Value for the intermediate response */
    protected byte[] responseValue;

    /**
     * Creates an IntermediateResponseImpl instance
     * 
     * @param responseName the IntermediateResponse's name
     */
    public IntermediateResponseImpl( String responseName )
    {
        super( -1, TYPE );
        this.responseName = responseName;
    }


    /**
     * Creates an IntermediateResponseImpl instance
     * 
     * @param id the session unique message id
     * @param responseName the IntermediateResponse's name
     */
    public IntermediateResponseImpl( int id, String responseName )
    {
        super( id, TYPE );
        this.responseName = responseName;
    }


    /**
     * Creates a new IntermediateResponseImpl instance
     * @param id The request ID
     */
    public IntermediateResponseImpl( int id )
    {
        super( id, TYPE );
    }


    // ------------------------------------------------------------------------
    // IntermediateResponse Interface Method Implementations
    // ------------------------------------------------------------------------

    /**
     * Gets the reponseName specific encoded
     * 
     * @return the response value
     */
    @Override
    public byte[] getResponseValue()
    {
        if ( responseValue == null )
        {
            return null;
        }

        final byte[] copy = new byte[responseValue.length];
        System.arraycopy( responseValue, 0, copy, 0, responseValue.length );
        return copy;
    }


    /**
     * Sets the response value
     * 
     * @param value the response value.
     */
    @Override
    public void setResponseValue( byte[] value )
    {
        if ( value != null )
        {
            this.responseValue = new byte[value.length];
            System.arraycopy( value, 0, this.responseValue, 0, value.length );
        }
        else
        {
            this.responseValue = null;
        }
    }


    /**
     * Gets the OID uniquely identifying this Intermediate response (a.k.a. its
     * name).
     * 
     * @return the OID of the Intermediate response type.
     */
    @Override
    public String getResponseName()
    {
        return ( responseName == null ) ? "" : responseName;
    }


    /**
     * Sets the OID uniquely identifying this Intermediate response (a.k.a. its
     * name).
     * 
     * @param oid the OID of the Intermediate response type.
     */
    @Override
    public void setResponseName( String oid )
    {
        this.responseName = oid;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        if ( responseName != null )
        {
            hash = hash * 17 + responseName.hashCode();
        }
        if ( responseValue != null )
        {
            hash = hash * 17 + Arrays.hashCode( responseValue );
        }
        hash = hash * 17 + super.hashCode();

        return hash;
    }


    /**
     * Checks to see if an object equals this IntemediateResponse.
     * 
     * @param obj the object to be checked for equality
     * @return true if the obj equals this IntemediateResponse, false otherwise
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

        if ( !( obj instanceof IntermediateResponse ) )
        {
            return false;
        }

        IntermediateResponse resp = ( IntermediateResponse ) obj;

        if ( ( responseName != null ) && ( resp.getResponseName() == null ) )
        {
            return false;
        }

        if ( ( responseName == null ) && ( resp.getResponseName() != null ) )
        {
            return false;
        }

        if ( ( responseName != null ) && ( resp.getResponseName() != null )
            && !responseName.equals( resp.getResponseName() ) )
        {
            return false;
        }

        if ( ( responseValue != null ) && ( resp.getResponseValue() == null ) )
        {
            return false;
        }

        if ( ( responseValue == null ) && ( resp.getResponseValue() != null ) )
        {
            return false;
        }

        return ( responseValue == null ) || ( resp.getResponseValue() == null )
        || Arrays.equals( responseValue, resp.getResponseValue() );
    }


    /**
     * Get a String representation of an IntermediateResponse
     * 
     * @return An IntermediateResponse String
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    Intermediate Response\n" );

        if ( responseName != null )
        {
            sb.append( "        Response name :'" ).append( responseName ).append( "'\n" );
        }

        if ( responseValue != null )
        {
            sb.append( "        ResponseValue :'" );
            sb.append( Strings.dumpBytes( responseValue ) );
            sb.append( "'\n" );
        }

        sb.append( super.toString() );

        return super.toString( sb.toString() );
    }
}
