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


import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;


/**
 * Comparison request implementation.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CompareRequestImpl extends AbstractAbandonableRequest implements CompareRequest
{
    /** Declares the Serial Version Uid */
    static final long serialVersionUID = 1699731530016468977L;

    /** Distinguished name identifying the compared entry */
    private Dn name;

    /** The id of the attribute used in the comparison */
    private String attrId;

    /** The value of the attribute used in the comparison */
    private Value attrVal;

    /** The associated response */
    private CompareResponse response;


    // ------------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------------
    /**
     * Creates an CompareRequest implementation to compare a named entry with an
     * attribute value assertion pair.
     */
    public CompareRequestImpl()
    {
        super( -1, MessageTypeEnum.COMPARE_REQUEST );
    }


    // ------------------------------------------------------------------------
    // ComparisonRequest Interface Method Implementations
    // ------------------------------------------------------------------------

    /**
     * Gets the distinguished name of the entry to be compared using the
     * attribute value assertion.
     * 
     * @return the Dn of the compared entry.
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
    public CompareRequest setName( Dn name )
    {
        this.name = name;

        return this;
    }


    /**
     * Gets the attribute value to use in making the comparison.
     * 
     * @return the attribute value to used in comparison.
     */
    @Override
public Value getAssertionValue()
    {
        return attrVal;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest setAssertionValue( String value )
    {
        this.attrVal = new Value( value );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest setAssertionValue( byte[] value )
    {
        if ( value != null )
        {
            this.attrVal = new Value( value );
        }
        else
        {
            this.attrVal = null;
        }

        return this;
    }


    /**
     * Gets the attribute id use in making the comparison.
     * 
     * @return the attribute id used in comparison.
     */
    @Override
    public String getAttributeId()
    {
        return attrId;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest setAttributeId( String attributeId )
    {
        this.attrId = attributeId;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest addControl( Control control )
    {
        return ( CompareRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest addAllControls( Control[] controls )
    {
        return ( CompareRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareRequest removeControl( Control control )
    {
        return ( CompareRequest ) super.removeControl( control );
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
        return MessageTypeEnum.COMPARE_RESPONSE;
    }


    /**
     * The result containing response for this request.
     * 
     * @return the result containing response for this request
     */
    @Override
    public CompareResponse getResultResponse()
    {
        if ( response == null )
        {
            response = new CompareResponseImpl( getMessageId() );
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
        if ( attrId != null )
        {
            hash = hash * 17 + attrId.hashCode();
        }
        if ( attrVal != null )
        {
            hash = hash * 17 + attrVal.hashCode();
        }
        Value reqVal = getAssertionValue();
        if ( reqVal != null )
        {
            hash = hash * 17 + reqVal.hashCode();
        }
        hash = hash * 17 + super.hashCode();

        return hash;
    }


    /**
     * Checks to see if an object is equivalent to this CompareRequest.
     * 
     * @param obj the obj to compare with this CompareRequest
     * @return true if the obj is equal to this request, false otherwise
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

        CompareRequest req = ( CompareRequest ) obj;
        Dn reqName = req.getName();

        if ( name == null )
        {
            if ( reqName != null )
            {
                return false;
            }
        }
        else
        {
            if ( reqName == null )
            {
                return false;
            }
            else
            {
                if ( !name.equals( reqName ) )
                {
                    return false;
                }
            }
        }

        String reqId = req.getAttributeId();

        if ( attrId == null )
        {
            if ( reqId != null )
            {
                return false;
            }
        }
        else
        {
            if ( reqId == null )
            {
                return false;
            }
            else
            {
                if ( !attrId.equals( reqId ) )
                {
                    return false;
                }
            }
                
        }

        Value reqVal = req.getAssertionValue();

        if ( attrVal != null )
        {
            if ( reqVal != null )
            {
                return attrVal.equals( reqVal );
            }
            else
            {
                return false;
            }
        }
        else
        {
            return reqVal == null;
        }
    }


    /**
     * Get a String representation of a Compare Request
     * 
     * @return A Compare Request String
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    Compare request\n" );
        sb.append( "        Entry : '" ).append( name.toString() ).append( "'\n" );
        sb.append( "        Attribute description : '" ).append( attrId ).append( "'\n" );
        sb.append( "        Attribute value : '" );

        if ( attrVal.isHumanReadable() )
        {
            sb.append( attrVal.getString() );
        }
        else
        {
            byte[] binVal = attrVal.getBytes();
            sb.append( Strings.utf8ToString( binVal ) ).append( '/' ).append( Strings.dumpBytes( binVal ) )
                .append( "'\n" );
        }

        // The controls
        sb.append( super.toString() );

        return super.toString( sb.toString() );
    }
}
