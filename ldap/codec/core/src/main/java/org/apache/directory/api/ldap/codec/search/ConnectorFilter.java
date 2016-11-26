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
package org.apache.directory.api.ldap.codec.search;


import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.i18n.I18n;


/**
 * This Filter abstract class is used to store a set of filters used by
 * OR/AND/NOT filters.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class ConnectorFilter extends Filter
{
    /** The set of filters used by And/Or filters */
    protected List<Filter> filterSet;

    /** The filters length */
    protected int filtersLength;


    /**
     * The constructor. We wont initialize the ArrayList as it may not be used.
     * 
     * @param tlvId The TLV identifier
     */
    public ConnectorFilter( int tlvId )
    {
        super( tlvId );
    }


    /**
     * The constructor. We wont initialize the ArrayList as it may not be used.
     */
    public ConnectorFilter()
    {
        super();
    }


    /**
     * Add a new Filter to the list.
     * 
     * @param filter The filter to add
     * @throws DecoderException If the decoding failed
     */
    public void addFilter( Filter filter ) throws DecoderException
    {

        if ( filterSet == null )
        {
            filterSet = new ArrayList<>();
        }

        filterSet.add( filter );
    }


    /**
     * Get the list of filters stored in the composite filter
     * 
     * @return And array of filters
     */
    public List<Filter> getFilterSet()
    {
        return filterSet;
    }


    /**
     * Compute the ConnectorFilter length Length(ConnectorFilter) =
     * sum(filterSet.computeLength())
     * 
     * @return The encoded length
     */
    @Override
    public int computeLength()
    {
        int connectorFilterLength = 0;

        if ( ( filterSet != null ) && ( !filterSet.isEmpty() ) )
        {
            for ( Filter filter : filterSet )
            {
                connectorFilterLength += filter.computeLength();
            }
        }

        return connectorFilterLength;
    }


    /**
     * Encode the ConnectorFilter message to a PDU. 
     * <pre>
     * ConnectorFilter :
     * filter.encode() ... filter.encode()
     * </pre>
     * 
     * @param buffer The buffer where to put the PDU
     * @return The PDU.
     * @throws EncoderException If the encoding failed
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04023 ) );
        }

        // encode each filter
        if ( ( filterSet != null ) && ( !filterSet.isEmpty() ) )
        {
            for ( Filter filter : filterSet )
            {
                filter.encode( buffer );
            }
        }

        return buffer;
    }


    /**
     * Return a string compliant with RFC 2254 representing a composite filter,
     * one of AND, OR and NOT
     * 
     * @return The composite filter string
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        if ( ( filterSet != null ) && ( !filterSet.isEmpty() ) )
        {
            for ( Filter filter : filterSet )
            {
                sb.append( '(' ).append( filter ).append( ')' );
            }
        }

        return sb.toString();
    }
}
