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


import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.AttributeValueAssertion;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;


/**
 * Object to store the filter. A filter is seen as a tree with a root.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AttributeValueAssertionFilter extends Filter
{
    /** The assertion. */
    private AttributeValueAssertion assertion;

    /** The filter type */
    private int filterType;

    /** The attributeValueAssertion length */
    private int avaLength;


    /**
     * The constructor.
     * 
     * @param tlvId The TLV identifier
     * @param filterType The filter type
     */
    public AttributeValueAssertionFilter( int tlvId, int filterType )
    {
        super( tlvId );
        this.filterType = filterType;
    }


    /**
     * The constructor.
     * 
     * @param filterType The filter type
     */
    public AttributeValueAssertionFilter( int filterType )
    {
        super();
        this.filterType = filterType;
    }


    /**
     * Get the assertion
     * 
     * @return Returns the assertion.
     */
    public AttributeValueAssertion getAssertion()
    {
        return assertion;
    }


    /**
     * Set the assertion
     * 
     * @param assertion The assertion to set.
     */
    public void setAssertion( AttributeValueAssertion assertion )
    {
        this.assertion = assertion;
    }


    /**
     * Get the filter type
     * 
     * @return Returns the filterType.
     */
    public int getFilterType()
    {
        return filterType;
    }


    /**
     * Set the filter type
     * 
     * @param filterType The filterType to set.
     */
    public void setFilterType( int filterType )
    {
        this.filterType = filterType;
    }


    /**
     * Compute the AttributeValueFilter length
     * <br>
     * AttributeValueFilter :
     * <pre>
     * 0xA(3, 5, 6, 8) L1
     *  |
     *  +--&gt; 0x04 L2 attributeDesc
     *  +--&gt; 0x04 L3 assertionValue
     * 
     * 
     * L2 = Length(attributeDesc)
     * L3 = Length(assertionValue)
     * L1 = 1 + Length(L2) + L2
     *      + 1 + Length(L3) + L3
     * 
     * Length(AttributeValueFilter) = Length(0xA?) + Length(L1)
     *                                + 1 + Length(L2) + L2
     *                                + 1 + Length(L3) + L3
     * </pre>
     * 
     * @return The encoded length
     */
    @Override
    public int computeLength()
    {
        avaLength = 0;
        int attributeDescLength = assertion.getAttributeDesc().length();

        avaLength = 1 + TLV.getNbBytes( attributeDescLength ) + attributeDescLength;

        org.apache.directory.api.ldap.model.entry.Value<?> assertionValue = assertion.getAssertionValue();

        int assertionValueLength;

        assertionValueLength = assertionValue.getBytes().length;

        avaLength += 1 + TLV.getNbBytes( assertionValueLength ) + assertionValueLength;

        return 1 + TLV.getNbBytes( avaLength ) + avaLength;
    }


    /**
     * Encode the AttributeValueAssertion Filters to a PDU. The
     * following filters are to be encoded :
     * <ul>
     *   <li>equality match</li>
     *   <li>greater or equal</li>
     *   <li>less or equal</li>
     *   <li>approx match</li>
     * </ul>
     * 
     * AttributeValueAssertion filters :
     * <br>
     * <pre>
     * 0xA[3, 5, 6, 8] LL
     *   0x04 LL attributeDesc
     *   0x04 LL assertionValue
     * </pre>
     * 
     * @param buffer The buffer where to put the PDU
     * @return The PDU.
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04023 ) );
        }

        try
        {
            // The AttributeValueAssertion Tag
            switch ( filterType )
            {
                case LdapCodecConstants.EQUALITY_MATCH_FILTER:
                    buffer.put( ( byte ) LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG );
                    break;

                case LdapCodecConstants.LESS_OR_EQUAL_FILTER:
                    buffer.put( ( byte ) LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG );
                    break;

                case LdapCodecConstants.GREATER_OR_EQUAL_FILTER:
                    buffer.put( ( byte ) LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG );
                    break;

                case LdapCodecConstants.APPROX_MATCH_FILTER:
                    buffer.put( ( byte ) LdapCodecConstants.APPROX_MATCH_FILTER_TAG );
                    break;

                default:
                    throw new IllegalArgumentException( "Unexpected filter type: " + filterType );
            }

            buffer.put( TLV.getBytes( avaLength ) );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04005 ), boe );
        }

        // The attribute desc
        BerValue.encode( buffer, assertion.getAttributeDesc() );

        // The assertion desc
        if ( assertion.getAssertionValue().isHumanReadable() )
        {
            BerValue.encode( buffer, assertion.getAssertionValue().getString() );
        }
        else
        {
            BerValue.encode( buffer, assertion.getAssertionValue().getBytes() );
        }

        return buffer;
    }


    /**
     * Return a string compliant with RFC 2254 representing an item filter
     * 
     * @return The item filter string
     */
    @Override
    public String toString()
    {
        return assertion != null ? assertion.toStringRFC2254( filterType ) : "";
    }
}
