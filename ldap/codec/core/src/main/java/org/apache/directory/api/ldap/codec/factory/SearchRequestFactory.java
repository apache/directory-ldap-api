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
package org.apache.directory.api.ldap.codec.factory;

import java.util.Iterator;
import java.util.List;

import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.ApproximateNode;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.ExtensibleNode;
import org.apache.directory.api.ldap.model.filter.GreaterEqNode;
import org.apache.directory.api.ldap.model.filter.LessEqNode;
import org.apache.directory.api.ldap.model.filter.NotNode;
import org.apache.directory.api.ldap.model.filter.OrNode;
import org.apache.directory.api.ldap.model.filter.PresenceNode;
import org.apache.directory.api.ldap.model.filter.SubstringNode;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.util.Strings;

/**
 * The SearchRequest factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class SearchRequestFactory implements Messagefactory
{
    /** The static instance */
    public static final SearchRequestFactory INSTANCE = new SearchRequestFactory();

    private SearchRequestFactory()
    {
        // Nothing to do
    }

    /**
     * Recursively encode the children of a connector node (AND, OR, NOT)
     *
     * @param buffer The buffer where to put the PDU
     * @param children The children to encode
     */
    private void encodeFilters( Asn1Buffer buffer, Iterator<ExprNode> children )
    {
        if ( children.hasNext() )
        {
            ExprNode child = children.next();

            // Recurse
            encodeFilters( buffer, children );

            // And finally the child, at the right position
            encodeFilter( buffer, child );
        }
    }


    /**
     * Encode a AndNode.
     * <br>
     * AndFilter :
     * <pre>
     * 0xA0 LL
     *  filter.encode() ... filter.encode()
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param node The AND filter to encode
     */
    private void encodeFilter( Asn1Buffer buffer, AndNode node )
    {
        int start = buffer.getPos();

        // encode each filter
        List<ExprNode> children = node.getChildren();

        if ( ( children != null ) && ( !children.isEmpty() ) )
        {
            encodeFilters( buffer, children.iterator() );
        }

        // The AndNode sequence
        BerValue.encodeSequence( buffer, ( byte ) LdapCodecConstants.AND_FILTER_TAG, start );
    }


    /**
     * Encode a OrNode.
     * <br>
     * OrFilter :
     * <pre>
     * 0xA1 LL
     *  filter.encode() ... filter.encode()
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param node The OR filter to encode
     */
    private void encodeFilter( Asn1Buffer buffer, OrNode node )
    {
        int start = buffer.getPos();

        // encode each filter
        List<ExprNode> children = node.getChildren();

        if ( ( children != null ) && ( !children.isEmpty() ) )
        {
            encodeFilters( buffer, children.iterator() );
        }

        // The AndNode sequence
        BerValue.encodeSequence( buffer, ( byte ) LdapCodecConstants.OR_FILTER_TAG, start );
    }


    /**
     * Encode a NotNode.
     * <br>
     * NotFilter :
     * <pre>
     * 0xA2 LL
     *  filter.encode() ... filter.encode()
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param node The NOT filter to encode
     */
    private void encodeFilter( Asn1Buffer buffer, NotNode node )
    {
        int start = buffer.getPos();

        // encode each filter
        List<ExprNode> children = node.getChildren();

        if ( ( children != null ) && ( !children.isEmpty() ) )
        {
            encodeFilters( buffer, children.iterator() );
        }

        // The NotNode sequence
        BerValue.encodeSequence( buffer, ( byte ) LdapCodecConstants.NOT_FILTER_TAG, start );
    }


    /**
     * Encode a EqualityNode.
     * <pre>
     * EqualityFilter :
     * <pre>
     * 0xA3 LL
     *   0x04 LL attributeDesc
     *   0x04 LL assertionValue
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param node The Equality filter to encode
     */
    private void encodeFilter( Asn1Buffer buffer, EqualityNode<?> node )
    {
        int start = buffer.getPos();

        // The attribute desc
        BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( node.getEscapedValue() ) );

        // The assertion desc
        BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( node.getAttribute() ) );

        // The EqualityNode sequence
        BerValue.encodeSequence( buffer, ( byte ) LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG, start );
    }


    /**
     * Encode a ApproximateNode.
     * <pre>
     * ApproximateFilter :
     * <pre>
     * 0xA8 LL
     *   0x04 LL attributeDesc
     *   0x04 LL assertionValue
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param node The Approximate filter to encode
     */
    private void encodeFilter( Asn1Buffer buffer, ApproximateNode<?> node )
    {
        int start = buffer.getPos();

        // The attribute desc
        BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( node.getEscapedValue() ) );

        // The assertion desc
        BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( node.getAttribute() ) );

        // The EqualityNode sequence
        BerValue.encodeSequence( buffer, ( byte ) LdapCodecConstants.APPROX_MATCH_FILTER_TAG, start );
    }


    /**
     * Encode a PresenceNode.
     * <br>
     * PresentFilter :
     * <pre>
     * 0x87 L1 present
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param node The Presence filter to encode
     */
    private void encodeFilter( Asn1Buffer buffer, PresenceNode node )
    {
        // The PresentFilter Tag
        BerValue.encodeOctetString( buffer, ( byte ) LdapCodecConstants.PRESENT_FILTER_TAG,
            Strings.getBytesUtf8( node.getAttribute() ) );
    }


    /**
     * Encode a GreaterEqNode.
     * <pre>
     * GreaterEqFilter :
     * <pre>
     * 0xA5 LL
     *   0x04 LL attributeDesc
     *   0x04 LL assertionValue
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param node The GreaterEq filter to encode
     */
    private void encodeFilter( Asn1Buffer buffer, GreaterEqNode<?> node )
    {
        int start = buffer.getPos();

        // The attribute desc
        BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( node.getEscapedValue() ) );

        // The assertion desc
        BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( node.getAttribute() ) );

        // The EqualityNode sequence
        BerValue.encodeSequence( buffer, ( byte ) LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG, start );
    }


    /**
     * Encode a LessEqNode.
     * <pre>
     * LessEqFilter :
     * <pre>
     * 0xA6 LL
     *   0x04 LL attributeDesc
     *   0x04 LL assertionValue
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param node The LessEq filter to encode
     */
    private void encodeFilter( Asn1Buffer buffer, LessEqNode<?> node )
    {
        int start = buffer.getPos();

        // The attribute desc
        BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( node.getEscapedValue() ) );

        // The assertion desc
        BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( node.getAttribute() ) );

        // The EqualityNode sequence
        BerValue.encodeSequence( buffer, ( byte ) LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG, start );
    }


    /**
     * Encode a SubstringNode.
     * <pre>
     * Substrings Filter :
     * <pre>
     * 0xA4 LL
     *   0x04 LL type
     *   0x30 LL substrings sequence
     *    |  0x80 LL initial
     *    | /  [0x81 LL any]*
     *    |/   [0x82 LL final]
     *    +--[0x81 LL any]+
     *     \   [0x82 LL final]
     *      \
     *       0x82 LL final
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param node The Substring filter to encode
     */
    private void encodeFilter( Asn1Buffer buffer, SubstringNode node )
    {
        int start = buffer.getPos();

        // The final
        if ( node.getFinal() != null )
        {
            BerValue.encodeOctetString( buffer, ( byte ) LdapCodecConstants.SUBSTRINGS_FILTER_FINAL_TAG,
                Strings.getBytesUtf8( node.getFinal() ) );
        }

        // The any
        List<String> any = node.getAny();

        if ( any != null )
        {
            for ( int i = any.size(); i > 0; i-- )
            {
                BerValue.encodeOctetString( buffer, ( byte ) LdapCodecConstants.SUBSTRINGS_FILTER_ANY_TAG,
                    Strings.getBytesUtf8( any.get( i - 1 ) ) );
            }
        }

        // The initial
        if ( node.getInitial() != null )
        {
            BerValue.encodeOctetString( buffer, ( byte ) LdapCodecConstants.SUBSTRINGS_FILTER_INITIAL_TAG,
                Strings.getBytesUtf8( node.getInitial() ) );
        }

        // The Substring sequence
        BerValue.encodeSequence( buffer, start );

        // The type
        BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( node.getAttribute() ) );

        // The EqualityNode sequence
        BerValue.encodeSequence( buffer, ( byte ) LdapCodecConstants.SUBSTRINGS_FILTER_TAG, start );
    }


    /**
     * Encode an ExtensibleNode.
     * <pre>
     * <br>
     * ExtensibleMatch filter :
     * <pre>
     * 0xA9 L1
     *   |
     *  [+--&gt; 0x81 L3 matchingRule]
     *  [+--&gt; 0x82 L4 type]
     *  [+--&gt; 0x83 L5 matchValue]
     *  [+--&gt; 0x01 0x01 dnAttributes]
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param node The ExtensibleMatch filter to encode
     */
    private void encodeFilter( Asn1Buffer buffer, ExtensibleNode node )
    {
        int start = buffer.getPos();

        // The dnAttributes flag, if true only
        if ( node.hasDnAttributes() )
        {
            BerValue.encodeBoolean( buffer, true );
        }

        // The matching value
        if ( node.getValue() != null )
        {
            BerValue.encodeOctetString( buffer, ( byte ) LdapCodecConstants.MATCH_VALUE_TAG,
                node.getValue().getBytes() );
        }

        // The type
        if ( node.getAttribute() != null )
        {
            BerValue.encodeOctetString( buffer, ( byte ) LdapCodecConstants.MATCHING_RULE_TYPE_TAG,
                Strings.getBytesUtf8( node.getAttribute() ) );
        }

        // The matching rule
        if ( node.getMatchingRuleId() != null )
        {
            BerValue.encodeOctetString( buffer, ( byte ) LdapCodecConstants.MATCHING_RULE_ID_TAG,
                Strings.getBytesUtf8( node.getMatchingRuleId() ) );
        }

        // The EqualityNode sequence
        BerValue.encodeSequence( buffer, ( byte ) LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG, start );
    }


    /**
     * Encode a Search Filter
     *
     * @param buffer The buffer where to put the PDU
     * @param node The top filter
     */
    private void encodeFilter( Asn1Buffer buffer, ExprNode node )
    {
        switch ( node.getClass().getSimpleName() )
        {
            case "AndNode" :
                encodeFilter( buffer, ( AndNode ) node );
                break;

            case "ApproximateNode" :
                encodeFilter( buffer, ( ApproximateNode<?> ) node );
                break;

            case "EqualityNode" :
                encodeFilter( buffer, ( EqualityNode<?> ) node );
                break;

            case "ExtensibleNode" :
                encodeFilter( buffer, ( ExtensibleNode ) node );
                break;


            case "GreaterEqNode" :
                encodeFilter( buffer, ( GreaterEqNode<?> ) node );
                break;

            case "LessEqNode" :
                encodeFilter( buffer, ( LessEqNode<?> ) node );
                break;

            case "NotNode" :
                encodeFilter( buffer, ( NotNode ) node );
                break;

            case "OrNode" :
                encodeFilter( buffer, ( OrNode ) node );
                break;

            case "PresenceNode" :
                encodeFilter( buffer, ( PresenceNode ) node );
                break;

            case "SubstringNode" :
                encodeFilter( buffer, ( SubstringNode ) node );
                break;

            default:
                break;
        }
    }

    /**
     * Encode the SearchRequest message to a PDU.
     * <br>
     * SearchRequest :
     * <pre>
     * 0x63 LL
     *   0x04 LL baseObject
     *   0x0A 01 scope
     *   0x0A 01 derefAliases
     *   0x02 0N sizeLimit
     *   0x02 0N timeLimit
     *   0x01 0x01 typesOnly
     *   filter.encode()
     *   0x30 LL attributeDescriptionList
     *     0x04 LL attributeDescription
     *     ...
     *     0x04 LL attributeDescription
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param message the ModifyRequest to encode
     */
    @Override
    public void encodeReverse( Asn1Buffer buffer, Message message )
    {
        int start = buffer.getPos();
        SearchRequest searchRequest = ( SearchRequest ) message;

        // The attributes, if any
        List<String> attributes = searchRequest.getAttributes();

        if ( ( attributes != null ) && ( !attributes.isEmpty() ) )
        {
            for ( int i = attributes.size(); i > 0; i-- )
            {
                BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( attributes.get( i - 1 ) ) );
            }
        }

        // The attributes sequence
        BerValue.encodeSequence( buffer, start );

        // The filter
        encodeFilter( buffer, searchRequest.getFilter() );

        // The typesOnly
        BerValue.encodeBoolean( buffer, searchRequest.getTypesOnly() );

        // The timeLimit
        BerValue.encodeInteger( buffer, searchRequest.getTimeLimit() );

        // The sizeLimit
        BerValue.encodeInteger( buffer, searchRequest.getSizeLimit() );

        // The derefAliases
        BerValue.encodeEnumerated( buffer, searchRequest.getDerefAliases().getValue() );

        // The scope
        BerValue.encodeEnumerated( buffer, searchRequest.getScope().getScope() );

        // The base object
        BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( searchRequest.getBase().getName() ) );

        // The SearchRequest tag
        BerValue.encodeSequence( buffer, LdapCodecConstants.SEARCH_REQUEST_TAG, start );
    }
}
