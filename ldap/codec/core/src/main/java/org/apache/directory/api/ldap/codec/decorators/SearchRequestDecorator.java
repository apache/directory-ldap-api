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
package org.apache.directory.api.ldap.codec.decorators;


import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Container;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.AttributeValueAssertion;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.MessageDecorator;
import org.apache.directory.api.ldap.codec.search.AndFilter;
import org.apache.directory.api.ldap.codec.search.AttributeValueAssertionFilter;
import org.apache.directory.api.ldap.codec.search.ConnectorFilter;
import org.apache.directory.api.ldap.codec.search.ExtensibleMatchFilter;
import org.apache.directory.api.ldap.codec.search.Filter;
import org.apache.directory.api.ldap.codec.search.NotFilter;
import org.apache.directory.api.ldap.codec.search.OrFilter;
import org.apache.directory.api.ldap.codec.search.PresentFilter;
import org.apache.directory.api.ldap.codec.search.SubstringFilter;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.ApproximateNode;
import org.apache.directory.api.ldap.model.filter.BranchNode;
import org.apache.directory.api.ldap.model.filter.BranchNormalizedVisitor;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.ExtensibleNode;
import org.apache.directory.api.ldap.model.filter.GreaterEqNode;
import org.apache.directory.api.ldap.model.filter.LeafNode;
import org.apache.directory.api.ldap.model.filter.LessEqNode;
import org.apache.directory.api.ldap.model.filter.NotNode;
import org.apache.directory.api.ldap.model.filter.OrNode;
import org.apache.directory.api.ldap.model.filter.PresenceNode;
import org.apache.directory.api.ldap.model.filter.SimpleNode;
import org.apache.directory.api.ldap.model.filter.SubstringNode;
import org.apache.directory.api.ldap.model.message.AbandonListener;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;


/**
 * A decorator for the SearchRequest message
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SearchRequestDecorator extends MessageDecorator<SearchRequest> implements SearchRequest
{
    /** The searchRequest length */
    private int searchRequestLength;

    /** The attributeDescriptionList length */
    private int attributeDescriptionListLength;

    /** A temporary storage for a terminal Filter */
    private Filter terminalFilter;

    /** The current filter. This is used while decoding a PDU */
    private Filter currentFilter;

    /** The global filter. This is used while decoding a PDU */
    private Filter topFilter;

    /** The SearchRequest TLV id */
    private int tlvId;

    /** The bytes containing the Dn */
    private byte[] dnBytes;


    /**
     * Makes a SearchRequest encodable.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage the decorated SearchRequest
     */
    public SearchRequestDecorator( LdapApiService codec, SearchRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
    }


    /**
     * Set the SearchRequest PDU TLV's Id
     * @param tlvId The TLV id
     */
    public void setTlvId( int tlvId )
    {
        this.tlvId = tlvId;
    }


    /**
     * @return The current search filter
     */
    public Filter getCurrentFilter()
    {
        return currentFilter;
    }


    /**
     * Gets the search filter associated with this search request.
     *
     * @return the expression node for the root of the filter expression tree.
     */
    public Filter getCodecFilter()
    {
        return topFilter;
    }


    /**
     * Gets the search filter associated with this search request.
     *
     * @return the expression node for the root of the filter expression tree.
     */
    public ExprNode getFilterNode()
    {
        return transform( topFilter );
    }


    /**
     * Get the terminal filter
     *
     * @return Returns the terminal filter.
     */
    public Filter getTerminalFilter()
    {
        return terminalFilter;
    }


    /**
     * Set the terminal filter
     *
     * @param terminalFilter the teminalFilter.
     */
    public void setTerminalFilter( Filter terminalFilter )
    {
        this.terminalFilter = terminalFilter;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest setFilter( ExprNode filter )
    {
        topFilter = transform( filter );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest setFilter( String filter ) throws LdapException
    {
        getDecorated().setFilter( filter );
        this.currentFilter = transform( getDecorated().getFilter() );

        return this;
    }


    /**
     * Set the current filter
     *
     * @param filter The filter to set.
     */
    public void setCurrentFilter( Filter filter )
    {
        currentFilter = filter;
    }


    /**
     * Add a current filter. We have two cases :
     * - there is no previous current filter : the filter
     * is the top level filter
     * - there is a previous current filter : the filter is added
     * to the currentFilter set, and the current filter is changed
     *
     * In any case, the previous current filter will always be a
     * ConnectorFilter when this method is called.
     *
     * @param localFilter The filter to set.
     * @throws DecoderException If the filter is invalid
     */
    public void addCurrentFilter( Filter localFilter ) throws DecoderException
    {
        if ( currentFilter != null )
        {
            // Ok, we have a parent. The new Filter will be added to
            // this parent, and will become the currentFilter if it's a connector.
            ( ( ConnectorFilter ) currentFilter ).addFilter( localFilter );
            localFilter.setParent( currentFilter, currentFilter.getTlvId() );

            if ( localFilter instanceof ConnectorFilter )
            {
                currentFilter = localFilter;
            }
        }
        else
        {
            // No parent. This Filter will become the root.
            currentFilter = localFilter;
            currentFilter.setParent( null, tlvId );
            topFilter = localFilter;
        }
    }


    /**
     * This method is used to clear the filter's stack for terminated elements. An element
     * is considered as terminated either if :
     *  - it's a final element (ie an element which cannot contains a Filter)
     *  - its current length equals its expected length.
     *
     * @param container The container being decoded
     */
    @SuppressWarnings("unchecked")
    public void unstackFilters( Asn1Container container )
    {
        LdapMessageContainer<MessageDecorator<Message>> ldapMessageContainer =
            ( LdapMessageContainer<MessageDecorator<Message>> ) container;

        TLV tlv = ldapMessageContainer.getCurrentTLV();
        TLV localParent = tlv.getParent();
        Filter localFilter = terminalFilter;

        // The parent has been completed, so fold it
        while ( ( localParent != null ) && ( localParent.getExpectedLength() == 0 ) )
        {
            int parentTlvId = localFilter.getParent() != null ? localFilter.getParent().getTlvId() : localFilter
                .getParentTlvId();

            if ( localParent.getId() != parentTlvId )
            {
                localParent = localParent.getParent();
            }
            else
            {
                Filter filterParent = localFilter.getParent();

                // We have a special case with PresentFilter, which has not been
                // pushed on the stack, so we need to get its parent's parent
                if ( localFilter instanceof PresentFilter )
                {
                    if ( filterParent == null )
                    {
                        // We don't have parent, get out
                        break;
                    }

                    filterParent = filterParent.getParent();
                }
                else
                {
                    filterParent = filterParent.getParent();
                }

                if ( filterParent != null )
                {
                    // The parent is a filter ; it will become the new currentFilter
                    // and we will loop again.
                    localFilter = currentFilter;
                    currentFilter = filterParent;
                    localParent = localParent.getParent();
                }
                else
                {
                    // We can stop the recursion, we have reached the searchResult Object
                    break;
                }
            }
        }
    }


    /**
     * Transform the Filter part of a SearchRequest to an ExprNode
     *
     * @param filter The filter to be transformed
     * @return An ExprNode
     */
    @SuppressWarnings(
        { "unchecked", "rawtypes" })
    private ExprNode transform( Filter filter )
    {
        if ( filter != null )
        {
            // Transform OR, AND or NOT leaves
            if ( filter instanceof ConnectorFilter )
            {
                BranchNode branch;

                if ( filter instanceof AndFilter )
                {
                    branch = new AndNode();
                }
                else if ( filter instanceof OrFilter )
                {
                    branch = new OrNode();
                }
                else
                {
                    branch = new NotNode();
                }

                List<Filter> filtersSet = ( ( ConnectorFilter ) filter ).getFilterSet();

                // Loop on all AND/OR children
                if ( filtersSet != null )
                {
                    for ( Filter node : filtersSet )
                    {
                        branch.addNode( transform( node ) );
                    }
                }

                return branch;
            }
            else
            {
                // Transform PRESENT or ATTRIBUTE_VALUE_ASSERTION
                LeafNode branch = null;

                if ( filter instanceof PresentFilter )
                {
                    branch = new PresenceNode( ( ( PresentFilter ) filter ).getAttributeDescription() );
                }
                else if ( filter instanceof AttributeValueAssertionFilter )
                {
                    AttributeValueAssertion ava = ( ( AttributeValueAssertionFilter ) filter ).getAssertion();

                    // Transform =, >=, <=, ~= filters
                    int filterType = ( ( AttributeValueAssertionFilter ) filter ).getFilterType();
                    switch ( filterType )
                    {
                        case LdapCodecConstants.EQUALITY_MATCH_FILTER:
                            branch = new EqualityNode( ava.getAttributeDesc(), ava.getAssertionValue() );
                            break;

                        case LdapCodecConstants.GREATER_OR_EQUAL_FILTER:
                            branch = new GreaterEqNode( ava.getAttributeDesc(), ava.getAssertionValue() );
                            break;

                        case LdapCodecConstants.LESS_OR_EQUAL_FILTER:
                            branch = new LessEqNode( ava.getAttributeDesc(), ava.getAssertionValue() );
                            break;

                        case LdapCodecConstants.APPROX_MATCH_FILTER:
                            branch = new ApproximateNode( ava.getAttributeDesc(), ava.getAssertionValue() );
                            break;

                        default:
                            throw new IllegalArgumentException( "Unexpected filter type: " + filterType );
                    }

                }
                else if ( filter instanceof SubstringFilter )
                {
                    // Transform Substring filters
                    SubstringFilter substrFilter = ( SubstringFilter ) filter;
                    String initialString = null;
                    String finalString = null;
                    List<String> anyString = null;

                    if ( substrFilter.getInitialSubstrings() != null )
                    {
                        initialString = substrFilter.getInitialSubstrings();
                    }

                    if ( substrFilter.getFinalSubstrings() != null )
                    {
                        finalString = substrFilter.getFinalSubstrings();
                    }

                    if ( substrFilter.getAnySubstrings() != null )
                    {
                        anyString = new ArrayList<>();

                        for ( String any : substrFilter.getAnySubstrings() )
                        {
                            anyString.add( any );
                        }
                    }

                    branch = new SubstringNode( anyString, substrFilter.getType(), initialString, finalString );
                }
                else if ( filter instanceof ExtensibleMatchFilter )
                {
                    // Transform Extensible Match Filter
                    ExtensibleMatchFilter extFilter = ( ExtensibleMatchFilter ) filter;
                    String matchingRule = null;

                    Value<?> value = extFilter.getMatchValue();

                    if ( extFilter.getMatchingRule() != null )
                    {
                        matchingRule = extFilter.getMatchingRule();
                    }

                    branch = new ExtensibleNode( extFilter.getType(), value, matchingRule, extFilter.isDnAttributes() );
                }

                return branch;
            }
        }
        else
        {
            // We have found nothing to transform. Return null then.
            return null;
        }
    }


    /**
     * Transform an ExprNode filter to a Filter
     *
     * @param exprNode The filter to be transformed
     * @return A filter
     */
    private static Filter transform( ExprNode exprNode )
    {
        if ( exprNode != null )
        {
            Filter filter = null;

            // Transform OR, AND or NOT leaves
            if ( exprNode instanceof BranchNode )
            {
                if ( exprNode instanceof AndNode )
                {
                    filter = new AndFilter();
                }
                else if ( exprNode instanceof OrNode )
                {
                    filter = new OrFilter();
                }
                else
                {
                    filter = new NotFilter();
                }

                List<ExprNode> children = ( ( BranchNode ) exprNode ).getChildren();

                // Loop on all AND/OR children
                if ( children != null )
                {
                    for ( ExprNode child : children )
                    {
                        try
                        {
                            ( ( ConnectorFilter ) filter ).addFilter( transform( child ) );
                        }
                        catch ( DecoderException de )
                        {
                            return null;
                        }
                    }
                }
            }
            else
            {
                if ( exprNode instanceof PresenceNode )
                {
                    // Transform Presence Node
                    filter = new PresentFilter();
                    ( ( PresentFilter ) filter ).setAttributeDescription( ( ( PresenceNode ) exprNode ).getAttribute() );
                }
                else if ( exprNode instanceof SimpleNode<?> )
                {
                    if ( exprNode instanceof EqualityNode<?> )
                    {
                        filter = new AttributeValueAssertionFilter( LdapCodecConstants.EQUALITY_MATCH_FILTER );
                        AttributeValueAssertion assertion = new AttributeValueAssertion();
                        assertion.setAttributeDesc( ( ( EqualityNode<?> ) exprNode ).getAttribute() );
                        assertion.setAssertionValue( ( ( EqualityNode<?> ) exprNode ).getValue() );
                        ( ( AttributeValueAssertionFilter ) filter ).setAssertion( assertion );
                    }
                    else if ( exprNode instanceof GreaterEqNode<?> )
                    {
                        filter = new AttributeValueAssertionFilter( LdapCodecConstants.GREATER_OR_EQUAL_FILTER );
                        AttributeValueAssertion assertion = new AttributeValueAssertion();
                        assertion.setAttributeDesc( ( ( GreaterEqNode<?> ) exprNode ).getAttribute() );
                        assertion.setAssertionValue( ( ( GreaterEqNode<?> ) exprNode ).getValue() );
                        ( ( AttributeValueAssertionFilter ) filter ).setAssertion( assertion );
                    }
                    else if ( exprNode instanceof LessEqNode<?> )
                    {
                        filter = new AttributeValueAssertionFilter( LdapCodecConstants.LESS_OR_EQUAL_FILTER );
                        AttributeValueAssertion assertion = new AttributeValueAssertion();
                        assertion.setAttributeDesc( ( ( LessEqNode<?> ) exprNode ).getAttribute() );
                        assertion.setAssertionValue( ( ( LessEqNode<?> ) exprNode ).getValue() );
                        ( ( AttributeValueAssertionFilter ) filter ).setAssertion( assertion );
                    }
                    else if ( exprNode instanceof ApproximateNode<?> )
                    {
                        filter = new AttributeValueAssertionFilter( LdapCodecConstants.APPROX_MATCH_FILTER );
                        AttributeValueAssertion assertion = new AttributeValueAssertion();
                        assertion.setAttributeDesc( ( ( ApproximateNode<?> ) exprNode ).getAttribute() );
                        assertion.setAssertionValue( ( ( ApproximateNode<?> ) exprNode ).getValue() );
                        ( ( AttributeValueAssertionFilter ) filter ).setAssertion( assertion );
                    }
                }
                else if ( exprNode instanceof SubstringNode )
                {
                    // Transform Substring Nodes
                    filter = new SubstringFilter();

                    ( ( SubstringFilter ) filter ).setType( ( ( SubstringNode ) exprNode ).getAttribute() );
                    String initialString = ( ( SubstringNode ) exprNode ).getInitial();
                    String finalString = ( ( SubstringNode ) exprNode ).getFinal();
                    List<String> anyStrings = ( ( SubstringNode ) exprNode ).getAny();

                    if ( initialString != null )
                    {
                        ( ( SubstringFilter ) filter ).setInitialSubstrings( initialString );
                    }

                    if ( finalString != null )
                    {
                        ( ( SubstringFilter ) filter ).setFinalSubstrings( finalString );
                    }

                    if ( anyStrings != null )
                    {
                        for ( String any : anyStrings )
                        {
                            ( ( SubstringFilter ) filter ).addAnySubstrings( any );
                        }
                    }
                }
                else if ( exprNode instanceof ExtensibleNode )
                {
                    // Transform Extensible Node
                    filter = new ExtensibleMatchFilter();

                    String attribute = ( ( ExtensibleNode ) exprNode ).getAttribute();
                    String matchingRule = ( ( ExtensibleNode ) exprNode ).getMatchingRuleId();
                    boolean dnAttributes = ( ( ExtensibleNode ) exprNode ).hasDnAttributes();
                    Value<?> value = ( ( ExtensibleNode ) exprNode ).getValue();

                    if ( attribute != null )
                    {
                        ( ( ExtensibleMatchFilter ) filter ).setType( attribute );
                    }

                    if ( matchingRule != null )
                    {
                        ( ( ExtensibleMatchFilter ) filter ).setMatchingRule( matchingRule );
                    }

                    ( ( ExtensibleMatchFilter ) filter ).setMatchValue( value );
                    ( ( ExtensibleMatchFilter ) filter ).setDnAttributes( dnAttributes );
                }
            }

            return filter;
        }
        else
        {
            // We have found nothing to transform. Return null then.
            return null;
        }
    }


    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        int hash = 37;

        if ( getDecorated().getBase() != null )
        {
            hash = hash * 17 + getDecorated().getBase().hashCode();
        }

        hash = hash * 17 + getDecorated().getDerefAliases().hashCode();
        hash = hash * 17 + getDecorated().getScope().hashCode();
        hash = hash * 17 + Long.valueOf( getDecorated().getSizeLimit() ).hashCode();
        hash = hash * 17 + getDecorated().getTimeLimit();
        hash = hash * 17 + ( getDecorated().getTypesOnly() ? 0 : 1 );

        List<String> attributes = getDecorated().getAttributes();
        if ( attributes != null )
        {
            hash = hash * 17 + attributes.size();

            // Order doesn't matter, thus just add hashCode
            for ( String attr : attributes )
            {
                hash = hash + attr.hashCode();
            }
        }

        BranchNormalizedVisitor visitor = new BranchNormalizedVisitor();
        getDecorated().getFilter().accept( visitor );
        hash = hash * 17 + currentFilter.toString().hashCode();
        hash = hash * 17 + super.hashCode();

        return hash;
    }


    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals( Object o )
    {
        if ( !super.equals( o ) )
        {
            return false;
        }

        if ( !( o instanceof SearchRequestDecorator ) )
        {
            return false;
        }

        SearchRequestDecorator otherSearchRequestDecorator = ( SearchRequestDecorator ) o;

        if ( ( getDecorated() != null ) && ( !getDecorated().equals( otherSearchRequestDecorator.getDecorated() ) ) )
        {
            return false;
        }

        if ( searchRequestLength != otherSearchRequestDecorator.searchRequestLength )
        {
            return false;
        }

        if ( attributeDescriptionListLength != otherSearchRequestDecorator.attributeDescriptionListLength )
        {
            return false;
        }

        if ( ( terminalFilter != null ) && ( terminalFilter.equals( otherSearchRequestDecorator.terminalFilter ) ) )
        {
            return false;
        }

        if ( ( currentFilter != null ) && ( currentFilter.equals( otherSearchRequestDecorator.currentFilter ) ) )
        {
            return false;
        }

        if ( ( topFilter != null ) && ( topFilter.equals( otherSearchRequestDecorator.topFilter ) ) )
        {
            return false;
        }

        if ( tlvId != otherSearchRequestDecorator.tlvId )
        {
            return false;
        }

        return true;
    }


    //-------------------------------------------------------------------------
    // The SearchRequest methods
    //-------------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public MessageTypeEnum[] getResponseTypes()
    {
        return getDecorated().getResponseTypes();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getBase()
    {
        return getDecorated().getBase();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest setBase( Dn baseDn )
    {
        getDecorated().setBase( baseDn );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchScope getScope()
    {
        return getDecorated().getScope();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest setScope( SearchScope scope )
    {
        getDecorated().setScope( scope );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AliasDerefMode getDerefAliases()
    {
        return getDecorated().getDerefAliases();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest setDerefAliases( AliasDerefMode aliasDerefAliases )
    {
        getDecorated().setDerefAliases( aliasDerefAliases );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public long getSizeLimit()
    {
        return getDecorated().getSizeLimit();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest setSizeLimit( long entriesMax )
    {
        getDecorated().setSizeLimit( entriesMax );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getTimeLimit()
    {
        return getDecorated().getTimeLimit();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest setTimeLimit( int secondsMax )
    {
        getDecorated().setTimeLimit( secondsMax );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getTypesOnly()
    {
        return getDecorated().getTypesOnly();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest setTypesOnly( boolean typesOnly )
    {
        getDecorated().setTypesOnly( typesOnly );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExprNode getFilter()
    {
        return getDecorated().getFilter();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getAttributes()
    {
        return getDecorated().getAttributes();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest addAttributes( String... attributes )
    {
        getDecorated().addAttributes( attributes );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest removeAttribute( String attribute )
    {
        getDecorated().removeAttribute( attribute );

        return this;
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------

    /**
     * Compute the SearchRequest length
     * <br>
     * SearchRequest :
     * <pre>
     * 0x63 L1
     *  |
     *  +--&gt; 0x04 L2 baseObject
     *  +--&gt; 0x0A 0x01 scope
     *  +--&gt; 0x0A 0x01 derefAliases
     *  +--&gt; 0x02 0x0(1..4) sizeLimit
     *  +--&gt; 0x02 0x0(1..4) timeLimit
     *  +--&gt; 0x01 0x01 typesOnly
     *  +--&gt; filter.computeLength()
     *  +--&gt; 0x30 L3 (Attribute description list)
     *        |
     *        +--&gt; 0x04 L4-1 Attribute description
     *        +--&gt; 0x04 L4-2 Attribute description
     *        +--&gt; ...
     *        +--&gt; 0x04 L4-i Attribute description
     *        +--&gt; ...
     *        +--&gt; 0x04 L4-n Attribute description
     * </pre>
     */
    @Override
    public int computeLength()
    {
        searchRequestLength = 0;

        // The baseObject
        dnBytes = Strings.getBytesUtf8( getBase().getName() );
        searchRequestLength += 1 + TLV.getNbBytes( dnBytes.length ) + dnBytes.length;

        // The scope
        searchRequestLength += 1 + 1 + 1;

        // The derefAliases
        searchRequestLength += 1 + 1 + 1;

        // The sizeLimit
        searchRequestLength += 1 + 1 + BerValue.getNbBytes( getSizeLimit() );

        // The timeLimit
        searchRequestLength += 1 + 1 + BerValue.getNbBytes( getTimeLimit() );

        // The typesOnly
        searchRequestLength += 1 + 1 + 1;

        // The filter
        setFilter( getFilter() );
        searchRequestLength +=
            getCodecFilter().computeLength();

        // The attributes description list
        attributeDescriptionListLength = 0;

        if ( ( getAttributes() != null ) && ( !getAttributes().isEmpty() ) )
        {
            // Compute the attributes length
            for ( String attribute : getAttributes() )
            {
                // add the attribute length to the attributes length
                int idLength = Strings.getBytesUtf8( attribute ).length;
                attributeDescriptionListLength += 1 + TLV.getNbBytes( idLength ) + idLength;
            }
        }

        searchRequestLength += 1 + TLV.getNbBytes( attributeDescriptionListLength ) + attributeDescriptionListLength;

        // Return the result.
        return 1 + TLV.getNbBytes( searchRequestLength ) + searchRequestLength;
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
     * @return The PDU.
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        try
        {
            // The SearchRequest Tag
            buffer.put( LdapCodecConstants.SEARCH_REQUEST_TAG );
            buffer.put( TLV.getBytes( searchRequestLength ) );

            // The baseObject
            BerValue.encode( buffer, dnBytes );

            // The scope
            BerValue.encodeEnumerated( buffer, getScope().getScope() );

            // The derefAliases
            BerValue.encodeEnumerated( buffer, getDerefAliases().getValue() );

            // The sizeLimit
            BerValue.encode( buffer, getSizeLimit() );

            // The timeLimit
            BerValue.encode( buffer, getTimeLimit() );

            // The typesOnly
            BerValue.encode( buffer, getTypesOnly() );

            // The filter
            getCodecFilter().encode( buffer );

            // The attributeDescriptionList
            buffer.put( UniversalTag.SEQUENCE.getValue() );
            buffer.put( TLV.getBytes( attributeDescriptionListLength ) );

            if ( ( getAttributes() != null ) && ( !getAttributes().isEmpty() ) )
            {
                // encode each attribute
                for ( String attribute : getAttributes() )
                {
                    BerValue.encode( buffer, attribute );
                }
            }
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04005 ), boe );
        }

        return buffer;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchResultDone getResultResponse()
    {
        return ( SearchResultDone ) getDecorated().getResultResponse();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasResponse()
    {
        return getDecorated().hasResponse();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void abandon()
    {
        getDecorated().abandon();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAbandoned()
    {
        return getDecorated().isAbandoned();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest addAbandonListener( AbandonListener listener )
    {
        getDecorated().addAbandonListener( listener );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest setMessageId( int messageId )
    {
        return ( SearchRequest ) super.setMessageId( messageId );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest addControl( Control control )
    {
        return ( SearchRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest addAllControls( Control[] controls )
    {
        return ( SearchRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest removeControl( Control control )
    {
        return ( SearchRequest ) super.removeControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isFollowReferrals()
    {
        return getDecorated().isFollowReferrals();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest followReferrals()
    {
        return getDecorated().followReferrals();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isIgnoreReferrals()
    {
        return getDecorated().isIgnoreReferrals();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest ignoreReferrals()
    {
        return getDecorated().ignoreReferrals();
    }
}
