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
package org.apache.directory.api.dsmlv2.request;


import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.dsmlv2.ParserUtils;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.ApproximateNode;
import org.apache.directory.api.ldap.model.filter.BranchNode;
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
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;


/**
 * DSML Decorator for SearchRequest
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SearchRequestDsml
    extends AbstractResultResponseRequestDsml<SearchRequest, SearchResultDone>
    implements SearchRequest
{
    /** Some string constants */
    private static final String DEREF_ALIASES = "derefAliases";
    private static final String NAME = "name";
    private static final String VALUE = "value";
    
    /** A temporary storage for a terminal Filter */
    private Filter terminalFilter;

    /** The current filter. This is used while decoding a PDU */
    private Filter currentFilter;

    /** The global filter. This is used while decoding a PDU */
    private Filter topFilter;


    /**
     * Creates a new getDecoratedMessage() of SearchRequestDsml.
     * 
     * @param codec The LDAP Service to use
     */
    public SearchRequestDsml( LdapApiService codec )
    {
        super( codec, new SearchRequestImpl() );
    }


    /**
     * Creates a new getDecoratedMessage() of SearchRequestDsml.
     *
     * @param codec The LDAP Service to use
     * @param ldapMessage the message to decorate
     */
    public SearchRequestDsml( LdapApiService codec, SearchRequest ldapMessage )
    {
        super( codec, ldapMessage );
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
     * set the currentFilter to its parent
     */
    public void endCurrentConnectorFilter()
    {
        currentFilter = currentFilter.getParent();
    }


    /**
     * Add a current filter. We have two cases :
     * <ul>
     *   <li>there is no previous current filter : the filter
     *     is the top level filter</li>
     *   <li>there is a previous current filter : the filter is added
     *     to the currentFilter set, and the current filter is changed</li>
     * </ul>
     * In any case, the previous current filter will always be a
     * ConnectorFilter when this method is called.
     *
     * @param localFilter The filter to set.
     * @throws DecoderException If the added filter is invalid
     */
    public void addCurrentFilter( Filter localFilter ) throws DecoderException
    {
        if ( currentFilter != null )
        {
            // Ok, we have a parent. The new Filter will be added to
            // this parent, and will become the currentFilter if it's a connector.
            ( ( ConnectorFilter ) currentFilter ).addFilter( localFilter );
            localFilter.setParent( currentFilter );

            if ( localFilter instanceof ConnectorFilter )
            {
                currentFilter = localFilter;
            }
        }
        else
        {
            // No parent. This Filter will become the root.
            currentFilter = localFilter;
            currentFilter.setParent( null );
            topFilter = localFilter;
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
                BranchNode branch = null;

                if ( filter instanceof AndFilter )
                {
                    branch = new AndNode();
                }
                else if ( filter instanceof OrFilter )
                {
                    branch = new OrNode();
                }
                else if ( filter instanceof NotFilter )
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
                    AttributeValueAssertionFilter avaFilter = ( AttributeValueAssertionFilter ) filter;

                    AttributeValueAssertion ava = avaFilter.getAssertion();

                    // Transform =, >=, <=, ~= filters
                    int filterType = avaFilter.getFilterType();
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
                            throw new IllegalStateException( "Unexpected filter type " + filterType );
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
                        anyString = new ArrayList<String>();

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
     * {@inheritDoc}
     */
    public MessageTypeEnum getType()
    {
        return getDecorated().getType();
    }


    /**
     * {@inheritDoc}
     */
    public Element toDsml( Element root )
    {
        Element element = super.toDsml( root );

        SearchRequest request = getDecorated();

        // Dn
        if ( request.getBase() != null )
        {
            element.addAttribute( "dn", request.getBase().getName() );
        }

        // Scope
        SearchScope scope = request.getScope();
        if ( scope != null )
        {
            if ( scope == SearchScope.OBJECT )
            {
                element.addAttribute( "scope", "baseObject" );
            }
            else if ( scope == SearchScope.ONELEVEL )
            {
                element.addAttribute( "scope", "singleLevel" );
            }
            else if ( scope == SearchScope.SUBTREE )
            {
                element.addAttribute( "scope", "wholeSubtree" );
            }
        }

        // DerefAliases
        AliasDerefMode derefAliases = request.getDerefAliases();

        switch ( derefAliases )
        {
            case NEVER_DEREF_ALIASES:
                element.addAttribute( DEREF_ALIASES, "neverDerefAliases" );
                break;

            case DEREF_ALWAYS:
                element.addAttribute( DEREF_ALIASES, "derefAlways" );
                break;

            case DEREF_FINDING_BASE_OBJ:
                element.addAttribute( DEREF_ALIASES, "derefFindingBaseObj" );
                break;

            case DEREF_IN_SEARCHING:
                element.addAttribute( DEREF_ALIASES, "derefInSearching" );
                break;

            default:
                throw new IllegalStateException( "Unexpected deref alias mode " + derefAliases );
        }

        // SizeLimit
        if ( request.getSizeLimit() != 0L )
        {
            element.addAttribute( "sizeLimit", "" + request.getSizeLimit() );
        }

        // TimeLimit
        if ( request.getTimeLimit() != 0 )
        {
            element.addAttribute( "timeLimit", "" + request.getTimeLimit() );
        }

        // TypesOnly
        if ( request.getTypesOnly() )
        {
            element.addAttribute( "typesOnly", "true" );
        }

        // Filter
        Element filterElement = element.addElement( "filter" );
        toDsml( filterElement, request.getFilter() );

        // Attributes
        List<String> attributes = request.getAttributes();

        if ( attributes.size() > 0 )
        {
            Element attributesElement = element.addElement( "attributes" );

            for ( String entryAttribute : attributes )
            {
                attributesElement.addElement( "attribute" ).addAttribute( NAME, entryAttribute );
            }
        }

        return element;
    }


    /**
     * Recursively converts the filter of the Search Request into a DSML representation and adds 
     * it to the XML Element corresponding to the Search Request
     *
     * @param element
     *      the parent Element
     * @param filter
     *      the filter to convert
     */
    private void toDsml( Element element, ExprNode filter )
    {
        // AND FILTER
        if ( filter instanceof AndNode )
        {
            Element newElement = element.addElement( "and" );

            List<ExprNode> filterList = ( ( AndNode ) filter ).getChildren();

            for ( int i = 0; i < filterList.size(); i++ )
            {
                toDsml( newElement, filterList.get( i ) );
            }
        }

        // OR FILTER
        else if ( filter instanceof OrNode )
        {
            Element newElement = element.addElement( "or" );

            List<ExprNode> filterList = ( ( OrNode ) filter ).getChildren();

            for ( int i = 0; i < filterList.size(); i++ )
            {
                toDsml( newElement, filterList.get( i ) );
            }
        }

        // NOT FILTER
        else if ( filter instanceof NotNode )
        {
            Element newElement = element.addElement( "not" );

            toDsml( newElement, ( ( NotNode ) filter ).getFirstChild() );
        }

        // SUBSTRING FILTER
        else if ( filter instanceof SubstringNode )
        {
            Element newElement = element.addElement( "substrings" );

            SubstringNode substringFilter = ( SubstringNode ) filter;

            newElement.addAttribute( NAME, substringFilter.getAttribute() );

            String initial = substringFilter.getInitial();

            if ( ( initial != null ) && ( !"".equals( initial ) ) )
            {
                newElement.addElement( "initial" ).setText( initial );
            }

            List<String> anyList = substringFilter.getAny();

            for ( int i = 0; i < anyList.size(); i++ )
            {
                newElement.addElement( "any" ).setText( anyList.get( i ) );
            }

            String finalString = substringFilter.getFinal();

            if ( ( finalString != null ) && ( !"".equals( finalString ) ) )
            {
                newElement.addElement( "final" ).setText( finalString );
            }
        }

        // APPROXMATCH, EQUALITYMATCH, GREATEROREQUALS & LESSOREQUAL FILTERS
        else if ( filter instanceof SimpleNode )
        {
            Element newElement = null;

            if ( filter instanceof ApproximateNode )
            {
                newElement = element.addElement( "approxMatch" );
            }
            else if ( filter instanceof EqualityNode )
            {
                newElement = element.addElement( "equalityMatch" );
            }
            else if ( filter instanceof GreaterEqNode )
            {
                newElement = element.addElement( "greaterOrEqual" );
            }
            else
            // it is a LessEqNode )
            {
                newElement = element.addElement( "lessOrEqual" );
            }

            String attributeName = ( ( SimpleNode<?> ) filter ).getAttribute();
            newElement.addAttribute( NAME, attributeName );

            Value<?> value = ( ( SimpleNode<?> ) filter ).getValue();
            if ( value != null )
            {
                if ( ParserUtils.needsBase64Encoding( value ) )
                {
                    Namespace xsdNamespace = new Namespace( "xsd", ParserUtils.XML_SCHEMA_URI );
                    Namespace xsiNamespace = new Namespace( "xsi", ParserUtils.XML_SCHEMA_INSTANCE_URI );
                    element.getDocument().getRootElement().add( xsdNamespace );
                    element.getDocument().getRootElement().add( xsiNamespace );

                    Element valueElement = newElement.addElement( VALUE ).addText(
                        ParserUtils.base64Encode( value ) );
                    valueElement
                        .addAttribute( new QName( "type", xsiNamespace ), "xsd:" + ParserUtils.BASE64BINARY );
                }
                else
                {
                    newElement.addElement( VALUE ).setText( value.getString() );
                }
            }
        }

        // PRESENT FILTER
        else if ( filter instanceof PresenceNode )
        {
            Element newElement = element.addElement( "present" );

            newElement.addAttribute( NAME, ( ( PresenceNode ) filter ).getAttribute() );
        }

        // EXTENSIBLEMATCH
        else if ( filter instanceof ExtensibleNode )
        {
            Element newElement = element.addElement( "extensibleMatch" );

            Value<?> value = ( ( ExtensibleNode ) filter ).getValue();
            if ( value != null )
            {
                if ( ParserUtils.needsBase64Encoding( value ) )
                {
                    Namespace xsdNamespace = new Namespace( "xsd", ParserUtils.XML_SCHEMA_URI );
                    Namespace xsiNamespace = new Namespace( "xsi", ParserUtils.XML_SCHEMA_INSTANCE_URI );
                    element.getDocument().getRootElement().add( xsdNamespace );
                    element.getDocument().getRootElement().add( xsiNamespace );

                    Element valueElement = newElement.addElement( VALUE ).addText(
                        ParserUtils.base64Encode( value.getValue() ) );
                    valueElement.addAttribute( new QName( "type", xsiNamespace ), "xsd:" + ParserUtils.BASE64BINARY );
                }
                else
                {
                    newElement.addElement( VALUE ).setText( value.getString() );
                }
            }

            if ( ( ( ExtensibleNode ) filter ).hasDnAttributes() )
            {
                newElement.addAttribute( "dnAttributes", "true" );
            }

            String matchingRule = ( ( ExtensibleNode ) filter ).getMatchingRuleId();
            if ( ( matchingRule != null ) && ( "".equals( matchingRule ) ) )
            {
                newElement.addAttribute( "matchingRule", matchingRule );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    public MessageTypeEnum[] getResponseTypes()
    {
        return getDecorated().getResponseTypes();
    }


    /**
     * {@inheritDoc}
     */
    public Dn getBase()
    {
        return getDecorated().getBase();
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest setBase( Dn baseDn )
    {
        getDecorated().setBase( baseDn );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public SearchScope getScope()
    {
        return getDecorated().getScope();
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest setScope( SearchScope scope )
    {
        getDecorated().setScope( scope );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public AliasDerefMode getDerefAliases()
    {
        return getDecorated().getDerefAliases();
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest setDerefAliases( AliasDerefMode aliasDerefAliases )
    {
        getDecorated().setDerefAliases( aliasDerefAliases );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public long getSizeLimit()
    {
        return getDecorated().getSizeLimit();
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest setSizeLimit( long entriesMax )
    {
        getDecorated().setSizeLimit( entriesMax );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public int getTimeLimit()
    {
        return getDecorated().getTimeLimit();
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest setTimeLimit( int secondsMax )
    {
        getDecorated().setTimeLimit( secondsMax );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public boolean getTypesOnly()
    {
        return getDecorated().getTypesOnly();
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest setTypesOnly( boolean typesOnly )
    {
        getDecorated().setTypesOnly( typesOnly );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ExprNode getFilter()
    {
        return getDecorated().getFilter();
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest setFilter( ExprNode filter )
    {
        getDecorated().setFilter( filter );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest setFilter( String filter ) throws LdapException
    {
        getDecorated().setFilter( filter );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public List<String> getAttributes()
    {
        return getDecorated().getAttributes();
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest addAttributes( String... attributes )
    {
        getDecorated().addAttributes( attributes );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest removeAttribute( String attribute )
    {
        getDecorated().removeAttribute( attribute );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest setMessageId( int messageId )
    {
        return ( SearchRequest ) super.setMessageId( messageId );
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest addControl( Control control )
    {
        return ( SearchRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest addAllControls( Control[] controls )
    {
        return ( SearchRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest removeControl( Control control )
    {
        return ( SearchRequest ) super.removeControl( control );
    }


    /**
     * {@inheritDoc}
     */
    public boolean isFollowReferrals()
    {
        return getDecorated().isFollowReferrals();
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest followReferrals()
    {
        return getDecorated().followReferrals();
    }


    /**
     * {@inheritDoc}
     */
    public boolean isIgnoreReferrals()
    {
        return getDecorated().isIgnoreReferrals();
    }


    /**
     * {@inheritDoc}
     */
    public SearchRequest ignoreReferrals()
    {
        return getDecorated().ignoreReferrals();
    }
}
