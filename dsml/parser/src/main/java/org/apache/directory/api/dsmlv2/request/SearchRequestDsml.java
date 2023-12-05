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
package org.apache.directory.api.dsmlv2.request;


import java.util.ArrayList;
import java.util.List;

import org.apache.commons.text.StringEscapeUtils;
import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.dsmlv2.DsmlLiterals;
import org.apache.directory.api.dsmlv2.ParserUtils;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
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
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Strings;
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
     * @throws LdapSchemaException If the filter is invalid
     */
    public ExprNode getFilterNode() throws LdapSchemaException
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
     * @throws LdapSchemaException If the filter contains a wrong schema element
     */
    @SuppressWarnings({ "rawtypes" })
    private ExprNode transform( Filter filter ) throws LdapSchemaException
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
                    AttributeValueAssertionFilter avaFilter = ( AttributeValueAssertionFilter ) filter;

                    AttributeValueAssertion ava = avaFilter.getAssertion();

                    // Transform =, >=, <=, ~= filters
                    int filterType = avaFilter.getFilterType();
                    byte[] value = null;
                    
                    if ( ava.getAssertionValue() != null )
                    {
                        value = ava.getAssertionValue().getBytes();
                    }
                    
                    switch ( filterType )
                    {
                        case LdapCodecConstants.EQUALITY_MATCH_FILTER:
                            branch = new EqualityNode( ava.getAttributeDesc(), value );
                            break;

                        case LdapCodecConstants.GREATER_OR_EQUAL_FILTER:
                            branch = new GreaterEqNode( ava.getAttributeDesc(), value );
                            break;

                        case LdapCodecConstants.LESS_OR_EQUAL_FILTER:
                            branch = new LessEqNode( ava.getAttributeDesc(), value );
                            break;

                        case LdapCodecConstants.APPROX_MATCH_FILTER:
                            branch = new ApproximateNode( ava.getAttributeDesc(), value );
                            break;

                        default:
                            throw new IllegalStateException( I18n.err( I18n.ERR_03042_UNEXPECTED_FILTER_TYPE, filterType ) );
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

                    Value value = extFilter.getMatchValue();

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
    @Override
    public MessageTypeEnum getType()
    {
        return getDecorated().getType();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Element toDsml( Element root )
    {
        Element element = super.toDsml( root );

        SearchRequest request = getDecorated();

        // Dn
        if ( request.getBase() != null )
        {
            element.addAttribute( DsmlLiterals.DN, request.getBase().getName() );
        }

        // Scope
        SearchScope scope = request.getScope();
        if ( scope != null )
        {
            if ( scope == SearchScope.OBJECT )
            {
                element.addAttribute( DsmlLiterals.SCOPE, DsmlLiterals.BASE_OBJECT );
            }
            else if ( scope == SearchScope.ONELEVEL )
            {
                element.addAttribute( DsmlLiterals.SCOPE, DsmlLiterals.SINGLE_LEVEL );
            }
            else if ( scope == SearchScope.SUBTREE )
            {
                element.addAttribute( DsmlLiterals.SCOPE, DsmlLiterals.WHOLE_SUBTREE );
            }
        }

        // DerefAliases
        AliasDerefMode derefAliases = request.getDerefAliases();

        switch ( derefAliases )
        {
            case NEVER_DEREF_ALIASES:
                element.addAttribute( DsmlLiterals.DEREF_ALIASES, DsmlLiterals.NEVER_DEREF_ALIASES );
                break;

            case DEREF_ALWAYS:
                element.addAttribute( DsmlLiterals.DEREF_ALIASES, DsmlLiterals.DEREF_ALWAYS );
                break;

            case DEREF_FINDING_BASE_OBJ:
                element.addAttribute( DsmlLiterals.DEREF_ALIASES, DsmlLiterals.DEREF_FINDING_BASE_OBJ );
                break;

            case DEREF_IN_SEARCHING:
                element.addAttribute( DsmlLiterals.DEREF_ALIASES, DsmlLiterals.DEREF_IN_SEARCHING );
                break;

            default:
                throw new IllegalStateException( I18n.err( I18n.ERR_03043_UNEXPECTED_DEREF_ALIAS, derefAliases ) );
        }

        // SizeLimit
        if ( request.getSizeLimit() != 0L )
        {
            element.addAttribute( DsmlLiterals.SIZE_LIMIT, Long.toString( request.getSizeLimit() ) );
        }

        // TimeLimit
        if ( request.getTimeLimit() != 0 )
        {
            element.addAttribute( DsmlLiterals.TIME_LIMIT, Integer.toString( request.getTimeLimit() ) );
        }

        // TypesOnly
        if ( request.getTypesOnly() )
        {
            element.addAttribute( DsmlLiterals.TYPES_ONLY,  DsmlLiterals.TRUE );
        }

        // Filter
        Element filterElement = element.addElement( DsmlLiterals.FILTER );
        toDsml( filterElement, request.getFilter() );

        // Attributes
        List<String> attributes = request.getAttributes();

        if ( !attributes.isEmpty() )
        {
            Element attributesElement = element.addElement( DsmlLiterals.ATTRIBUTES );

            for ( String entryAttribute : attributes )
            {
                attributesElement.addElement( DsmlLiterals.ATTRIBUTE ).addAttribute( DsmlLiterals.NAME, entryAttribute );
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
            Element newElement = element.addElement( DsmlLiterals.AND );

            List<ExprNode> filterList = ( ( AndNode ) filter ).getChildren();

            for ( int i = 0; i < filterList.size(); i++ )
            {
                toDsml( newElement, filterList.get( i ) );
            }
        }

        // OR FILTER
        else if ( filter instanceof OrNode )
        {
            Element newElement = element.addElement( DsmlLiterals.OR );

            List<ExprNode> filterList = ( ( OrNode ) filter ).getChildren();

            for ( int i = 0; i < filterList.size(); i++ )
            {
                toDsml( newElement, filterList.get( i ) );
            }
        }

        // NOT FILTER
        else if ( filter instanceof NotNode )
        {
            Element newElement = element.addElement( DsmlLiterals.NOT );

            toDsml( newElement, ( ( NotNode ) filter ).getFirstChild() );
        }

        // SUBSTRING FILTER
        else if ( filter instanceof SubstringNode )
        {
            Element newElement = element.addElement( DsmlLiterals.SUBSTRINGS );

            SubstringNode substringFilter = ( SubstringNode ) filter;

            newElement.addAttribute( DsmlLiterals.NAME, substringFilter.getAttribute() );

            String initial = substringFilter.getInitial();

            if ( Strings.isNotEmpty( initial ) )
            {
                newElement.addElement( DsmlLiterals.INITIAL ).setText( initial );
            }

            List<String> anyList = substringFilter.getAny();

            for ( int i = 0; i < anyList.size(); i++ )
            {
                newElement.addElement( DsmlLiterals.ANY ).setText( anyList.get( i ) );
            }

            String finalString = substringFilter.getFinal();

            if ( Strings.isNotEmpty( finalString  ) )
            {
                newElement.addElement( DsmlLiterals.FINAL ).setText( finalString );
            }
        }

        // APPROXMATCH, EQUALITYMATCH, GREATEROREQUALS & LESSOREQUAL FILTERS
        else if ( filter instanceof SimpleNode )
        {
            Element newElement;

            if ( filter instanceof ApproximateNode )
            {
                newElement = element.addElement( DsmlLiterals.APPROX_MATCH );
            }
            else if ( filter instanceof EqualityNode )
            {
                newElement = element.addElement( DsmlLiterals.EQUALITY_MATCH );
            }
            else if ( filter instanceof GreaterEqNode )
            {
                newElement = element.addElement( DsmlLiterals.GREATER_OR_EQUAL );
            }
            else
            // it is a LessEqNode )
            {
                newElement = element.addElement( DsmlLiterals.LESS_OR_EQUAL );
            }

            String attributeName = ( ( SimpleNode<?> ) filter ).getAttribute();
            newElement.addAttribute( DsmlLiterals.NAME, attributeName );

            Value value = ( ( SimpleNode<?> ) filter ).getValue();
            
            if ( value != null )
            {
                if ( value.isHumanReadable() )
                {
                    newElement.addElement( DsmlLiterals.VALUE ).setText( StringEscapeUtils.escapeXml11( value.getString() ) );
                }
                else
                {
                    Namespace xsdNamespace = new Namespace( ParserUtils.XSD, ParserUtils.XML_SCHEMA_URI );
                    Namespace xsiNamespace = new Namespace( ParserUtils.XSI, ParserUtils.XML_SCHEMA_INSTANCE_URI );
                    element.getDocument().getRootElement().add( xsdNamespace );
                    element.getDocument().getRootElement().add( xsiNamespace );

                    Element valueElement = newElement.addElement( DsmlLiterals.VALUE ).addText(
                        ParserUtils.base64Encode( value.getBytes() ) );
                    valueElement
                        .addAttribute( new QName( DsmlLiterals.TYPE, xsiNamespace ), ParserUtils.XSD_COLON + ParserUtils.BASE64BINARY );
                }
            }
        }

        // PRESENT FILTER
        else if ( filter instanceof PresenceNode )
        {
            Element newElement = element.addElement( DsmlLiterals.PRESENT );

            newElement.addAttribute( DsmlLiterals.NAME, ( ( PresenceNode ) filter ).getAttribute() );
        }

        // EXTENSIBLEMATCH
        else if ( filter instanceof ExtensibleNode )
        {
            Element newElement = element.addElement( DsmlLiterals.EXTENSIBLE_MATCH );

            Value value = ( ( ExtensibleNode ) filter ).getValue();
            
            if ( value != null )
            {
                if ( !value.isHumanReadable() )
                {
                    Namespace xsdNamespace = new Namespace( ParserUtils.XSD, ParserUtils.XML_SCHEMA_URI );
                    Namespace xsiNamespace = new Namespace( ParserUtils.XSI, ParserUtils.XML_SCHEMA_INSTANCE_URI );
                    element.getDocument().getRootElement().add( xsdNamespace );
                    element.getDocument().getRootElement().add( xsiNamespace );

                    Element valueElement = newElement.addElement( DsmlLiterals.VALUE ).addText(
                        ParserUtils.base64Encode( value.getBytes() ) );
                    valueElement.addAttribute( new QName( DsmlLiterals.TYPE, xsiNamespace ), ParserUtils.XSD_COLON + ParserUtils.BASE64BINARY );
                }
                else
                {
                    newElement.addElement( DsmlLiterals.VALUE ).setText( value.getString() );
                }
            }

            if ( ( ( ExtensibleNode ) filter ).hasDnAttributes() )
            {
                newElement.addAttribute( DsmlLiterals.DN_ATTRIBUTES,  DsmlLiterals.TRUE );
            }

            String matchingRule = ( ( ExtensibleNode ) filter ).getMatchingRuleId();
            
            if ( Strings.isNotEmpty( matchingRule ) )
            {
                newElement.addAttribute( DsmlLiterals.MATCHING_RULE, matchingRule );
            }
        }
    }


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
    public SearchRequest setFilter( ExprNode filter )
    {
        getDecorated().setFilter( filter );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest setFilter( String filter ) throws LdapException
    {
        getDecorated().setFilter( filter );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchRequest setFilter( SchemaManager schemaManager, String filter ) throws LdapException
    {
        getDecorated().setFilter( schemaManager, filter );

        return this;
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
