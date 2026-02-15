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

package org.apache.directory.api.ldap.model.subtree;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.BranchNode;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.NotNode;
import org.apache.directory.api.ldap.model.filter.OrNode;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.NormalizerMappingResolver;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Position;
import org.apache.directory.api.util.Strings;

import static org.apache.directory.api.util.ParserUtil.getToken;
import static org.apache.directory.api.util.ParserUtil.isMatchChar;
import static org.apache.directory.api.util.ParserUtil.matchChar;
import static org.apache.directory.api.util.ParserUtil.parseQuotedSafeUtf8;
import static org.apache.directory.api.util.ParserUtil.parseInteger;
import static org.apache.directory.api.util.ParserUtil.parseOid;
import static org.apache.directory.api.util.ParserUtil.skipSpaces;

import java.text.ParseException;

import static org.apache.directory.api.util.ParserUtil.COLON;
import static org.apache.directory.api.util.ParserUtil.END;
import static org.apache.directory.api.util.ParserUtil.LCURLY;
import static org.apache.directory.api.util.ParserUtil.RCURLY;
import static org.apache.directory.api.util.ParserUtil.SEP;
import static org.apache.directory.api.util.ParserUtil.ONE_N;
import static org.apache.directory.api.util.ParserUtil.ZERO_N;


/**
 * A reusable wrapper around the antlr generated parser for an LDAP subtree
 * specification as defined by <a href="http://www.faqs.org/rfcs/rfc3672.html">
 * RFC 3672</a>. 
 * 
 * The parsed grammar is:
 * 
 * <pre>
 * subtreeSpecification = OPEN_CURLY ( SP )*
 *                          ( subtreeSpecificationComponent ( SP )*
 *                            ( SEP ( SP )* subtreeSpecificationComponent ( SP )* )* 
 *                          )?
 *                        CLOSE_CURLY
 * subtreeSpecificationComponent = ss_base | ss_specificExclusions | ss_minimum | ss_maximum | ss_specificationFilter
 * ss_base = ID_base ( SP )+ distinguishedName
 * ss_specificExclusions = ID_specificExclusions ( SP )+ specificExclusions
 * specificExclusions = OPEN_CURLY ( SP )*
 *                        ( specificExclusion ( SP )*
 *                          ( SEP ( SP )* specificExclusion ( SP )* )*
 *                        )?
 *                      CLOSE_CURLY
 * specificExclusion = chopBefore | chopAfter
 * chopBefore = ID_chopBefore ( SP )* COLON ( SP )* distinguishedName
 * chopAfter = ID_chopAfter ( SP )* COLON ( SP )* distinguishedName
 * ss_minimum = ID_minimum ( SP )+ INTEGER
 * ss_maximum = ID_maximum ( SP )+ INTEGER
 * ss_specificationFilter = ID_specificationFilter ( SP )+ ( refinement [| FILTER] )
 * refinements = OPEN_CURLY ( SP )*
 *                 (
 *                   refinement ( SP )* ( SEP ( SP )* refinement ( SP )* )*
 *                 )? 
 *               CLOSE_CURLY
 * refinement = item | and | or | not
 * item = ID_item ( SP )* COLON ( SP )* oid
 * and = ID_and ( SP )* COLON ( SP )* refinements
 * or = ID_or ( SP )* COLON ( SP )* refinements
 * not = ID_not ( SP )* COLON ( SP )* refinement
 * [FILTER = '(' ( '&' (SP)* FILTER+ | '|' (SP)* FILTER+ | '!' (SP)* FILTER | FILTER_VALUE ) ')' (SP)*
 * FILTER_VALUE = every char but '(', ')', '&', '|', '!']
 * </pre>
 * 
 * Note: the 'filter' part is not present in RFC 3672
 * 
 * @see <a href="http://www.faqs.org/rfcs/rfc3672.html">RFC 3672</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SubtreeSpecificationParser
{
     /** The schema manager instance */
    private SchemaManager schemaManager;

    private final boolean isNormalizing;
    
    /** The subtree specification tokens */
    private static final String ID_BASE = "base";
    private static final String ID_SPECIFIC_EXCLUSIONS = "specificExclusions";
    private static final String ID_CHOP_BEFORE = "chopBefore";
    private static final String ID_CHOP_AFTER = "chopAfter";
    private static final String ID_MINIMUM = "minimum";
    private static final String ID_MAXIMUM = "maximum";
    private static final String ID_SPECIFICATION_FILTER = "specificationFilter";
    private static final String ID_ITEM = "item";
    private static final String ID_AND = "and";
    private static final String ID_OR = "or";
    private static final String ID_NOT = "not";
    
    /** Flags to use to differentiate a parsing from a checking */
    private static final boolean PARSE = true;
    private static final boolean VALIDATE = false;

    /** The ObjectClass AT */
    private static AttributeType objectClassAt;

    /**
     * Creates a subtree specification parser.
     * 
     * @param schemaManager The SchemaManager
     */
    public SubtreeSpecificationParser( SchemaManager schemaManager )
    {
        // place holder for the first input
        this.isNormalizing = false;
        this.schemaManager = schemaManager;
        
        if ( schemaManager != null )
        {
            objectClassAt = schemaManager.getAttributeType( SchemaConstants.OBJECT_CLASS_AT );
        }

    }


    /**
     * Creates a normalizing subtree specification parser.
     * 
     * @param resolver The resolver to use
     * @param schemaManager The SchemaManager
     */
    public SubtreeSpecificationParser( @SuppressWarnings("rawtypes") NormalizerMappingResolver resolver,
        SchemaManager schemaManager )
    {
        // place holder for the first input
        this.isNormalizing = true;
        this.schemaManager = schemaManager;
    }

    
    /**
     * Parse a Base component, following this grammar:
     * 
     * <pre>
     *   base ::= ID_base ( SP )+ distinguishedName
     * </pre>
     * 
     * @param spec The string to parse
     * @param pos The position in the string
     * @return a valid DN
     * @throws ParseException The the Base component is incorrect
     */
    private Dn parseBase( String spec, Position pos ) throws ParseException
    {
        // First skip mandatory spaces
        if ( !skipSpaces( spec, pos, ONE_N ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_13904_MISSING_SPACE_AFTER_BASE ), pos.start );
        }
        
        // Parse the DN
        String dnStr = parseQuotedSafeUtf8( spec, pos );
        
        // Check the DN
        try
        {
            Dn dn = new Dn( schemaManager, dnStr );
            
            return dn;
        }
        catch ( LdapInvalidDnException ldie )
        {
            // error
            throw new ParseException( I18n.err( I18n.ERR_13908_SS_INVALID_DN, dnStr ), pos.start );
        }
    }
    
    
    /**
     * Parse a specific exclusion, following this grammar:
     * <pre>
     *   specificExclusion = chopBefore | chopAfter
     *   chopBefore = ID_chopBefore ( SP )* COLON ( SP )* distinguishedName
     *   chopAfter = ID_chopAfter ( SP )* COLON ( SP )* distinguishedName
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The subtreeSpecification string to parse
     * @param pos The position in the string
     * @ParseException If the input was incorrect
     */
    private void parseSpecificExclusion( boolean action, String spec, Position pos,
            SubtreeSpecificationModifier ssModifier ) throws ParseException
    {
        String token = getToken( spec, pos );
        
        // We may have none
        if ( END.equals( token ) )
        {
            return;
        }
        
        // Get rid of spaces, colon, spaces
        skipSpaces( spec, pos, ZERO_N );
        matchChar( spec, COLON, pos );
        skipSpaces( spec, pos, ZERO_N );

        // Get the DN
        String dnStr = parseQuotedSafeUtf8( spec, pos );
        
        // Check the DN and store 
        Dn dn;
        
        try
        {
            dn = new Dn( schemaManager, dnStr );
        }
        catch ( LdapInvalidDnException ldie )
        {
            throw new ParseException( I18n.err( I18n.ERR_13908_SS_INVALID_DN, dnStr ), pos.start );
        }
        
        if ( action == PARSE )
        {
            switch ( token )
            {
                case ID_CHOP_BEFORE:
                    ssModifier.addChopBeforeExclusions( dn );
                    return;
    
                case ID_CHOP_AFTER:
                    
                    ssModifier.addChopAfterExclusions( dn );
                    return;
    
                default:
                    // We are done
                    return;
            }
        }
    }
    
    
    /**
     * Parse the specific exclusions, following this grammar:
     * <pre>
     *   ID_specificExclusions ( SP )+ specificExclusions
     *   specificExclusions = 
     *     OPEN_CURLY ( SP )*
     *       ( specificExclusion ( SP )* ( SEP ( SP )* specificExclusion ( SP )* )* )?
     *     CLOSE_CURLY
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The subtreeSpecification string to parse
     * @param pos The position in the string
     * @ParseException If the input was incorrect
     */
    private void parseSpecificExclusions( boolean action, String spec, Position pos,
            SubtreeSpecificationModifier ssModifier ) throws ParseException
    {
        // Skip mandatory spaces
        if ( !skipSpaces( spec, pos, ONE_N ) )
        {
            // error
            throw new ParseException( I18n.err( I18n.ERR_13907_REQUIRED_SPACE_SS_SPEC_EXCLUSIONS ), pos.start );
        }
        
        // Specific exclusions starts with '{'
        matchChar( spec, LCURLY, pos );
        
        skipSpaces( spec, pos, ZERO_N );
        
        boolean isFirst = true;
        
        while ( true )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                // Check if we have a ','
                if ( !isMatchChar( spec, SEP, pos ) )
                {
                    // the end
                    break;
                }
                
                // skip the spaces
                skipSpaces( spec, pos, ZERO_N );
            }
            
            parseSpecificExclusion( action, spec, pos, ssModifier );
        }

        // Skip ending spaces
        skipSpaces( spec, pos, ZERO_N );

        // Must have an closing }
        matchChar( spec, RCURLY, pos );
    }
    
    
    /**
     * Parse the item, following this grammar:
     * <pre>
     *   item = ID_item ( SP )* COLON ( SP )* oid
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The subtreeSpecification string to parse
     * @param pos The position in the string
     * @ParseException If the input was incorrect
     */
    private ExprNode parseItem( boolean action, String spec, Position pos ) throws ParseException
    {
        // item = ID_item ( SP )* COLON ( SP )* oid
        skipSpaces( spec, pos, ZERO_N );
        
        matchChar( spec, COLON, pos );
        
        // The oid
        String oid = parseOid( spec, pos );
        
        try
        {
            // Check that the oid is valid
            if ( schemaManager != null )
            {
                schemaManager.lookupObjectClassRegistry( oid );
            }
        }
        catch ( LdapException le )
        {
            // The oid does not exist
            throw new ParseException( I18n.err( I18n.ERR_13906_SS_INVALID_ITEM, oid ), pos.start );
        }

        ExprNode item = null;
        
        if ( action == PARSE )
        {
            item = new EqualityNode( objectClassAt, new Value( oid ) );
        }

        return item;
    }
    
    
    /**
     * Parse the and/or refinement, following this grammar:
     * <pre>
     *   (ID_and | ID_or) ( SP )* COLON ( SP )* refinements
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The subtreeSpecification string to parse
     * @param pos The position in the string
     * @return The parsed node
     * @ParseException If the input was incorrect
     */
    private void parseAndOr( boolean action, String spec, Position pos, BranchNode node ) throws ParseException
    {
        // The 'and'/'or' token has already been parsed
        skipSpaces( spec, pos, ZERO_N );
        
        matchChar( spec, COLON, pos );
        
        parseRefinements( action, spec, pos, node );
    }
    
    
    /**
     * Parse the not refinement, following this grammar:
     * <pre>
     *   ID_not ( SP )* COLON ( SP )* refinement
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The subtreeSpecification string to parse
     * @param pos The position in the string
     * @return The parsed node
     * @ParseException If the input was incorrect
     */
    private void parseNot( boolean action, String spec, Position pos, BranchNode node ) throws ParseException
    {
        // The 'and'/'or' token has already been parsed
        skipSpaces( spec, pos, ZERO_N );
        
        matchChar( spec, COLON, pos );
        
        ExprNode refinement = parseRefinement( action, spec, pos );
        
        if ( action == PARSE )
        {
            node.addNode( refinement );
        }
    }

    
    /**
     * Parse some refinement, following this grammar:
     * <pre>
     * refinements = OPEN_CURLY ( SP )*
     *                  (
     *                    refinement ( SP )* ( SEP ( SP )* refinement ( SP )* )*
     *                  )? 
     *               CLOSE_CURLY
     * </pre>
     * 
     * @param spec The subtreeSpecification string to parse
     * @param pos The position in the string
     * @return the parsed nodes
     * @ParseException If the input was incorrect
     */
    private void parseRefinements( boolean  action, String spec, Position pos, BranchNode node ) throws ParseException
    {
        matchChar( spec, LCURLY, pos );
        
        skipSpaces( spec, pos, ZERO_N );
        
        boolean isFirst = true;
        
        while ( true )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                skipSpaces( spec, pos, ZERO_N );
                
                if ( !isMatchChar( spec, SEP, pos ) )
                {
                    // The end, expecting a ')'
                    matchChar( spec, RCURLY, pos );
                    
                    return;
                }
            }
            
            skipSpaces( spec, pos, ZERO_N );
            
            ExprNode refinement = parseRefinement( action, spec, pos );
            
            if ( action == PARSE )
            {
                node.addNode( refinement );
            }
        }
    }

    
    /**
     * Parse a refinement, following this grammar:
     * <pre>
     *   refinement = item | and | or | not
     *   item = ID_item ( SP )* COLON ( SP )* oid
     *   and = ID_and ( SP )* COLON ( SP )* refinements
     *   or = ID_or ( SP )* COLON ( SP )* refinements
     *   not = ID_not ( SP )* COLON ( SP )* refinement
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The subtreeSpecification string to parse
     * @param pos The position in the string
     * @return the parsed refinement
     * @ParseException If the input was incorrect
     */
    private ExprNode parseRefinement( boolean action, String spec, Position pos ) throws ParseException
    {
        // Skip optional spaces
        skipSpaces( spec, pos, ONE_N );
        
        // We have either an item, or an and/or/not filter
        String token = getToken( spec, pos );
        
        switch ( token )
        {
            case ID_ITEM:
                return parseItem( action, spec, pos );
                
            case ID_AND:
                AndNode andNode = null;
                
                if ( action  == PARSE )
                {
                    andNode = new AndNode();
                }
                
                parseAndOr( action, spec, pos, andNode );
                
                return andNode;
                
            case ID_OR:
                OrNode orNode = null;
                
                if ( action == PARSE )
                {
                    orNode = new OrNode();
                }
                
                parseAndOr( action, spec, pos, orNode );
                
                return orNode;
                
            case ID_NOT:
                NotNode notNode = null;
                
                if ( action == PARSE )
                {
                    notNode = new NotNode();
                }
                
                parseNot( action, spec, pos, notNode );
                
                return notNode;
                
            default:
                // The refinement end
                return null;
        }
    }

    
    /**
     * Parse a filter, following this grammar:
     * <pre>
     * FILTER = '(' ( '&' (SP)* FILTER+ | '|' (SP)* FILTER+ | '!' (SP)* FILTER | FILTER_VALUE ) ')' (SP)*
     * FILTER_VALUE = every char but '(', ')', '&', '|', '!'
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The subtreeSpecification string to parse
     * @param pos The position in the string
     * @return the parsed filter
     * @ParseException If the input was incorrect
     */
    private String parseFilter( boolean action, String spec, Position pos ) throws ParseException
    {
        int start = pos.start;
        
        /*
        while ( true )
        {
            char c = spec.charAt( pos.start );
        }
        */
        
        if ( action == PARSE )
        {
            return spec.substring( start, pos.start );
        }
        else
        {
            return null;
        }
    }
    
    /**
     * Parse the specification filter, following this grammar:
     * <pre>
     *   ss_specificationFilter =  ( SP )+  ( refinement |  filter )
     *   refinement = item | and | or | not
     *   item = ID_item ( SP )* COLON ( SP )* oid
     *   and = ID_and ( SP )* COLON ( SP )* refinements
     *   or = ID_or ( SP )* COLON ( SP )* refinements
     *   not = ID_not ( SP )* COLON ( SP )* refinement
     *   filter = '(' 
     *      ( 
     *          ( '&' (SP)* (filter)+ ) | 
     *          ( '|' (SP)* (filter)+ ) | 
     *          ( '!' (SP)* filter ) | 
     *          FILTER_VALUE 
     *      ) ')' (SP)* ;
     *   // Every char but '(', ')', '&', '|', '!'
     *   FILTER_VALUE : ( ')' | '(' | '&' | '|' | '!' ) ( ~(')') )*
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The subtreeSpecification string to parse
     * @param pos The position in the string
     * @param ssModifier The SubtreeSpecification modifier instance
     * @ParseException If the input was incorrect
     */
    private void parseSpecificationFilter( boolean action, String spec, Position pos,
            SubtreeSpecificationModifier ssModifier ) throws ParseException
    {
        // Skip mandatory spaces
        if ( !skipSpaces( spec, pos, ONE_N ) )
        {
            // error
            throw new ParseException( I18n.err( I18n.ERR_13905_REQUIRED_SPACE_SS_SPEC_FILTER ), pos.start );
        }
        
        // We have either a refinement or a filter
        String token = getToken( spec, pos );
        
        switch ( token )
        {
            case ID_ITEM:
                // item = ID_item ( SP )* COLON ( SP )* oid
                skipSpaces( spec, pos, ZERO_N );
                
                matchChar( spec, COLON, pos );
                
                // The oid
                String oid = parseOid( spec, pos );
                
                try
                {
                    // Check that the oid is valid
                    if ( schemaManager != null )
                    {
                        schemaManager.lookupObjectClassRegistry( oid );
                    }
                }
                catch ( LdapException le )
                {
                      // The oid does not exist
                    throw new ParseException( I18n.err( I18n.ERR_13906_SS_INVALID_ITEM, oid ), pos.start );
                }

                if ( action == PARSE )
                {
                    ExprNode node = new EqualityNode( objectClassAt, new Value( oid ) );

                    ssModifier.setRefinement( node );
                }
                
                return;
                
            case ID_AND:
                AndNode andNode = null;
                
                if ( action == PARSE )
                {
                    andNode = new AndNode();
                }
                
                parseAndOr( action, spec, pos, andNode );
                
                if ( action == PARSE )
                {
                    ssModifier.setRefinement( andNode );
                }

                return;

            case ID_OR:
                OrNode orNode = null;
                
                if ( action == PARSE )
                {
                    orNode = new OrNode();
                }
                
                parseAndOr( action, spec, pos, orNode );
                
                if ( action == PARSE )
                {
                    ssModifier.setRefinement( orNode );
                }

                return;

            case ID_NOT:
                NotNode notNode = null;
                
                if ( action == PARSE )
                {
                    new NotNode();
                }
                
                parseNot( action, spec, pos, notNode );
                
                if ( action == PARSE )
                {
                    ssModifier.setRefinement( notNode );
                }

                return;
                
            default:
                // The filter part is not implemented. It's not either 
                // part of the RFC 3672
                /*if ( isMatchChar( spec, LPAREN, pos ) )
                {
                    // A filter
                    String filter = parseFilter( spec, pos );
                    
                    try 
                    {
                        FilterParser.parse( filter );
                    } 
                    catch ( ParseException e ) 
                    {
                        // TODO Auto-generated catch block
                    }

                    System.out.println( "TODO" );
                }
                else
                {
                    // The specification filter end
                    return;
                }*/
                
                return;
        }
    }

    
    /**
     * Parse a substreeSpecification component, using this grammar:
     * 
     * <pre>
     * subtreeSpecificationComponent ::=
     *   ss_base | ss_specificExclusions | ss_minimum | ss_maximum | ss_specificationFilter
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The subtreeSpecification string to parse
     * @param pos The position in the string
     * @param ssModifier The SubtreeSpecification modifier instance
     * @ParseException If the input was incorrect
     */
    private void parseSubtreeSpecificationComponent( boolean action, String spec, Position pos, 
            SubtreeSpecificationModifier ssModifier ) throws ParseException
    {
        String token = getToken( spec, pos );
        
        switch ( token )
        {
            case ID_BASE:
                Dn base = parseBase( spec, pos );
                
                if ( action == PARSE )
                {
                    ssModifier.setBase( base );
                }
                
                return;
                
            case ID_SPECIFIC_EXCLUSIONS:
                // Parse the exclusions
                parseSpecificExclusions( action, spec, pos, ssModifier );
                
                return;

            case ID_MINIMUM:
                // The grammar for this component is:
                // <pre>ID_minimum ( SP )+ INTEGER</pre>
                // First skip spaces
                skipSpaces( spec, pos, ZERO_N );
                
                // Now parse an integer
                int minimum = parseInteger( spec, pos );
                
                if ( action == PARSE )
                {
                    ssModifier.setMinBaseDistance( minimum );
                }
                
                return;
                
            case ID_MAXIMUM:
                // The grammar for this component is:
                // <pre>ID_maximum ( SP )+ INTEGER</pre>
                // First skip spaces
                skipSpaces( spec, pos, ZERO_N );
                
                // Now parse an integer
                int maximum = parseInteger( spec, pos );
                
                if ( action == PARSE )
                {
                    ssModifier.setMaxBaseDistance( maximum );
                }
                
                return;
                
            case ID_SPECIFICATION_FILTER:
                parseSpecificationFilter( action, spec, pos, ssModifier );
                
                return;

            default:
                // Nothing more, get out
                return;
        }
    }
    
    
    /**
     * Parse a substreeSpecification, using this grammar:
     * 
     * <pre>
     * subtreeSpecificationComponent ::=
     *   ( SP )* OPEN_CURLY ( SP )*
     *     ( subtreeSpecificationComponent ( SP )*
     *         ( SEP ( SP )* subtreeSpecificationComponent ( SP )* )* )?
     *     CLOSE_CURLY
     *   ( SP )*
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The subtreeSpecification string to parse
     * @param pos The position in the string
     * @return A SubtreeSpecification instance
     * @ParseException If the input was incorrect
     */
    private SubtreeSpecification parse( boolean action, String spec, Position pos ) throws ParseException
    {
        // Get rid of spaces 
        spec = Strings.trim( spec );
        
        if ( Strings.isEmpty( spec ) )
        {
            return null;
        }
        
        
        SubtreeSpecificationModifier ssModifier = null;
        
        if ( action == PARSE )
        {
            ssModifier = new SubtreeSpecificationModifier();
        }

        // Must have an opening {
        matchChar( spec, LCURLY, pos );
        
        boolean isFirst = true;
        
        while ( true )
        {
            // Some more space removal
            skipSpaces( spec, pos, ZERO_N );

            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                // Check for the separator
                if ( !isMatchChar( spec, SEP, pos ) )
                {
                    // The end
                    break;
                }
                
                // Skip the spaces
                skipSpaces( spec, pos, ZERO_N );
            }
            
            parseSubtreeSpecificationComponent( action, spec, pos, ssModifier );
        }

        // Must have an closing }
        matchChar( spec, RCURLY, pos );
    
        if ( action == PARSE )
        {
            return ssModifier.getSubtreeSpecification();
        }
        else
        {
            return null;
        }
    }


    /**
     * Parses a subtree specification
     * 
     * @param spec the specification to be parsed
     * @return the specification bean
     * @throws ParseException if there are any recognition errors (bad syntax)
     */
    public SubtreeSpecification parse( String spec ) throws ParseException
    {
        if ( spec == null )
        {
            return null;
        }
        
        Position pos = new Position();
        pos.length = spec.length();
        
        return parse( PARSE, spec, pos );
    }


    /**
     * Check a subtree specification
     * 
     * @param spec the specification to be checked
     * @return <code>true</code> if the subtree specification is valid, <code>false</code> otherwise
     **/
    public boolean check( String spec )
    {
        if ( spec == null )
        {
            return true;
        }
        
        Position pos = new Position();
        pos.length = spec.length();
        
        try
        {
            parse( VALIDATE, spec, pos );
            
            return true;
        }
        catch ( ParseException pe )
        {
            return false;
        }
    }


    /**
     * Tests to see if this parser is normalizing.
     * 
     * @return true if it normalizes false otherwise
     */
    public boolean isNormilizing()
    {
        return this.isNormalizing;
    }
}
