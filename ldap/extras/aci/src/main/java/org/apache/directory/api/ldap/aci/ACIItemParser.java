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

package org.apache.directory.api.ldap.aci;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.aci.protectedItem.AttributeTypeItem;
import org.apache.directory.api.ldap.aci.protectedItem.AttributeValueItem;
import org.apache.directory.api.ldap.aci.protectedItem.ClassesItem;
import org.apache.directory.api.ldap.aci.protectedItem.MaxImmSubItem;
import org.apache.directory.api.ldap.aci.protectedItem.MaxValueCountElem;
import org.apache.directory.api.ldap.aci.protectedItem.MaxValueCountItem;
import org.apache.directory.api.ldap.aci.protectedItem.RangeOfValuesItem;
import org.apache.directory.api.ldap.aci.protectedItem.RestrictedByElem;
import org.apache.directory.api.ldap.aci.protectedItem.RestrictedByItem;
import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.FilterParser;
import org.apache.directory.api.ldap.model.filter.NotNode;
import org.apache.directory.api.ldap.model.filter.OrNode;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.normalizers.NameComponentNormalizer;
import org.apache.directory.api.ldap.model.subtree.SubtreeSpecification;
import org.apache.directory.api.ldap.model.subtree.SubtreeSpecificationModifier;
import org.apache.directory.api.util.NoDuplicateKeysMap;
import org.apache.directory.api.util.Position;
import org.apache.directory.api.util.StringConstants;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.apache.directory.api.util.ParserUtil.getToken;
import static org.apache.directory.api.util.ParserUtil.isMatchChar;
import static org.apache.directory.api.util.ParserUtil.hasMoreChars;
import static org.apache.directory.api.util.ParserUtil.matchChar;
import static org.apache.directory.api.util.ParserUtil.parseInteger;
import static org.apache.directory.api.util.ParserUtil.parseOid;
import static org.apache.directory.api.util.ParserUtil.parseQuotedSafeUtf8;
import static org.apache.directory.api.util.ParserUtil.skipSpaces;

import static org.apache.directory.api.util.ParserUtil.COLON;
import static org.apache.directory.api.util.ParserUtil.EQUAL;
import static org.apache.directory.api.util.ParserUtil.LCURLY;
import static org.apache.directory.api.util.ParserUtil.ONE_N;
import static org.apache.directory.api.util.ParserUtil.RCURLY;
import static org.apache.directory.api.util.ParserUtil.SEP;
import static org.apache.directory.api.util.ParserUtil.ZERO_N;

/**
 * A parser for an ACIItem as defined by X.501. T
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ACIItemParser
{
    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( ACIItemParser.class );
    
    /** The schema manager instance */
    private SchemaManager schemaManager;

    /** The is normalizing flag. */
    private final boolean isNormalizing;
    
    /** Flags to use to differentiate a parsing from a checking */
    private static final boolean PARSE = true;
    private static final boolean VALIDATE = false;

    /** The grammar tokens */
    private static final String ID_ALL_ATTRIBUTE_VALUES     = "allattributevalues";
    private static final String ID_ALL_USER_ATTRIBUTE_TYPES = "alluserattributetypes";
    private static final String ID_ALL_USER_ATTRIBUTE_TYPES_AND_VALUES  
                                                            = "alluserattributetypesandvalues";
    private static final String ID_ALL_USERS                = "allusers";
    private static final String ID_AND                      = "and";
    private static final String ID_ATTRIBUTE_TYPE           = "attributetype";
    private static final String ID_ATTRIBUTE_VALUE          = "attributevalue";
    private static final String ID_AUTHENTICATION_LEVEL     = "authenticationlevel";
    private static final String ID_BASE                     = "base";
    //private static final String ID_BASIC_LEVELS             = "basiclevels";
    private static final String ID_CHOP_AFTER               = "chopafter";
    private static final String ID_CHOP_BEFORE              = "chopbefore";
    private static final String ID_DENY_ADD                 = "denyadd";
    private static final String ID_DENY_BROWSE              = "denybrowse";
    private static final String ID_DENY_COMPARE             = "denycompare";
    private static final String ID_DENY_DISCLOSE_ON_ERROR   = "denydiscloseonerror";
    private static final String ID_DENY_EXPORT              = "denyexport";
    private static final String ID_DENY_FILTER_MATCH        = "denyfiltermatch";
    private static final String ID_DENY_IMPORT              = "denyimport";
    private static final String ID_DENY_INVOKE              = "denyinvoke";
    private static final String ID_DENY_MODIFY              = "denymodify";
    private static final String ID_DENY_READ                = "denyread";
    private static final String ID_DENY_REMOVE              = "denyremove";
    private static final String ID_DENY_RENAME              = "denyrename";
    private static final String ID_DENY_RETURN_DN           = "denyreturndn";
    private static final String ID_CLASSES                  = "classes";
    private static final String ID_ENTRY                    = "entry";
   // private static final String ID_FALSE                    = "false";
    //private static final String ID_LEVEL                    = "level";
    private static final String ID_GRANT_ADD                = "grantadd";
    private static final String ID_GRANT_BROWSE             = "grantbrowse";
    private static final String ID_GRANT_COMPARE            = "grantcompare";
    private static final String ID_GRANT_DISCLOSE_ON_ERROR  = "grantdiscloseonerror";
    private static final String ID_GRANT_EXPORT             = "grantexport";
    private static final String ID_GRANT_FILTER_MATCH       = "grantfiltermatch";
    private static final String ID_GRANT_IMPORT             = "grantimport";
    private static final String ID_GRANT_INVOKE             = "grantinvoke";
    private static final String ID_GRANT_MODIFY             = "grantmodify";
    private static final String ID_GRANT_READ               = "grantread";
    private static final String ID_GRANT_REMOVE             = "grantremove";
    private static final String ID_GRANT_RENAME             = "grantrename";
    private static final String ID_GRANT_RETURN_DN          = "grantreturndn";
    private static final String ID_GRANTS_AND_DENIALS       = "grantsanddenials";
    private static final String ID_IDENTIFICATION_TAG       = "identificationtag";
    private static final String ID_ITEM                     = "item";
    private static final String ID_ITEM_FIRST               = "itemfirst";
    private static final String ID_ITEM_OR_USER_FIRST       = "itemoruserfirst";
    private static final String ID_ITEM_PERMISSIONS         = "itempermissions";
    //private static final String ID_LOCAL_QUALIFIER          = "localqualifier";
    private static final String ID_MAX_COUNT                = "maxcount";
    private static final String ID_MAX_IMM_SUB              = "maximmsub";
    private static final String ID_MAXIMUM                  = "maximum";
    private static final String ID_MAX_VALUE_COUNT          = "maxvaluecount";
    private static final String ID_MINIMUM                  = "minimum";
    private static final String ID_NAME                     = "name";
    private static final String ID_NONE                     = "none";
    private static final String ID_NOT                      = "not";
    private static final String ID_OR                       = "or";
    private static final String ID_PARENT_OF_ENTRY          = "parentofentry";
    private static final String ID_PRECEDENCE               = "precedence";
    private static final String ID_PROTECTED_ITEMS          = "protecteditems";
    private static final String ID_RANGE_OF_VALUES          = "rangeofvalues";
    private static final String ID_RESTRICTED_BY            = "restrictedby";
    private static final String ID_SELF_VALUE               = "selfvalue";
    private static final String ID_SIMPLE                   = "simple";
    //private static final String ID_SIGNED                   = "signed";
    //private static final String ID_SPECIFICATION_FILTER     = "specificationfilter";
    private static final String ID_SPECIFIC_EXCLUSIONS      = "specificexclusions";
    private static final String ID_STRONG                   = "strong";
    private static final String ID_SUBTREE                  = "subtree";
    private static final String ID_THIS_ENTRY               = "thisentry";
    //private static final String ID_TRUE                     = "true";
    private static final String ID_TYPE                     = "type";
    private static final String ID_USER_CLASSES             = "userclasses";
    private static final String ID_USER_FIRST               = "userfirst";
    private static final String ID_USER_GROUP               = "usergroup";
    private static final String ID_USER_PERMISSIONS         = "userpermissions";
    private static final String ID_VALUES_IN                = "valuesin";

    
    /**
     * A internal class used to store the ACIItem creation result
     */
    private final class AciItemTuple
    {
        private Set<UserClass> userClasses;
        private Set<UserPermission> userPermissions;
        private Set<ProtectedItem> protectedItems;
        private Set<ItemPermission> itemPermissions;

        private AciItemTuple()
        {
        }
    }

    /**
     * Creates a ACIItem parser.
     *
     * @param schemaManager the schema manager
     */
    public ACIItemParser( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
        isNormalizing = false;
    }

    
    /**
     * Parse the subtree specification.
     * 
     * The grammar is:
     * <pre>
     * subtreeSpecification ::=
     *     OPEN_CURLY ( SP )*
     *         ( subtreeSpecificationComponent ( SP )* ( SEP ( SP )* subtreeSpecificationComponent ( SP )* )* )?
     *     CLOSE_CURLY
     *
     * // We can have only one of each
     * subtreeSpecificationComponent ::=
     *     ID_base ( SP )+ DN
     *     | 
     *     ID_specificExclusions ( SP )+ specificExclusions
     *     | 
     *     ID_minimum ( SP )+ INTEGER
     *     | 
     *     ID_maximum ( SP )+ INTEGER
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The list of refinements
     * @throws ParseException If the grant or denial is invalid
     */
    private SubtreeSpecification parseSubtreeSpecification( boolean action, String item, Position pos ) 
            throws ParseException
    {
        LOG.debug( "Parsing a subtreeSpecification: {}", pos );
        SubtreeSpecificationModifier ssModifier = null;
        
        if ( action == PARSE )
        {
            ssModifier = new SubtreeSpecificationModifier();
        }
        
        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        boolean isFirst = true;
        
        // A set of boolean used to avoid each of the component to be present more than once
        boolean baseSeen = false;
        boolean minimumSeen = false;
        boolean maximumSeen = false;
        boolean specificExclusionsSeen = false;
        
        while ( hasMoreChars( pos ) )
        {
            if ( isMatchChar( item, RCURLY, pos ) )
            {
                // The end. It can be empty
                // CLOSE_CURLY
                if ( action == PARSE )
                {
                    return ssModifier.getSubtreeSpecification();
                }
                else
                { 
                    return null;
                }
            }
            
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
            }
            
            // A subtreeSpecificationComponent token
            String token = getToken( item, pos );
            
            // ( SP )+
            if ( !skipSpaces( item, pos, ONE_N ) )
            {
                throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
            }

            // subtreeSpecificationComponent
            switch ( token )
            {
                case ID_BASE:
                    // ID_base
                    LOG.debug( "Parsing base: {}", pos );

                    if ( baseSeen )
                    {
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07019_SUBTREE_SPECIFICATION_BASE_SEEN, token ), pos.start );
                    }
                    else
                    {
                        baseSeen = true;
                    }
                    
                    // distinguishedName
                    Dn dn = parseDn( item, pos );
                    
                    if ( action == PARSE )
                    {
                        ssModifier.setBase( dn );
                    }
                    
                    break;
                    
                case ID_MINIMUM:
                    // ID_minimum
                    LOG.debug( "Parsing minimum: {}", pos );

                    if ( minimumSeen )
                    {
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07020_SUBTREE_SPECIFICATION_MINIMUM_SEEN, token ), pos.start );
                    }
                    else
                    {
                        minimumSeen = true;
                    }
                    
                    // integer
                    int minimum = parseInteger( item, pos );
                    
                    if ( action == PARSE )
                    {
                        ssModifier.setMinBaseDistance( minimum );
                    }
                    
                    break;
                    
                case ID_MAXIMUM:
                    // ID_maximum
                    LOG.debug( "Parsing maximum: {}", pos );

                    if ( maximumSeen )
                    {
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07021_SUBTREE_SPECIFICATION_MAXIMUM_SEEN, token ), pos.start );
                    }
                    else
                    {
                        maximumSeen = true;
                    }
                    
                    // integer
                    int maximum = parseInteger( item, pos );
                    
                    if ( action == PARSE )
                    {
                        ssModifier.setMaxBaseDistance( maximum );
                    }
                    
                    break;
                    
                case ID_SPECIFIC_EXCLUSIONS:
                    // ID_specificExclusions
                    LOG.debug( "Parsing a specificExclusion: {}", pos );

                    if ( specificExclusionsSeen )
                    {
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07022_SUBTREE_SPECIFICATION_EXCLUSIONS_SEEN, token ), pos.start );
                    }
                    else
                    {
                        specificExclusionsSeen = true;
                    }
                    
                    // specificExclusions
                    parseSpecificExclusions( action, item, pos, ssModifier );
                    
                    break;
                    
                default:
                    throw new ParseException( 
                            I18n.err( I18n.ERR_07018_BAD_SUBTREE_SPECIFICATION, token ), pos.start );
            }
            
            skipSpaces( item, pos, ZERO_N );
        }
        
        // We should never get there
        throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
    }
    
    
    /**
     * Parse a DN.
     * 
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The parsed DN
     * @throws ParseException If the DN is invalid
     */
    private Dn parseDn( String item, Position pos ) throws ParseException
    {
        LOG.debug( "Parsing a DN: {}", pos );

        String dnStr = parseQuotedSafeUtf8( item, pos );
        Dn dn = null;

        try
        {
            dn = new Dn( schemaManager, dnStr );
        }
        catch ( LdapInvalidDnException ldie )
        {
            // error
            throw new ParseException( I18n.err( I18n.ERR_13908_SS_INVALID_DN, dnStr ), pos.start );
        }

        return dn;
    }
    
    
    /**
     * Parse the specific exclusions.
     * 
     * The grammar is:
     * <pre>
     * specificExclusions ::=
     *     OPEN_CURLY ( SP )*
     *         ( specificExclusion ( SP )*
     *             ( SEP ( SP )* specificExclusion ( SP )* )*
     *         )?
     *     CLOSE_CURLY
     * 
     * specificExclusion ::=
     *     ID_chopBefore ( SP )* COLON ( SP )* DN | ID_chopAfter ( SP )* COLON ( SP )* DN
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The list of refinements
     * @throws ParseException If the grant or denial is invalid
     */
    private void parseSpecificExclusions( boolean action, String item, Position pos,
            SubtreeSpecificationModifier ssModifier ) throws ParseException
    {
        LOG.debug( "Parsing specificExclusions: {}", pos );

        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        boolean isFirst = true;
        
        if ( action == PARSE )
        {
            ssModifier.setChopBeforeExclusions( new HashSet<Dn>() );
            ssModifier.setChopAfterExclusions( new HashSet<Dn>() );
        }
        
        while ( hasMoreChars( pos ) )
        {
            if ( isMatchChar( item, RCURLY, pos ) )
            {
                // The end. It can be empty
                // CLOSE_CURLY
                return;
            }
            
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
            }
            
            String token = getToken( item, pos );
            
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );
            
            // COLON
            matchChar( item, COLON, pos );
            
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );

            // Check the DN
            // distinguishedName
            Dn dn = parseDn( item, pos );

            switch ( Strings.toLowerCaseAscii( token ) )
            {
                case ID_CHOP_BEFORE:
                    // ID_chopBefore
                    LOG.debug( "Parsing chopBefore: {}", pos );

                    if ( action == PARSE )
                    {
                        ssModifier.getSubtreeSpecification().getChopBeforeExclusions().add( dn );
                    }
                    
                    break;
                    
                case ID_CHOP_AFTER:
                    // ID_chopAfter
                    LOG.debug( "Parsing chopAfter: {}", pos );

                    if ( action == PARSE )
                    {
                        ssModifier.getSubtreeSpecification().getChopAfterExclusions().add( dn );
                    }
                    break;
                    
                default:
                    // Error
                    throw new ParseException( I18n.err( I18n.ERR_07017_BAD_SPECIFIC_EXCLUSION, token ), pos.start );
            }
            
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );
        }

        // Should never get there...
        throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );

    }
    
    
    /**
     * Parse the item for Grant and Denial following this grammar:
     * 
     * <pre>
     * grantAndDenial ::=
     *     ID_grantAdd
     *     | 
     *     ID_denyAdd
     *     | 
     *     ID_grantDiscloseOnError
     *     | 
     *     ID_denyDiscloseOnError
     *     | 
     *     ID_grantRead
     *     | 
     *     ID_denyRead
     *     | 
     *     ID_grantRemove
     *     | 
     *     ID_denyRemove 
     *     //-- permissions that may be used only in conjunction
     *     //-- with the entry component
     *     | 
     *     ID_grantBrowse
     *     |
     *     ID_denyBrowse 
     *     |
     *     ID_grantExport
     *     |
     *     ID_denyExport
     *     | 
     *     ID_grantImport
     *     | 
     *     ID_denyImport 
     *     | 
     *     ID_grantModify
     *     | 
     *     ID_denyModify 
     *     | 
     *     ID_grantRename
     *     | 
     *     ID_denyRename 
     *     | 
     *     ID_grantReturnDN
     *     | 
     *     ID_denyReturnDN 
     *     //-- permissions that may be used in conjunction
     *     //-- with any component, except entry, of ProtectedItems
     *     | 
     *     ID_grantCompare 
     *     | 
     *     ID_denyCompare
     *     | 
     *     ID_grantFilterMatch
     *     | 
     *     ID_denyFilterMatch 
     *     | 
     *     ID_grantInvoke 
     *     | 
     *     ID_denyInvoke
     * </pre>
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The GrantAndDenial instance
     * @throws ParseException If the grant or denial is invalid
     */
    private GrantAndDenial parseGrantAndDenial( String item, Position pos ) throws ParseException
    {
        String token = getToken( item, pos );
        LOG.debug( "Parsing a grantAndDenial: {], {}", token, pos );

        
        switch ( Strings.toLowerCaseAscii( token ) )
        {
            case ID_GRANT_ADD:
                return GrantAndDenial.GRANT_ADD;
                
            case ID_DENY_ADD:
                return GrantAndDenial.DENY_ADD;
                
            case ID_GRANT_DISCLOSE_ON_ERROR:
                return GrantAndDenial.GRANT_DISCLOSE_ON_ERROR;
                
            case ID_DENY_DISCLOSE_ON_ERROR:
                return GrantAndDenial.DENY_DISCLOSE_ON_ERROR;
                
            case ID_GRANT_READ:
                return GrantAndDenial.GRANT_READ;
                
            case ID_DENY_READ:
                return GrantAndDenial.DENY_READ;
                
            case ID_GRANT_REMOVE:
                return GrantAndDenial.GRANT_REMOVE;
                
            case ID_DENY_REMOVE:
                return GrantAndDenial.DENY_REMOVE;
                
            case ID_GRANT_BROWSE:
                return GrantAndDenial.GRANT_BROWSE;
                
            case ID_DENY_BROWSE:
                return GrantAndDenial.DENY_BROWSE;

            case ID_GRANT_EXPORT:
                return GrantAndDenial.GRANT_EXPORT;
                
            case ID_DENY_EXPORT:
                return GrantAndDenial.DENY_EXPORT;

            case ID_GRANT_IMPORT:
                return GrantAndDenial.GRANT_IMPORT;
                
            case ID_DENY_IMPORT:
                return GrantAndDenial.DENY_IMPORT;

            case ID_GRANT_MODIFY:
                return GrantAndDenial.GRANT_MODIFY;
                
            case ID_DENY_MODIFY:
                return GrantAndDenial.DENY_MODIFY;

            case ID_GRANT_RENAME:
                return GrantAndDenial.GRANT_RENAME;
                
            case ID_DENY_RENAME:
                return GrantAndDenial.DENY_RENAME;

            case ID_GRANT_RETURN_DN:
                return GrantAndDenial.GRANT_RETURN_DN;
                
            case ID_DENY_RETURN_DN:
                return GrantAndDenial.DENY_RETURN_DN;

            case ID_GRANT_COMPARE:
                return GrantAndDenial.GRANT_COMPARE;
                
            case ID_DENY_COMPARE:
                return GrantAndDenial.DENY_COMPARE;

            case ID_GRANT_FILTER_MATCH:
                return GrantAndDenial.GRANT_FILTER_MATCH;
                
            case ID_DENY_FILTER_MATCH:
                return GrantAndDenial.DENY_FILTER_MATCH;

            case ID_GRANT_INVOKE:
                return GrantAndDenial.GRANT_INVOKE;
                
            case ID_DENY_INVOKE:
                return GrantAndDenial.DENY_INVOKE;
                
            default:
                throw new ParseException( I18n.err( I18n.ERR_07013_UNKNOWN_GRANT_AND_DENIAL, token ), pos.start );
        }
    }

    
    /**
     * Parse a protectedItem
     * 
     * The grammar is:
     * <pre>
     * protectedItem ::=
     *     ID_entry
     *     | 
     *     ID_ allUserAttributeTypes
     *     | 
     *     ID_attributeType ( SP )+ attributeTypeSet
     *     | 
     *     ID_allAttributeValues ( SP )+ attributeTypeSet 
     *     | 
     *     ID_allUserAttributeTypesAndValues
     *     | 
     *     ATTRIBUTE_VALUE_CANDIDATE
     *     | 
     *     ID_selfValue ( SP )+ attributeTypeSet
     *     | 
     *     RANGE_OF_VALUES_CANDIDATE
     *     | 
     *     ID_maxValueCount ( SP )+
     *         OPEN_CURLY ( SP )*
     *             aMaxValueCount ( SP )* ( SEP ( SP )* aMaxValueCount ( SP )* )*
     *         CLOSE_CURLY
     *     | 
     *     ID_maxImmSub ( SP )+ INTEGER
     *     | 
     *     ID_restrictedBy ( SP )+
     *         OPEN_CURLY ( SP )*
     *             restrictedValue ( SP )* ( SEP ( SP )* restrictedValue ( SP )* )*
     *         CLOSE_CURLY
     *     | 
     *     ID_classes ( SP )+ refinement
     * </pre>
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The ProtectedItem
     * @throws ParseException If the grant or denial is invalid
     */
    private void parseProtectedItem( NoDuplicateKeysMap protectedItems, boolean action, String item, Position pos ) 
            throws ParseException
    {
        String token = Strings.toLowerCaseAscii( getToken( item, pos ) );
        LOG.debug( "Parsing a protecteItem: {}, {}", token, pos );
        
        try
        {
            switch ( token )
            {
                case ID_ENTRY:
                    // ID_entry
                    if ( action == PARSE )
                    {
                        protectedItems.put( ID_ENTRY, ProtectedItem.ENTRY );
                    }
                    
                    return;
                    
                case ID_ALL_USER_ATTRIBUTE_TYPES:
                    // ID_ allUserAttributeTypes
                    if ( action == PARSE )
                    {
                        protectedItems.put( ID_ALL_USER_ATTRIBUTE_TYPES, ProtectedItem.ALL_USER_ATTRIBUTE_TYPES );
                    }
                    
                    return;
    
                case ID_ATTRIBUTE_TYPE:         // fallback
                case ID_ALL_ATTRIBUTE_VALUES:   // fallback
                case ID_SELF_VALUE:
                    // ID_attributeType ( SP )+ attributeTypeSet
                    // ID_allAttributeValues ( SP )+ attributeTypeSet 
                    // ID_selfValue ( SP )+ attributeTypeSet
                    if ( !skipSpaces( item, pos, ONE_N ) )
                    {
                        throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                    }
                    
                    Set<AttributeType> attributeTypeSet = parseAttributeTypeSet( action, item, pos );
                    
                    if ( action == PARSE )
                    {
                        protectedItems.put( token, new AttributeTypeItem( attributeTypeSet ) );
                    }
                    
                    return;
                    
                case ID_ALL_USER_ATTRIBUTE_TYPES_AND_VALUES:
                    if ( action == PARSE )
                    {
                        protectedItems.put( ID_ALL_USER_ATTRIBUTE_TYPES_AND_VALUES, 
                                ProtectedItem.ALL_USER_ATTRIBUTE_TYPES_AND_VALUES );
                    }
                    
                    return;
                
                case ID_ATTRIBUTE_VALUE:
                    // ID_ATTRIBUTE_VALUE ( SP )*
                    // OPEN_CURLY 
                    //     ( SP )* ava ( SP )* ( SEP ( SP )* ava ( SP )* )*
                    // CLOSE_CURLY
                    // ava ::= oid ( SP )* attributeValue
                    // attributeValue ::= quotestring | string | hexstring
                    
                    // ( SP )+
                    skipSpaces( item, pos, ZERO_N );
                    
                    // OPEN_CURLY
                    matchChar( item, LCURLY, pos );
                    
                    boolean isFirst = true;
                    Set<Attribute> avas = null;
                    
                    if ( action == PARSE )
                    {
                        avas = new HashSet<>();
                    }
                    
                    while ( hasMoreChars( pos ) ) 
                    {
                        // ( SP )*
                        skipSpaces( item, pos, ZERO_N );
    
                        // CLOSE_CURLY
                        if ( isMatchChar( item, RCURLY, pos ) )
                        {
                            // The end
                            if ( action == PARSE )
                            {
                                protectedItems.put( ID_ATTRIBUTE_VALUE, new AttributeValueItem( avas ) );
                            }
                                
                            return;
                        }
                        
                        if ( isFirst )
                        {
                            isFirst = false;
                        }
                        else
                        {
                            // SEP
                            matchChar( item, SEP, pos );
                            
                            // ( SP )*
                            skipSpaces( item, pos, ZERO_N );
                        }
                        
                        // The attrubuteType
                        // oid
                        String name = parseOid( item, pos );
                        String value = null;
                        
                        Attribute attribute = null;
    
                        if ( schemaManager != null )
                        {
                            try
                            {
                                AttributeType attributeType = schemaManager.lookupAttributeTypeRegistry( name );
                                
                                attribute = new DefaultAttribute( attributeType, value );
                            }
                            catch ( LdapException le )
                            {
                                throw new ParseException( 
                                        I18n.err( I18n.ERR_07045_BAD_ATTRIBUTE_TYPE, name ), pos.start );
                            }
                        }
                        else
                        {
                            attribute = new DefaultAttribute( name );
                        }
    
                        
                        // EQUAL
                        matchChar( item, EQUAL, pos );
    
                        // The value. Can be anything up to a ',' or the closing '}'
                        int start = pos.start;
                        
                        while ( hasMoreChars( pos ) )
                        {
                            if ( isMatchChar( item, RCURLY, pos ) || isMatchChar( item, SEP, pos ) )
                            {
                                pos.start--;
                                value = item.substring( start, pos.start );
                                break;
                            }
                            else
                            {
                                pos.start++;
                            }
                        }
                        
                        if ( action == PARSE )
                        {
                            try
                            {
                                attribute.add( value );
                            
                                avas.add( attribute );
                            }
                            catch ( LdapInvalidAttributeValueException liave )
                            {
                                throw new ParseException( I18n.err( 
                                        I18n.ERR_07046_BAD_ATTRIBUTE_TYPE_OR_VALUE, name, value ), pos.start );
                            }
                        }
                    }
                    
                    // Error, we should have more
                    throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
    
                case ID_RANGE_OF_VALUES:
                    // ID_RANGE_OF_VALUES_CANDIDATE 
                    // ( SP )+ 
                    if ( !skipSpaces( item, pos, ONE_N ) )
                    {
                        throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                    }
                    
                    // filter
                    ExprNode filter = FilterParser.parse( schemaManager, item, pos );
                    
                    if ( action == PARSE )
                    {
                        protectedItems.put( ID_RANGE_OF_VALUES, new RangeOfValuesItem( filter ) );
                    }
                    
                    return;
                    
                case ID_MAX_VALUE_COUNT:
                    // ID_maxValueCount ( SP )*
                    //            aMaxValueCount ( SP )* ( SEP ( SP )* aMaxValueCount ( SP )* )*
                    //        CLOSE_CURLY
                    // ( SP )*
                    skipSpaces( item, pos, ZERO_N );
                    
                    // OPEN_CURLY
                    matchChar( item, LCURLY, pos );
                    
                    // ( SP )*
                    skipSpaces( item, pos, ZERO_N );
    
                    isFirst = true;
                    Set<MaxValueCountElem> maxValueCountSet = null;
                    
                    if ( action == PARSE )
                    {
                        maxValueCountSet = new HashSet<MaxValueCountElem>();
                    }
                    
                    while ( hasMoreChars( pos ) ) 
                    {
                        if ( isMatchChar( item, RCURLY, pos ) )
                        {
                            // CLOSE_CURLY
                            // The end
                            if ( action == PARSE )
                            {
                                protectedItems.put( ID_MAX_VALUE_COUNT, new MaxValueCountItem( maxValueCountSet ) );
                            }
                            
                            return;
                        }
                        
                        if ( isFirst )
                        {
                            isFirst = false;
                        }
                        else
                        {
                            // SEP
                            matchChar( item, SEP, pos );
                            
                            // ( SP )*
                            skipSpaces( item, pos, ZERO_N );
                        }
                        
                        // aMaxValueCount
                        MaxValueCountElem maxValueCount = parseMaxValueCount( action, item, pos );
                        
                        if ( action == PARSE )
                        {
                            maxValueCountSet.add( maxValueCount );
                        }
                        
                        // ( SP )*
                        skipSpaces( item, pos, ZERO_N );
                    }
                    
                    // Error, we should have more
                    throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
    
                case ID_MAX_IMM_SUB:
                    // ID_maxImmSub
                    // ( SP )+
                    if ( !skipSpaces( item, pos, ONE_N ) )
                    {
                        throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                    }
                    
                    // NTEGER
                    int maxImmSub = parseInteger( item, pos );
                    
                    if ( action == PARSE )
                    {
                        protectedItems.put( ID_MAX_IMM_SUB, new MaxImmSubItem( maxImmSub ) );
                    }
                    
                    return;
                    
                case ID_RESTRICTED_BY:
                    // ID_restrictedBy 
                    // ( SP )*
                    skipSpaces( item, pos, ZERO_N );
                    
                    // OPEN_CURLY
                    matchChar( item, LCURLY, pos );
                    
                    // ( SP )*
                    skipSpaces( item, pos, ZERO_N );
    
                    isFirst = true;
                    Set<RestrictedByElem> restrictedBy = null;
                    
                    if ( action == PARSE )
                    {
                        restrictedBy = new HashSet<RestrictedByElem>();
                    }
                    
                    while ( hasMoreChars( pos ) ) 
                    {
                        if ( isMatchChar( item, RCURLY, pos ) )
                        {
                            // CLOSE_CURLY
                            // The end
                            if ( action == PARSE )
                            {
                                protectedItems.put( ID_RESTRICTED_BY, new RestrictedByItem( restrictedBy ) );
                            }
                            
                            return;
                        }
                        
                        if ( isFirst )
                        {
                            isFirst = false;
                        }
                        else
                        {
                            // SEP
                            matchChar( item, SEP, pos );
                            
                            // ( SP )* 
                            skipSpaces( item, pos, ZERO_N );
                        }
    
                        // restrictedValue
                        RestrictedByElem restrictedValue = parseRestrictedValue( action, item, pos );
                        
                        if ( action == PARSE )
                        {
                            restrictedBy.add( restrictedValue );
                        }
    
                        // ( SP )* 
                        skipSpaces( item, pos, ZERO_N );
                    }
                    
                    // Error, we should have more
                    throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
    
                case ID_CLASSES:
                    // ID_classes 
                    // ( SP )+
                    if ( !skipSpaces( item, pos, ONE_N ) )
                    {
                        throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                    }
    
                    // refinement
                    ExprNode refinement = parseRefinement( action, item, pos );
                    
                    if ( action == PARSE )
                    {
                        protectedItems.put( ID_CLASSES, new ClassesItem( refinement ) );
                    }
                    
                    return;
                    
                default:
                    throw new ParseException( I18n.err( I18n.ERR_07033_UNKNOWN_PROTECTED_ITEM, token ), pos.start );
            }
        }
        catch ( IllegalArgumentException e )
        {
            throw new ParseException( I18n.err( I18n.ERR_07007_DUPLICATED_PROTECTED_ITEM, token ), pos.start );
        }
    }

    
    /**
     * Parse the protectedItems
     * 
     * The grammar is:
     * <pre>
     * protectedItems ::=
     *     [ID_protectedItems] ( SP )*
     *     OPEN_CURLY ( SP )*
     *     ( 
     *         protectedItem ( SP )* ( SEP ( SP )* protectedItem ( SP )* )*
     *     )?
     *     CLOSE_CURLY
     * </pre>
     * 
     * Note: The <b>ID_protectedItems</b> token has already been processed.
     * 
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The ProectedItem set set
     * @throws ParseException If the grant or denial is invalid
     */
    private Set<ProtectedItem> parseProtectedItems( boolean action, String item, Position pos ) throws ParseException
    {
        LOG.debug( "Parsing protecteItems: {}", pos );

        // The ID_protectedItems token has already been read by the caller function
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );

        boolean isFirst = true;
        
        NoDuplicateKeysMap protectedItems = null;
        
        if ( action == PARSE )
        {
            protectedItems = new NoDuplicateKeysMap();
        }
        
        while ( hasMoreChars( pos ) )
        {
            // CLOSE_CURLY
            if ( isMatchChar( item, RCURLY, pos ) )
            {
                // The end
                if ( action == PARSE )
                {
                    return new HashSet<ProtectedItem>( protectedItems.values() );
                }
                else
                {
                    return null;
                }
            }

            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
            }
            
            // protectedItem
            parseProtectedItem( protectedItems, action, item, pos );
            
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );
        }
        
        // We should never get there
        throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
    }

    
    /**
     * Parse the multiple possible grants and denials.
     * 
     * The grammar is:
     * <pre>
     * grantsAndDenials ::=
     *     ID_grantsAndDenials ( SP )*
     *     OPEN_CURLY ( SP )*
     *     ( 
     *         grantAndDenial ( SP )*
     *         ( SEP ( SP )* grantAndDenial ( SP )* )*
     *     )?
     *     CLOSE_CURLY
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The GrantAndDenial set
     * @throws ParseException If the grant or denial is invalid
     */
    private Set<GrantAndDenial> parseGrantAndDenials( boolean action, String item, Position pos ) 
            throws ParseException
    {
        LOG.debug( "Parsing grantAndDenials: {}", pos );

        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        // OPEN_CURLY 
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );

        boolean isFirst = true;
        
        Set<GrantAndDenial> grantsAndDenials = null;
        
        if ( action == PARSE )
        {
            grantsAndDenials = new HashSet<>();
        }
        
        while ( hasMoreChars( pos ) )
        {
            if ( isMatchChar( item, RCURLY, pos ) )
            {
                // CLOSE_CURLY
                // The end
                return grantsAndDenials;
            }
            
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
            }
            
            // grantAndDenial
            GrantAndDenial grantAndDenial = parseGrantAndDenial( item, pos );
            
            if ( action == PARSE )
            {
                if ( !grantsAndDenials.add( grantAndDenial ) )
                {
                    throw new ParseException( 
                            I18n.err( I18n.ERR_07010_DUPLICATED_GRANT_AND_DENIAL, grantAndDenial ), pos.start );
                }
            }
            
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );
        }
        
        // We should never get there
        throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
    }

   
    /**
     * Parse the refinements.
     * 
     * The grammar is:
     * <pre>
     * refinements ::=
     *     OPEN_CURLY ( SP )*
     *     (
     *         refinement ( SP )*
     *         ( SEP ( SP )* refinement ( SP )* )*
     *     )? CLOSE_CURLY
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The list of refinements
     * @throws ParseException If the grant or denial is invalid
     */
    private List<ExprNode> parseRefinements( boolean action, String item, Position pos ) throws ParseException
    {
        LOG.debug( "Parsing refinements: {}", pos );

        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        boolean isFirst = true;
        List<ExprNode> refinements = null;
        
        if ( action == PARSE )
        {
            refinements = new ArrayList<>();
        }
        
        while ( hasMoreChars( pos ) )
        {
            if ( isMatchChar( item, RCURLY, pos ) )
            {
                // The end. It can be empty
                // CLOSE_CURLY
                return refinements;
            }
            
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
            }
            
            // refinement
            ExprNode refinement = parseRefinement( action, item, pos );
            
            if ( action == PARSE )
            {
                refinements.add( refinement );
            }
            
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );
        }
        
        // This is an error: we need a closing '}'
        throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
    }

    
    /**
     * Parse a refinement.
     * 
     * The grammar is:
     * <pre>
     * refinement ::=
     *     ID_item ( SP )* COLON ( SP )* oid
     *     | 
     *     ID_and ( SP )* COLON ( SP )* refinements 
     *     | 
     *     ID_or ( SP )* COLON ( SP )* refinements 
     *     | 
     *     ID_not ( SP )* COLON ( SP )* refinement
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The ExprNode representing the refinement
     * @throws ParseException If the refinement is invalid
     */
    private ExprNode parseRefinement( boolean action, String item, Position pos ) throws ParseException
    {
        String token = getToken( item, pos );
        LOG.debug( "Parsing a refinement: {}, {}", token, pos );

        ExprNode node = null;
        
        switch ( Strings.toLowerCaseAscii( token ) )
        {
            case ID_ITEM:
                // ID_item
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
                
                // COLON
                matchChar( item, COLON, pos );
                
                // oid
                String oid = parseOid( item, pos );

                if ( action == PARSE )
                {
                    node = new EqualityNode<>( SchemaConstants.OBJECT_CLASS_AT, oid );
                }
                
                break;
                
            case ID_AND:
                // ID_and
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
                
                // COLON
                matchChar( item, COLON, pos );

                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
                
                List<ExprNode> andChildren = parseRefinements( action, item, pos );

                if ( action == PARSE )
                {
                    node = new AndNode( andChildren );
                }
                
                break;
                
            case ID_OR:
                // ID_or
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
                
                // COLON
                matchChar( item, COLON, pos );

                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
                
                List<ExprNode> orChildren = parseRefinements( action, item, pos );

                if ( action == PARSE )
                {
                    node = new OrNode( orChildren );
                }
                
                break;
                
            case ID_NOT:
                // ID_not
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
                
                // COLON
                matchChar( item, COLON, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
                
                // refinement
                ExprNode child = parseRefinement( action, item, pos );

                if ( action == PARSE )
                {
                    node = new NotNode( child );
                }
                
                break;
                
            default:
                throw new ParseException( I18n.err( I18n.ERR_07016_BAD_REFINEMENT, token ), pos.start );
        }
        
        return node;
    }

    
    /**
     * Parse a maxValueCount.
     * 
     * The grammar is:
     * <pre>
     * aMaxValueCount ::=
     *     OPEN_CURLY ( SP )*
     *     (
     *         ID_type ( SP )+ oid ( SP )* SEP ( SP )* ID_maxCount ( SP )+ INTEGER
     *         | 
     *         ID_maxCount ( SP )+ INTEGER ( SP )* SEP ( SP )* ID_type ( SP )+ oid 
     *     ) ( SP )*
     *     CLOSE_CURLY
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The max value count instance
     * @throws ParseException If the refinement is invalid
     */
    private MaxValueCountElem parseMaxValueCount( boolean action, String item, Position pos ) throws ParseException
    {
        LOG.debug( "Parsing a maxValueCount: {}", pos );

        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        String token = getToken( item, pos );
        String oid = null;
        int count = 0;
        
        switch ( Strings.toLowerCaseAscii( token ) )
        {
            case ID_TYPE:
                // ID_type
                LOG.debug( "Parsing a type: {}", pos );

                // ( SP )+
                if ( !skipSpaces( item, pos, ONE_N ) )
                {
                    throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                }
                
                // oid
                oid = parseOid( item, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
                
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );

                // ID_maxCount
                token = getToken( item, pos );
                
                if ( !ID_MAX_COUNT.equals( Strings.toLowerCaseAscii( token ) ) )
                {
                    throw new ParseException( I18n.err( I18n.ERR_07023_MAX_COUNT_TOKEN_EXPECTED, token ), pos.start );
                }
                
                // ( SP )+
                if ( !skipSpaces( item, pos, ONE_N ) )
                {
                    throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                }
                
                // INTEGER
                count = parseInteger( item, pos );
                
                break;
                
            case ID_MAX_COUNT:
                // ID_maxCount
                LOG.debug( "Parsing a maxCount: {}", pos );

                // ( SP )+ 
                if ( !skipSpaces( item, pos, ONE_N ) )
                {
                    throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                }
                
                // INTEGER
                count = parseInteger( item, pos );

                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
                
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );

                // ID_type
                token = getToken( item, pos );
                
                if ( !ID_TYPE.equals( Strings.toLowerCaseAscii( token ) ) )
                {
                    throw new ParseException( I18n.err( I18n.ERR_07026_TYPE_TOKEN_EXPECTED, token ), pos.start );
                }
                
                // ( SP )+ 
                if ( !skipSpaces( item, pos, ONE_N ) )
                {
                    throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                }
                
                // oid
                oid = parseOid( item, pos );
                
                break;
                
            default:
                throw new ParseException( I18n.err( I18n.ERR_07025_EXPECTED_MAX_COUNT_OR_TYPE, token ), pos.start );
        }
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        // CLOSE_CURLY
        matchChar( item, RCURLY, pos );
        
        if ( action == PARSE )
        {
            try 
            {
                AttributeType attributeType = null;
                
                if ( schemaManager != null )
                {
                    attributeType = schemaManager.lookupAttributeTypeRegistry( oid );
                }
                else
                {
                    attributeType = new AttributeType( oid );
                }
                
                MaxValueCountElem maxValueCount = new MaxValueCountElem( attributeType, count );
                
                return maxValueCount;
            } 
            catch ( LdapException e ) 
            {
                throw new ParseException( 
                        I18n.err( I18n.ERR_07024_MAX_COUNT_MISSING_ATTRIBUTE_TYPE, oid ), pos.start );
            }
        }
        else
        {
            return null;
        }
    }

    
    /**
     * Parse a restrictedValue.
     * 
     * The grammar is:
     * <pre>
     * restrictedValue ::=
     *     OPEN_CURLY ( SP )*
     *     (
     *         ID_type ( SP )+ oid ( SP )* SEP ( SP )* ID_valuesIn ( SP )+ oid
     *         | 
     *         ID_valuesIn ( SP )+ oid ( SP )* SEP ( SP )* ID_type ( SP )+ oid
     *     ) ( SP )*
     *     CLOSE_CURLY
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The restrictedValue instance
     * @throws ParseException If the refinement is invalid
     */
    private RestrictedByElem parseRestrictedValue( boolean action, String item, Position pos ) throws ParseException
    {
        LOG.debug( "Parsing a restrictedValue: {}", pos );

        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        String token = getToken( item, pos );
        String typeOid = null;
        String valuesInOid = null;
        
        switch ( Strings.toLowerCaseAscii( token ) )
        {
            // ID_type
            case ID_TYPE:
                LOG.debug( "Parsing a type: {}", pos );

                // ( SP )+
                if ( !skipSpaces( item, pos, ONE_N ) )
                {
                    throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                }
                
                // oid
                typeOid = parseOid( item, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
                
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );

                // ID_valuesIn
                token = getToken( item, pos );
                
                if ( !ID_VALUES_IN.equals( Strings.toLowerCaseAscii( token ) ) )
                {
                    throw new ParseException( I18n.err( I18n.ERR_07027_VALUES_IN_TOKEN_EXPECTED, token ), pos.start );
                }
                
                // ( SP )+
                if ( !skipSpaces( item, pos, ONE_N ) )
                {
                    throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                }
                
                // oid
                valuesInOid = parseOid( item, pos );
                
                break;
                
            case ID_VALUES_IN:
                // ID_valuesIn
                LOG.debug( "Parsing valuesIn: {}", pos );

                // ( SP ) +
                if ( !skipSpaces( item, pos, ONE_N ) )
                {
                    throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                }
                
                // oid
                valuesInOid = parseOid( item, pos );

                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
                
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );

                // ID_type
                token = getToken( item, pos );
                
                if ( !ID_TYPE.equals( Strings.toLowerCaseAscii( token ) ) )
                {
                    throw new ParseException( I18n.err( I18n.ERR_07026_TYPE_TOKEN_EXPECTED, token ), pos.start );
                }
                
                // ( SP )+
                if ( !skipSpaces( item, pos, ONE_N ) )
                {
                    throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                }
                
                // oid
                typeOid = parseOid( item, pos );
                
                break;
                
            default:
                throw new ParseException( I18n.err( I18n.ERR_07030_EXPECTED_VALUES_IN_OR_TYPE, token ), pos.start );
        }
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        // CLOSE_CURLY
        matchChar( item, RCURLY, pos );
        
        if ( action == PARSE )
        {
            AttributeType attributeType = null;
            AttributeType valuesInAttributeType = null;

            // The type attribute
            try 
            {
                if ( schemaManager != null )
                {
                    attributeType = schemaManager.lookupAttributeTypeRegistry( typeOid );
                }
                else
                {
                    attributeType = new AttributeType( typeOid );
                }
                
            } 
            catch ( LdapException e ) 
            {
                throw new ParseException( I18n.err( I18n.ERR_07028_TYPE_INVALID_ATTRIBUTE, typeOid ), pos.start );
            }
            
            // Th evaluesIn attribute
            try 
            {
                if ( schemaManager != null )
                {
                    valuesInAttributeType = schemaManager.lookupAttributeTypeRegistry( valuesInOid );
                }
                else
                {
                    valuesInAttributeType = new AttributeType( valuesInOid );
                }
            } 
            catch ( LdapException e ) 
            {
                throw new ParseException( 
                        I18n.err( I18n.ERR_07029_VALUES_IN_INVALID_ATTRIBUTE, valuesInOid ), pos.start );
            }
            
            if ( action == PARSE )
            {
                RestrictedByElem restrictedValue = new RestrictedByElem( attributeType, valuesInAttributeType );
            
                return restrictedValue;
            }
            else
            {
                return null;
            }
        }
        else
        {
            return null;
        }
    }

    /**
     * Parse a set of DNs.
     * 
     * The grammar is:
     * <pre>
     * DNs ::=
     * ( SP )* 
     *     OPEN_CURLY ( SP )*
     *         distinguishedName ( SP )* ( SEP ( SP )* distinguishedName ( SP )* )*
     *     CLOSE_CURLY
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The set of DNs found
     * @throws ParseException If the aciitem is invalid
     */
    private Set<String> parseDNs( boolean action, String item, Position pos ) throws ParseException
    {
        LOG.debug( "Parsing DNs: {}", pos );

        Set<String> names = new HashSet<>();
        boolean isFirst = true;
        
        // ( SP )* 
        skipSpaces( item, pos, ZERO_N );
        
        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        while ( hasMoreChars( pos ) )
        {
            if ( isMatchChar( item, RCURLY, pos ) )
            {
                // The end. It can be empty
                // CLOSE_CURLY
                if ( action == PARSE )
                {
                    return names;
                }
                else
                { 
                    return null;
                }
            }
            
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
            }
            
            
            // distinguishedName
            Dn dn = parseDn( item, pos );
            
            if ( action == PARSE )
            {
                names.add( dn.getNormName() );
            }
            
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );
        }

        // We should never get there
        throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
    }
    
    
    /**
     * Parse a user class.
     * 
     * The grammar is:
     * <pre>
     * userClass ::=
     *     ID_allUsers
     *     |
     *     ID_thisEntry
     *     |
     *     ID_parentOfEntry
     *     |
     *     ID_name ( SP )*
     *         OPEN_CURLY ( SP )*
     *             distinguishedName ( SP )* ( SEP ( SP )* distinguishedName ( SP )* )*
     *         CLOSE_CURLY
     *     |
     *     ID_userGroup ( SP )*
     *         OPEN_CURLY ( SP )*
     *             distinguishedName ( SP )* ( SEP ( SP )* distinguishedName ( SP )* )*
     *         CLOSE_CURLY
     *     |
     *     ID_subtree ( SP )*
     *         OPEN_CURLY ( SP )*
     *             subtreeSpecification (SP)* ( SEP (SP)* subtreeSpecification (SP)* )*
     *         CLOSE_CURLY
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The userPermission instance
     * @throws ParseException If the aciitem is invalid
     */
    private void parseUserClass( NoDuplicateKeysMap userClasses, boolean action, String item, Position pos ) 
            throws ParseException
    {
        String token = getToken(  item, pos );
        LOG.debug( "Parsing a userClass: {}, {}", token, pos );


        try 
        {
            switch ( Strings.toLowerCaseAscii( token ) )
            {
                case ID_ALL_USERS:
                    // ID_allUsers
                    if ( action == PARSE )
                    {
                        userClasses.put( token, UserClass.ALL_USERS );
                    }
                    
                    break;
                    
                case ID_THIS_ENTRY:
                    // ID_thisEntry
                    if ( action == PARSE )
                    {
                        userClasses.put( token, UserClass.THIS_ENTRY );
                    }
                    
                    break;
                    
                case ID_PARENT_OF_ENTRY:
                    // ID_parentOfEntry
                    if ( action == PARSE )
                    {
                        userClasses.put( token, UserClass.PARENT_OF_ENTRY );
                    }
                    
                    break;
                    
    
                case ID_NAME:
                    /*
                     * ID_name ( SP )*
                     *     OPEN_CURLY ( SP )*
                     *         distinguishedName ( SP )* ( SEP ( SP )* distinguishedName ( SP )* )*
                     *     CLOSE_CURLY
                     */
                    // ID_name
                    // ( SP )*
                    skipSpaces( item, pos, ZERO_N );
    
                    Set<String> names = parseDNs( action, item, pos );

                    if ( action == PARSE )
                    {
                        userClasses.put( token, new UserClass.Name( names ) );
                    }
                    
                    break;
    
                case ID_USER_GROUP:
                    /*
                     * ID_userGroup ( SP )*
                     *     OPEN_CURLY ( SP )*
                     *         distinguishedName ( SP )* ( SEP ( SP )* distinguishedName ( SP )* )*
                     *     CLOSE_CURLY
                     */
                    // ID_userGroup
                    // ( SP )*
                    skipSpaces( item, pos, ZERO_N );

                    Set<String> group = parseDNs( action, item, pos );
                    
                    if ( action == PARSE )
                    {
                        userClasses.put( token, new UserClass.UserGroup( group ) );
                    }
                    
                    break;
    
                case ID_SUBTREE:
                    /*
                     * ID_subtree ( SP )*
                     *     OPEN_CURLY ( SP )*
                     *         subtreeSpecification (SP)* ( SEP (SP)* subtreeSpecification (SP)* )*
                     *     CLOSE_CURLY
                     */
                    // ID_subtree
                    Set<SubtreeSpecification> subtrees = null;
                    
                    if ( action == PARSE )
                    {
                        subtrees = new HashSet<>();
                    }
                    
                    boolean isFirst = true;
                    
                    // ( SP )*
                    skipSpaces( item, pos, ZERO_N );
                    
                    // OPEN_CURLY
                    matchChar( item, LCURLY, pos );
                    
                    // ( SP )*
                    skipSpaces( item, pos, ZERO_N );
                    
                    while ( hasMoreChars( pos ) )
                    {
                        if ( isMatchChar( item, RCURLY, pos ) )
                        {
                            // CLOSE_CURLY
                            // The end. It can be empty
                            if ( action == PARSE )
                            {
                                userClasses.put( token, new UserClass.Subtree( subtrees ) );
                            }
                            
                            return;
                        }
                        
                        if ( isFirst )
                        {
                            isFirst = false;
                        }
                        else
                        {
                            // SEP
                            matchChar( item, SEP, pos );
                            
                            // ( SP )*
                            skipSpaces( item, pos, ZERO_N );
                        }
                        
                        // subtreeSpecification
                        SubtreeSpecification subtree = parseSubtreeSpecification( action, item, pos );
                        
                        if ( action == PARSE )
                        {
                            subtrees.add( subtree );
                        }
                        
                        // ( SP )*
                        skipSpaces( item, pos, ZERO_N );
                    }
    
                    // We should never get there
                    throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
    
                default:
                    throw new ParseException( I18n.err( I18n.ERR_07037_BAD_USER_CLASS, token ), pos.start );
            }
        }
        catch ( IllegalArgumentException e )
        {
            throw new ParseException( I18n.err( I18n.ERR_07011_DUPLICATED_USER_CLASSES, token ), pos.start );
        }
    }

    
    /**
     * Parse item permissions.
     * 
     * The grammar is:
     * <pre>
     * itemPermissions ::=
     *     [ID_itemPermissions] ( SP )+
     *         OPEN_CURLY ( SP )*
     *             ( itemPermission ( SP )* ( SEP ( SP )* itemPermission ( SP )* )* )?
     *         CLOSE_CURLY
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The itemPermission instance
     * @throws ParseException If the aciitem is invalid
     */
    private Set<ItemPermission> parseItemPermissions( boolean action, String item, Position pos ) 
            throws ParseException
    {
        LOG.debug( "Parsing itemPermissions: {}", pos );

        Set<ItemPermission> itemPermissions = null;
        
        // ID_itemPermissions
        String token = getToken( item, pos );
        
        if ( !ID_ITEM_PERMISSIONS.equalsIgnoreCase( token ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_07031_MISSING_ITEM_PERMISSIONS_TOKEN, token ), pos.start );
        }

        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        boolean isFirst = true;
        
        if ( action == PARSE )
        {
            itemPermissions = new HashSet<ItemPermission>();
        }
        
        while ( hasMoreChars( pos ) )
        {
            // CLOSE_CURLY
            if ( isMatchChar( item, RCURLY, pos ) )
            {
                // The end. It can be empty
                return itemPermissions;
            }
            
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
            }
            
            // itemPermission
            ItemPermission itemPermission = parseItemPermission( action, item, pos );
            
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );

            if ( action == PARSE )
            {
                itemPermissions.add( itemPermission );
            }
        }

        // We should never get there
        throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
    }

    
    /**
     * Parse an item permission.
     * 
     * The grammar is:
     * <pre>
     * ItemPermission ::=
     *     OPEN_CURLY ( SP )*
     *         ID_precedence ( SP )+ INTEGER ( SP )* SEP ( SP )*
     *             userClasses ( SP )* SEP ( SP )*
     *             ID_grantsAndDenials grantsAndDenials ( SP )* 
     *         |
     *         userClasses ( SP )* SEP ( SP )*
     *             ID_grantsAndDenials grantsAndDenials ( SP )* 
     *     CLOSE_CURLY        
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The itemPermission instance
     * @throws ParseException If the aciitem is invalid
     */
    private ItemPermission parseItemPermission( boolean action, String item, Position pos ) throws ParseException
    {
        LOG.debug( "Parsing a itemPermission: {}", pos );

        ItemPermission itemPermission = null;
        int precedence = 0;
        Set<UserClass> userClass = null;
        Set<GrantAndDenial> grantAndDenials = null;
        boolean precedenceSeen = false;
        boolean userClassSeen = false;
        boolean grantsAndDenialsSeen = false;
        boolean isFirstPermission = true;

        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        while ( !isMatchChar( item, RCURLY, pos ) )
        {
            if ( isFirstPermission )
            {
                isFirstPermission = false;
            }
            else
            {
                // Skip the SEP and ( SP )*
                matchChar( item, SEP, pos );

                // ( SP )* 
                skipSpaces( item, pos, ZERO_N );
            }

            String token = getToken(  item, pos );
            
            switch ( Strings.toLowerCaseAscii( token ) )
            {
                case ID_PRECEDENCE:
                    LOG.debug( "Parsing itemPermission's precedence: {}", pos );

                    if ( precedenceSeen )
                    {
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07049_PRECEDENCE_ALREADY_SEEN, token ), pos.start );
                    }
                    
                    // Ok, check the precedence then
                    // ( SP )+
                    if ( !skipSpaces( item, pos, ONE_N ) )
                    {
                        throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                    }
                    
                    // INTEGER
                    precedence = parseInteger( item, pos );
                    precedenceSeen = true;
                    
                    break;

                case ID_USER_CLASSES:
                    LOG.debug( "Parsing itemPermission's userClass: {}", pos );

                    if ( userClassSeen )
                    {
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07057_USER_CLASSES_ALREADY_SEEN, token ), pos.start );
                    }

                    // userClasses
                    userClass = parseUserClasses( action, item, pos );
                    userClassSeen = true;
                    
                    break;

                case ID_GRANTS_AND_DENIALS:
                    LOG.debug( "Parsing itemPermission's grantsAndDenials: {}", pos );

                    if ( grantsAndDenialsSeen )
                    {
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07056_GRANTS_AND_DENIALS_ALREADY_SEEN, token ), pos.start );
                    }

                    // grantsAndDenials
                    grantAndDenials = parseGrantAndDenials( action, item, pos );
                    grantsAndDenialsSeen = true;
                    break;
                    
                default:
                    // This is an error, we must have a set of grants and denials
                    if ( !userClassSeen ) 
                    {
                        // This is an error, we must have a userClasses token
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07047_MISSING_USER_CLASSES_TOKEN, token ), pos.start );
                    }
                    
                    if ( !grantsAndDenialsSeen )
                    {
                        // This is an error, we must have a set of grants and denials
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07035_MISSING_GRANTS_AND_DENIALS, token ), pos.start );
                    }
                    
                    break;
            }
            
            skipSpaces( item, pos, ZERO_N );
        }
        
        if ( !userClassSeen ) 
        {
            // This is an error, we must have a userClasses token
            throw new ParseException( I18n.err( I18n.ERR_07047_MISSING_USER_CLASSES_TOKEN ), pos.start );
        }
        
        if ( !grantsAndDenialsSeen )
        {
            // This is an error, we must have a set of grants and denials
            throw new ParseException( I18n.err( I18n.ERR_07035_MISSING_GRANTS_AND_DENIALS ), pos.start );
        }

        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
            
        if ( action == PARSE )
        {
            itemPermission = new ItemPermission( precedence, grantAndDenials, userClass );
        }
        
        return itemPermission;
    }

    

    
    /**
     * Parse a user permission.
     * 
     * The grammar is:
     * <pre>
     * UserPermission ::=
     *     OPEN_CURLY ( SP )*
     *         ID_precedence ( SP )+ INTEGER ( SP )* SEP ( SP )*
     *             ID_protectedItems protectedItems ( SP )* SEP ( SP )*
     *             ID_grantsAndDenials grantsAndDenials ( SP )* 
     *         |
     *         ID_protectedItems protectedItems ( SP )* SEP ( SP )*
     *             ID_grantsAndDenials grantsAndDenials ( SP )* 
     *     CLOSE_CURLY        
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return The userPermission instance
     * @throws ParseException If the aciitem is invalid
     */
    private UserPermission parseUserPermission( boolean action, String item, Position pos ) throws ParseException
    {
        LOG.debug( "Parsing a userPermission: {}", pos );

        UserPermission userPermission = null;
        Integer precedence = null;
        Set<ProtectedItem> protectedItems = null;
        Set<GrantAndDenial> grantAndDenials = null;
        boolean precedenceSeen = false;
        boolean protectedItemsSeen = false;
        boolean grantsAndDenialsSeen = false;
        boolean isFirstPermission = true;
        
        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        while ( !isMatchChar( item, RCURLY, pos ) )
        {
            if ( isFirstPermission )
            {
                isFirstPermission = false;
            }
            else
            {
                // Skip the SEP and ( SP )*
                // SEP
                matchChar( item, SEP, pos );

                // ( SP )* 
                skipSpaces( item, pos, ZERO_N );
            }

            String token = getToken(  item, pos );
            
            // We may have either the precedence, protectedItems or grantAndDenials in any order
            switch ( Strings.toLowerCaseAscii( token ) )
            {
                case ID_PRECEDENCE:
                    // ID_precedence
                    LOG.debug( "Parsing userPermission's precedence: {}", pos );

                    if ( precedenceSeen )
                    {
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07049_PRECEDENCE_ALREADY_SEEN, token ), pos.start );
                    }
                
                    // Ok, check the precedence then
                    // ( SP )+
                    if ( !skipSpaces( item, pos, ONE_N ) )
                    {
                        throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                    }
                    
                    // integer
                    precedence = parseInteger( item, pos );
                    precedenceSeen = true;
                    
                    break;

                case ID_PROTECTED_ITEMS:
                    // ID_protectedItems
                    LOG.debug( "Parsing userPermission's protectedItems: {}", pos );

                    if ( protectedItemsSeen )
                    {
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07055_PROTECTED_ITEMS_ALREADY_SEEN, token ), pos.start );
                    }
                    
                    // protectedItems
                    protectedItems = parseProtectedItems( action, item, pos );
                    protectedItemsSeen = true;
                    
                    break;
                    
                case ID_GRANTS_AND_DENIALS:
                    // ID_grantsAndDenials
                    LOG.debug( "Parsing userPermission's grantsAndDenials: {}", pos );

                    if ( grantsAndDenialsSeen )
                    {
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07056_GRANTS_AND_DENIALS_ALREADY_SEEN, token ), pos.start );
                    }
                    
                    // grantsAndDenials
                    grantAndDenials = parseGrantAndDenials( action, item, pos );
                    grantsAndDenialsSeen = true;
                    
                    break;

                default:
                    throw new ParseException( I18n.err( I18n.ERR_07052_UNKNOWN_ACIITEM_PART, token ), pos.start );
            }
            
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );
        }
        
        // CLOSE_CURLY

        if ( !protectedItemsSeen )
        {
            // This is an error, we must have a set of protected items
            throw new ParseException( I18n.err( I18n.ERR_07054_MISSING_PROTECTED_ITEMS ), pos.start );
        }

        if ( !grantsAndDenialsSeen )
        {
            // This is an error, we must have a set of grants and denials
            throw new ParseException( I18n.err( I18n.ERR_07035_MISSING_GRANTS_AND_DENIALS ), pos.start );
        }
        
        if ( action == PARSE )
        {
            userPermission = new UserPermission( precedence, grantAndDenials, protectedItems );
        }
        
        return userPermission;
    }

    
    /**
     * Parse an attributeType set.
     * 
     * The grammar is:
     * <pre>
     * attributeTypeSet ::=
     *     OPEN_CURLY ( SP )*
     *         oid ( SP )* ( SEP ( SP )* oid ( SP )* )*
     *     CLOSE_CURLY
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return A set of attributeTypoes
     * @throws ParseException If the refinement is invalid
     */
    private Set<AttributeType> parseAttributeTypeSet( boolean action, String item, Position pos ) 
            throws ParseException
    {
        LOG.debug( "Parsing attributeTypeSet: {}", pos );

        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        boolean isFirst = true;
        Set<AttributeType> attributeTypes = null;
        
        if ( action == PARSE )
        {
            attributeTypes = new HashSet<>();
        }
        
        while ( hasMoreChars( pos ) )
        {
            // CLOSE_CURLY
            if ( isMatchChar( item, RCURLY, pos ) )
            {
                // The end. It can be empty
                return attributeTypes;
            }
            
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
            }
            
            // oid
            String oid = parseOid( item, pos );
            
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );

            if ( action == PARSE )
            {
                AttributeType attributeType = null;
                
                try 
                {
                    if ( schemaManager != null )
                    {
                        attributeType = schemaManager.lookupAttributeTypeRegistry( oid );
                    }
                    else
                    {
                        attributeType = new AttributeType( oid );
                    }
                } 
                catch ( LdapException e ) 
                {
                    throw new ParseException( I18n.err( I18n.ERR_07028_TYPE_INVALID_ATTRIBUTE, oid ), pos.start );
                }

                if ( action == PARSE )
                {
                    attributeTypes.add( attributeType );
                }
            }
        }
        
        // We should never get there
        throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
    }
    
    
    /**
     * Parse userClasses.
     * 
     * The grammar is:
     * <pre>
     * userClasses ::=
     *     ID_userClasses ( SP )*
     *     OPEN_CURLY ( SP )*
     *         ( userClass ( SP )* ( SEP ( SP )* userClass ( SP )* )* )?
     *     CLOSE_CURLY
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return A set of userPermission
     * @throws ParseException If the refinement is invalid
     */
    private Set<UserClass> parseUserClasses( boolean action, String item, Position pos ) throws ParseException
    {
        LOG.debug( "Parsing userClasses: {}", pos );

        NoDuplicateKeysMap userClasses = null;
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );

        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        boolean isFirst = true;

        if ( action == PARSE )
        {
            userClasses = new NoDuplicateKeysMap();
        }

        while ( hasMoreChars( pos ) )
        {
            if ( isMatchChar( item, RCURLY, pos ) )
            {
                // The end. It can be empty
                // CLOSE_CURLY
                if ( action == PARSE )
                {
                    return new HashSet<UserClass>( userClasses.values() );
                }
                else
                { 
                    return null;
                }
            }
            
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                // SEP
                matchChar( item, SEP, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );
            }
            
            parseUserClass( userClasses, action, item, pos );
            
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );
        }
        
        // We should never get there
        throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
   }
    
    
    /**
     * Parse userPermissions.
     * 
     * The grammar is:
     * <pre>
     * userPermissions ::=
     *     ID_userPermissions ( SP )*
     *     OPEN_CURLY ( SP )*
     *         ( userPermission ( SP )* ( SEP ( SP )* userPermission ( SP )* )* )?
     *     CLOSE_CURLY
     * </pre>
     * 
     * @action Tells if we parse or validate the ACIItem
     * @param item The ACIItem to parse
     * @param pos The position in the string
     * @return A set of userPermission
     * @throws ParseException If the refinement is invalid
     */
    private Set<UserPermission> parseUserPermissions( boolean action, String item, Position pos ) 
            throws ParseException
    {
        LOG.debug( "Parsing userPermissions: {}", pos );

        Set<UserPermission> userPermissions = null;
        
        String token = getToken( item, pos );
        
        // userPermissions
        if ( ID_USER_PERMISSIONS.equals( Strings.toLowerCaseAscii( token ) ) )
        {
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );

            // OPEN_CURLY
            matchChar( item, LCURLY, pos );
            
            // ( SP )*
            skipSpaces( item, pos, ZERO_N );
            boolean isFirst = true;

            if ( action == PARSE )
            {
                userPermissions = new HashSet<>();
            }
            
            while ( hasMoreChars( pos ) )
            {
                if ( isMatchChar( item, RCURLY, pos ) )
                {
                    // The end. It can be empty
                    // CLOSE_CURLY
                    if ( action == PARSE )
                    {
                        return userPermissions;
                    }
                    else
                    { 
                        return null;
                    }
                }
                
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    // SEP
                    matchChar( item, SEP, pos );
                    
                    //  ( SP )*
                    skipSpaces( item, pos, ZERO_N );
                }
                
                // userPermission
                UserPermission userPermission = parseUserPermission( action, item, pos );
                
                // ( SP )*
                skipSpaces( item, pos, ZERO_N );

                if ( action == PARSE )
                {
                    userPermissions.add( userPermission );
                }
            }
        }
        else
        {
            // Missing initial "userPermissions" token
            throw new ParseException( I18n.err( I18n.ERR_07032_MISSING_USER_PERMISSIONS_TOKEN, token ), pos.start );
        }
        
        // We should never get there
        throw new ParseException( I18n.err( I18n.ERR_07034_MISSING_EXPECTED_CLOSING_CURLY ), pos.start );
   }
  
    
    /**
     * Creates a normalizing ACIItem parser.
     *
     * @param normalizer the normalizer
     * @param schemaManager the schema manager
     */
    public ACIItemParser( NameComponentNormalizer normalizer, SchemaManager schemaManager )
    {
        isNormalizing = true;
        this.schemaManager = schemaManager;
    }


    /**
     * Parse an ACI Item first. The grammar is:
     * 
     * <pre>
     * itemFirst ::= ( SP )* COLON ( SP )*
     *     OPEN_CURLY ( SP )*
     *         [ID_protectedItems] protectedItems ( SP )* SEP  ( SP )* itemPermissions( SP )* 
     *     CLOSE_CURLY
     * </pre>
     * 
     * @param action
     * @param item
     * @param pos
     * @param identificationTag
     * @param precedence
     * @param authenticationLevel
     * @return
     * @throws ParseException
     */
    private AciItemTuple parseItemFirst( boolean action, String item, Position pos,
                String identificationTag, int precedence,  AuthenticationLevel authenticationLevel )
                    throws ParseException
    {
        LOG.debug( "Parsing itemFirst: {}", pos );

        AciItemTuple aciItemTuple = new AciItemTuple();
        
        if ( action == PARSE )
        {
            aciItemTuple.protectedItems = new HashSet<ProtectedItem>();
        }
        
        // The ID_itemFirst has been read, deal with the colon
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        // COLON
        matchChar( item, COLON, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        String token = getToken( item, pos );
        
        // ID_protectedItems
        if ( !ID_PROTECTED_ITEMS.equalsIgnoreCase( token ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_07036_MISSING_PROTECTED_ITEMS, token ), pos.start );
        }

        // Parse the protectedItems
        // protectedItems
        aciItemTuple.protectedItems = parseProtectedItems( action, item, pos );

        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        // SEP
        matchChar( item, SEP, pos );

        // ( SP )*
        skipSpaces( item, pos, ZERO_N );

        // itemPermissions
        aciItemTuple.itemPermissions = parseItemPermissions( action, item, pos );

        // ( SP )*
        skipSpaces( item, pos, ZERO_N );

        // CLOSE_CURLY
        if ( isMatchChar( item, RCURLY, pos ) )
        {
            // The end.
            return aciItemTuple;
        }
        else
        {
            throw new ParseException( I18n.err( I18n.ERR_07043_MISSING_ITEM_FIRST_RIGHT_CURLY ), pos.start );
        }
    }

    
    /**
     * Parse an ACI User first. The grammar is:
     * 
     * <pre>
     * userFirst ::= ( SP )* COLON ( SP )*
     *     OPEN_CURLY ( SP )*
     *        userClasses ( SP )* SEP ( SP )* userPermissions ( SP )*  
     *     CLOSE_CURLY
     * </pre>
     * 
     * @param action
     * @param item
     * @param pos
     * @param identificationTag
     * @param precedence
     * @param authenticationLevel
     * @return
     * @throws ParseException
     */
    private AciItemTuple parseUserFirst( boolean action, String item, Position pos,
                String identificationTag, int precedence,  AuthenticationLevel authenticationLevel )
                    throws ParseException
    {
        LOG.debug( "Parsing userFirst: {}", pos );

        AciItemTuple aciItemTuple = new AciItemTuple();
        
        // The ID_userFirst has been read, deal with the colon
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        // COLON
        matchChar( item, COLON, pos );

        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        // OPEN_CURLY
        matchChar( item, LCURLY, pos );

        // ( SP )*
        skipSpaces( item, pos, ZERO_N );

        // userClasses
        String token = getToken( item, pos );
        
        // ID_userClasses
        if ( ID_USER_CLASSES.equals( Strings.toLowerCaseAscii( token ) ) )
        {
            aciItemTuple.userClasses = parseUserClasses( action, item, pos );
        }
        else
        {
            // This is an error, we must have a userClasses token
            throw new ParseException( I18n.err( I18n.ERR_07047_MISSING_USER_CLASSES_TOKEN, token ), pos.start );
        }

        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        //SEP
        matchChar( item, SEP, pos );
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );

        // userPermissions
        aciItemTuple.userPermissions = parseUserPermissions( action, item, pos );

        // ( SP )*
        skipSpaces( item, pos, ZERO_N );

        // CLOSE_CURLY
        if ( isMatchChar( item, RCURLY, pos ) )
        {
            // The end.
            return aciItemTuple;
        }
        else
        {
            throw new ParseException( I18n.err( I18n.ERR_07044_MISSING_USER_FIRST_RIGHT_CURLY ), pos.start );
        }
    }
    
    
    /**
     * Parse an ACI Item. The grammar is:
     * 
     * <pre>
     * ACIItem ::= 
     *     ( SP )* 
     *     OPEN_CURLY
     *         ( SP )* 
     *         ( 
     *           ID_identificationTag ( SP )+ SAFEUTF8STRING ( SP )* SEP
     *           |
     *           ID_precedence ( SP )+ INTEGER ( SP )* SEP
     *           |
     *           ID_authenticationLevel ( SP )+ authenticationLevel ( SP )* SEP
     *           |
     *           [ID_itemOrUserFirst ( SP )+] itemOrUserFirst 
     *         )*
     *         ( SP )* 
     *    CLOSE_CURLY
     *    EOF
     * </pre>
     * @param action
     * @param aci
     * @return
     * @throws ParseException
     */
    private ACIItem parseAciItem( boolean action, String item ) throws ParseException
    {
        LOG.debug( "Parsing ACIItem: '{}'", item );

        Position pos = new Position( item );
        
        if ( item != null )
        {
            pos.length = item.length();
        }
        
        AciItemTuple aciItemTuple = null;
        String identificationTag = null;
        int precedence = 0;
        AuthenticationLevel authenticationLevel = null;
        boolean identificationTagSeen = false;
        boolean precedenceSeen = false;
        boolean authenticationLevelSeen = false;
        boolean itemOrUserFirstSeen = false;
        boolean isItemFirst = false;
        boolean isFirstItem = true;
        
        // ( SP )*
        skipSpaces( item, pos, ZERO_N );
        
        // OPEN_CURLY
        matchChar( item, LCURLY, pos );
        
        // ( SP )* 
        skipSpaces( item, pos, ZERO_N );

        while ( !isMatchChar( item, RCURLY, pos ) )
        {
            if ( isFirstItem )
            {
                isFirstItem = false;
            }
            else
            {
                // Skip the SEP and ( SP )*
                matchChar( item, SEP, pos );

                // ( SP )* 
                skipSpaces( item, pos, ZERO_N );
            }
            
            // The identification tag
            String token = getToken( item, pos );

            switch ( Strings.toLowerCaseAscii( token ) )
            {
                case ID_IDENTIFICATION_TAG:
                    LOG.debug( "Parsing ACIItem's identificationTag: {}", pos );

                    if ( identificationTagSeen )
                    {
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07048_IDENTIFICATION_TAG_ALREADY_SEEN, token ), pos.start );
                    }
                    
                    // ( SP )+
                    if ( !skipSpaces( item, pos, ONE_N ) )
                    {
                        throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                    }
                    
                    // SafeUTF8Character
                    identificationTag = parseQuotedSafeUtf8( item, pos );
            
                    identificationTagSeen = true;
                    break;
                    
                case ID_PRECEDENCE:
                    LOG.debug( "Parsing ACIItem's precedence: {}", pos );

                    if ( precedenceSeen )
                    {
                        throw new ParseException( 
                                I18n.err( I18n.ERR_07048_IDENTIFICATION_TAG_ALREADY_SEEN, token ), pos.start );
                    }
                    
                    // ( SP )+ 
                    if ( !skipSpaces( item, pos, ONE_N ) )
                    {
                        throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                    }
                    
                    // INTEGER
                    precedence = parseInteger( item, pos );
    
                    precedenceSeen = true;
                    break;
                    
                case ID_AUTHENTICATION_LEVEL:
                    LOG.debug( "Parsing ACIItem's authenticationLevel: {}", pos );

                    if ( authenticationLevelSeen )
                    {
                        throw new ParseException( I18n.err(
                                I18n.ERR_07050_AUTHENTICATION_LEVEL_ALREADY_SEEN, token ), pos.start );
                    }
                    
                    // ( SP )+
                    if ( !skipSpaces( item, pos, ONE_N ) )
                    {
                        throw new ParseException( I18n.err( I18n.ERR_07015_MISSING_MANDATORY_SPACES ), pos.start );
                    }
                    
                    // Check the authenticationLevel, on, of none, simple, strong
                    // authenticationLevel ::=
                    //     ID_none
                    //     |
                    //     ID_simple
                    //     |
                    //     ID_strong
                    token = getToken( item, pos );
                    
                    switch ( Strings.toLowerCaseAscii(  token ) )
                    {
                        case ID_NONE:
                            authenticationLevel = AuthenticationLevel.NONE;
                            break;
                            
                        case ID_SIMPLE:
                            authenticationLevel = AuthenticationLevel.SIMPLE;
                            break;
                            
                        case ID_STRONG:
                            authenticationLevel = AuthenticationLevel.STRONG;
                            break;
                            
                        default:
                            throw new ParseException( 
                                    I18n.err( I18n.ERR_07040_MISSING_AUTHENTICATION_LEVEL, token ), pos.start );
    
                    }
                    
                    authenticationLevelSeen = true;
                    break;
                    
                case ID_ITEM_OR_USER_FIRST:
                    LOG.debug( "Parsing ACIItem's itemOrUserFirst: {}", pos );

                    if ( itemOrUserFirstSeen )
                    {
                        throw new ParseException( I18n.err( 
                                I18n.ERR_07051_ITEM_OR_USER_FIRST_ALREADY_SEEN, token ), pos.start );
                    }
                    
                    
                    // Parse the ID_ItemOrUserFirst token, just in case.
                    // It's an error in the X.500 ASN.1 grammar, this ID
                    // should never exist.
                    // We check if it's present for back compatibility only...
                    // ( SP )+]
                    skipSpaces( item, pos, ZERO_N );
                    
                    // Get the next token
                    token = getToken( item, pos );
    
                    // Here, we have already swallowed the next token of the next rule:
                    // itemOrUserFirst
                    switch ( Strings.toLowerCaseAscii( token ) )
                    {
                        // ID_itemFirst
                        case ID_ITEM_FIRST:
                            isItemFirst = true;
                            aciItemTuple = parseItemFirst( action, item, pos, identificationTag, precedence, 
                                    authenticationLevel );
                            break;
    
                        // ID_userFirst
                        case ID_USER_FIRST:
                            isItemFirst = false;
                            aciItemTuple = parseUserFirst( action, item, pos, identificationTag, precedence, 
                                    authenticationLevel );
                            
                            break;
                        default:
                    }
    
                    itemOrUserFirstSeen = true;
                    break;
                    
                default:
                    throw new ParseException( I18n.err( I18n.ERR_07052_UNKNOWN_ACIITEM_PART, token ), pos.start );
            }
            
            // ( SP )* 
            skipSpaces( item, pos, ZERO_N );
        }

        // ( SP )*
        skipSpaces( item, pos, ZERO_N );

        if ( !identificationTagSeen )
        {
            throw new ParseException( I18n.err( I18n.ERR_07038_MISSING_IDENTIFIER_TAG ), pos.start );
        }
         
        if ( !precedenceSeen )
        {
            throw new ParseException( I18n.err( I18n.ERR_07039_MISSING_PRECEDENCE ), pos.start );
        }

        if ( !authenticationLevelSeen )
        {
            throw new ParseException( I18n.err( I18n.ERR_07040_MISSING_AUTHENTICATION_LEVEL ), pos.start );
        }

        if ( !itemOrUserFirstSeen )
        {
            throw new ParseException( I18n.err( I18n.ERR_07053_MISSING_ITEM_OR_USER_FIRST ), pos.start );
        }
        
        // EOF
        // The end. 
        if ( action == PARSE )
        {
            if ( isItemFirst )
            {
                return new ItemFirstACIItem( 
                        identificationTag, 
                        precedence, 
                        authenticationLevel, 
                        aciItemTuple.protectedItems, 
                        aciItemTuple.itemPermissions );
            }
            else
            {
                return new UserFirstACIItem( 
                        identificationTag, 
                        precedence, 
                        authenticationLevel, 
                        aciItemTuple.userClasses, 
                        aciItemTuple.userPermissions );
            }
        }
        else
        { 
            return null;
        }
    }


    /**
     * Parses an ACIItem without exhausting the parser.
     * 
     * @param spec the specification to be parsed
     * @return the specification bean
     * @throws ParseException
     *             if there are any recognition errors (bad syntax)
     */
    public ACIItem parse( String spec ) throws ParseException
    {
        ACIItem aCIItem;

        if ( ( spec == null ) || StringConstants.EMPTY.equals( spec.trim() ) )
        {
            return null;
        }
        
        try
        {
            aCIItem = parseAciItem( PARSE, spec );
        }
        catch ( ParseException e )
        {
            throw new ParseException( I18n
                    .err( I18n.ERR_07004_PARSER_FAILURE_ACI_ITEM, spec, e.getLocalizedMessage() ), 0 );
        }

        return aCIItem;
    }


    /**
     * Check an ACIItem specification
     * 
     * @param item the ACIItem to be checked
     * @return <code>true</code> if the ACIItem specification is valid, <code>false</code> otherwise
     **/
    public boolean check( String item )
    {
        if ( item == null )
        {
            return true;
        }
        
        try
        {
            LOG.debug( "Check the ACIItem '{}'", item );

            parseAciItem( VALIDATE, item );
            
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
    public boolean isNormizing()
    {
        return this.isNormalizing;
    }
}
