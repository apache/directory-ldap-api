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

package org.apache.directory.api.ldap.trigger;


import java.text.ParseException;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.NormalizerMappingResolver;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.trigger.TriggerSpecificationModifier.SPSpecModifier;
import org.apache.directory.api.util.Position;
import org.apache.directory.api.util.Strings;

import static org.apache.directory.api.util.ParserUtil.getDollarToken;
import static org.apache.directory.api.util.ParserUtil.getToken;
import static org.apache.directory.api.util.ParserUtil.isMatchChar;
import static org.apache.directory.api.util.ParserUtil.hasMoreChars;
import static org.apache.directory.api.util.ParserUtil.matchChar;
import static org.apache.directory.api.util.ParserUtil.parseQuotedSafeUtf8;
import static org.apache.directory.api.util.ParserUtil.skipSpaces;

import static org.apache.directory.api.util.ParserUtil.SEP;
import static org.apache.directory.api.util.ParserUtil.DOT;
import static org.apache.directory.api.util.ParserUtil.LCURLY;
import static org.apache.directory.api.util.ParserUtil.LPAREN;
import static org.apache.directory.api.util.ParserUtil.RCURLY;
import static org.apache.directory.api.util.ParserUtil.RPAREN;
import static org.apache.directory.api.util.ParserUtil.SEMI_COLON;
import static org.apache.directory.api.util.ParserUtil.ONE_N;
import static org.apache.directory.api.util.ParserUtil.ZERO_N;


/**
 * A parser for a TriggerSpecification.
 * 
 * Here is the grammar:
 * 
 * <pre>
* triggerSpecification = ( SP )* "after" ( SP )+ ldapOperationSPCalls
 * 
 * ldapOperationSPCalls =
 *              addOperationCalls | 
 *              deleteOperationCalls |
 *              modifyOperationCalls |
 *              modifyDNOperationCalls
 *         
 * --------------------------------------------
 *     
 * addOperationCalls =
 *    "add" ( SP )+
 *    ( 
 *      callNameOptionList
 *      OPEN_PAREN ( SP )*
 *        ( addParameterList )?
 *      CLOSE_PAREN ( SP )* SEMI ( SP )*
 *    )+
 *    
 * addParamList ::=
 *    addParameter ( SP )* ( SEP ( SP )* addParameter ( SP )* )*
 *        
 * addParameter ::= "$entry" | "$attributes" | "$ldapcontext" ( SP )+ DN | "$operationprincipal"
 *         
 * --------------------------------------------
 *
 * deleteOperationCalls =
 *    "delete" ( SP )
 *    ( 
 *      callNameOptionList
 *      OPEN_PAREN ( SP )*
 *        ( deleteParameterList )?
 *      CLOSE_PAREN ( SP )* SEMI ( SP )*
 *    )+
 *         
 * deleteParameterList =
 *    deleteParameter ( SP )*
 *        ( SEP ( SP )* deleteParameter ( SP )* )*
 *        
 * deleteParameter =
 *    "$name" | "$deletedentry" | "$ldapcontext" ( SP )+ DN | "$operationprincipal"
 *
 * --------------------------------------------
 *    
 * modifyOperationCalls =
 *    "modify" ( SP )+
 *    ( 
 *      callNameOptionList
 *      OPEN_PAREN ( SP )*
 *        ( modifyParameterList )?
 *      CLOSE_PAREN ( SP )* SEMI ( SP )* 
 *    )+
 *         
 * modifyParameterList =
 *    modifyParameter ( SP )*
 *        ( SEP ( SP )* modifyParameter ( SP )* )*
 *        
 * modifyParameter =
 *    "$object" | "$modification"| "$oldentry"  | "$newentry" | "$ldapcontext" ( SP )+ DN | "$operationprincipal"
 *
 * --------------------------------------------
 *    
 * modifyDNOperationCalls =
 *    "modify" DOT ( "rename" | "export" | "import" )
 *    ( 
 *      ( SP )+ callNameOptionList
 *      OPEN_PAREN ( SP )*
 *        ( modifyDNSPParameterList )?
 *      CLOSE_PAREN ( SP )* SEMI ( SP )*
 *    )+
 *         
 * modifyDNParameterList =
 *    modifyDNParameter ( SP )*
 *        ( SEP ( SP )* modifyDNParameter ( SP )* )*
 *        
 *    
 * modifyDNParameter =
 *    "$entry" | "$newrdn" | "$deleteoldrdn" | "$newSuperior" | "$oldRdn" | 
 *    "$oldSuperiorDn" | "$newDn"  | "$ldapcontext" ( SP )+ DN | "$operationprincipal"
 *    
 * --------------------------------------------
 *    
 * callNameOptionList =
 *    "call" ( SP )+ quotedUtf8String ( SP )*
 *        ( genericOptionList ( SP )* )?
 *        
 * genericOptionList =
 *    OPEN_CURLY 
 *      ( SP )* 
 *      ( 
 *        genericOption ( SP )* 
 *        ( 
 *          SEP ( SP )* genericOption ( SP )* 
 *        )* 
 *      )* 
 *    CLOSE_CURLY
 *    
 * genericOption =
 *    ( 
 *        "languagescheme" ( SP )+ QuotedUTF8String
 *        | 
 *        "searchcontext" ( SP )+ 
 *        ( 
 *            OPEN_CURLY ( SP )*
 *                ( "scope" ( SP )+ ( "base" | "one" | "subtree" ) ( SP )* )?
 *            CLOSE_CURLY ( SP )+ 
 *        )?
 *        DN
 *    )
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class TriggerSpecificationParser
{
    private final boolean isNormalizing;

    /** The schema manager instance */
    private SchemaManager schemaManager;

    /** Flags to use to differentiate a parsing from a checking */
    private static final boolean PARSE = true;
    private static final boolean VALIDATE = false;

    /** The TriggerSpecification tokens */
    private static final String ID_ADD = "add";
    private static final String ID_AFTER = "after";
    private static final String ID_ATTRIBUTES = "$attributes";
    private static final String ID_BASE = "base";
    private static final String ID_CALL = "call";
    private static final String ID_DELETE = "delete";
    private static final String ID_DELETE_OLD_RDN = "deleteoldrdn";
    private static final String ID_DELETED_ENTRY = "$deletedentry";
    private static final String ID_ENTRY = "$entry";
    private static final String ID_LANGUAGE_SCHEME = "languagescheme";
    private static final String ID_LDAP_CONTEXT = "$ldapcontext";
    private static final String ID_SEARCH_CONTEXT = "searchcontext";
    private static final String ID_MODIFICATION = "$modification";
    private static final String ID_MODIFY = "modify";
    private static final String ID_MODIFY_DN = "modifydn";
    private static final String ID_MODIFY_DN_EXPORT = "export";
    private static final String ID_MODIFY_DN_IMPORT = "import";
    private static final String ID_MODIFY_DN_RENAME = "rename";
    private static final String ID_NAME = "$name";
    private static final String ID_NEW_DN = "$newdn";
    private static final String ID_NEW_ENTRY = "$newentry";
    private static final String ID_NEW_RDN = "$newrdn";
    private static final String ID_NEW_SUPERIOR = "$newsuperior";
    private static final String ID_OBJECT = "$object";
    private static final String ID_OLD_ENTRY = "$oldentry";
    private static final String ID_OLD_RDN = "$oldrdn";
    private static final String ID_OLD_SUPERIOR_DN = "$oldsuperiordn";
    private static final String ID_ONE = "one";
    private static final String ID_OPERATION_PRINCIPAL = "$operationprincipal";
    private static final String ID_SCOPE  = "scope";
    private static final String ID_SUBTREE = "subtree";

    /**
     * Creates a TriggerSpecification parser.
     */
    public TriggerSpecificationParser()
    {
        this.isNormalizing = false;
    }


    /**
     * Creates a TriggerSpecification parser.
     * 
     * @param schemaManager The SchemaManager
     */
    public TriggerSpecificationParser( SchemaManager schemaManager )
    {
        this.isNormalizing = false;
        this.schemaManager = schemaManager;
    }


    /**
     * Creates a normalizing TriggerSpecification parser.
     *
     * @param resolver the resolver
     */
    public TriggerSpecificationParser( NormalizerMappingResolver<Normalizer> resolver )
    {
        // this method MUST be called while we cannot do
        // constructor overloading for ANTLR generated parser
        this.isNormalizing = true;
    }
    
    
    /**
     * Parse an SP call, following this grammar:
     * 
     * <pre>
     * genericOption ::=
     *     ( 
     *         "languagescheme" ( SP )+ UTF8String 
     *         |
     *         “searchcontext” ( SP )+ 
     *         ( 
     *             OPEN_CURLY ( SP )*
     *                 ( “scope” ( SP )+ ( ”base” | “one” | “subtree” ) ( SP )* )?
     *             CLOSE_CURLY ( SP )+ 
     *         )?
     *         DN 
     *     )
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The trigger specification string to parse
     * @param pos The position in the string
     * @param spSPecModifier The parsed Stored Procedure specification instance
     * @throws ParseException If the input was incorrect
     */
    private void parseGenericOption( boolean action, String spec, Position pos, SPSpecModifier spSPecModifier )
            throws ParseException
    {
        String token = getToken( spec, pos );
        
        switch ( Strings.toLowerCaseAscii( token ) )
        {
            case ID_LANGUAGE_SCHEME:
                skipSpaces( spec, pos, ONE_N );
                String language = parseQuotedSafeUtf8( spec, pos );
                
                if ( action == PARSE )
                {
                    StoredProcedureOption spOption = new StoredProcedureLanguageSchemeOption( language );
                    
                    spSPecModifier.addOption( spOption );
                }
                
                return;
                
            case ID_SEARCH_CONTEXT:
                skipSpaces( spec, pos, ONE_N );
                SearchScope searchScope = null;

                if ( isMatchChar( spec, LCURLY, pos ) )
                {
                    skipSpaces( spec, pos, ZERO_N );
                    
                    if ( ID_SCOPE.equalsIgnoreCase( getToken( spec, pos ) ) )
                    {
                        skipSpaces( spec, pos, ONE_N );

                        String scopeValue = getToken( spec, pos );
                        
                        switch ( Strings.toLowerCaseAscii( scopeValue ) )
                        {
                            case ID_BASE:
                                if ( action == PARSE )
                                {
                                    searchScope = SearchScope.OBJECT;
                                }
                                
                                break;
                                
                            case ID_ONE:
                                if ( action == PARSE )
                                {
                                    searchScope = SearchScope.ONELEVEL;
                                }
                                
                                break;
                                
                            case ID_SUBTREE:
                                if ( action == PARSE )
                                {
                                    searchScope = SearchScope.SUBTREE;
                                }
                                
                                skipSpaces( spec, pos, ZERO_N );
                                
                                break;
                                
                            default:
                                // error
                                throw new ParseException( 
                                        I18n.err( I18n.ERR_11007_MUST_HAVE_SCOPE_VALUE, scopeValue ), pos.start );
                        }
                    }
                }
                
                skipSpaces( spec, pos, ZERO_N );
                
                // The closing '}'
                matchChar( spec, RCURLY, pos );
              
                skipSpaces( spec, pos, ZERO_N );

                // We expect a DN
                String dnStr = parseQuotedSafeUtf8( spec, pos );
                
                if ( action == PARSE )
                {
                    Dn dn = null;
                    
                    try
                    {
                        dn = new Dn( schemaManager, dnStr );
                    }
                    catch ( LdapInvalidDnException ldie )
                    {
                        // 
                        throw new ParseException( I18n.err( I18n.ERR_11008_INVALID_DN, dnStr ), pos.start );
                    }

                    StoredProcedureOption spOption = new StoredProcedureSearchContextOption( dn, searchScope );
                    
                    spSPecModifier.addOption( spOption );
                }
      
                return;
                
            default:
                // We are done
                return;
        }
    }
    
    
    /**
     * Parse an SP call options, following this grammar:
     * 
     * <pre>
     * callNameOptionList ::=
     *     “call” ( SP )+ UTF8String ( SP )*
     *     ( 
     *         OPEN_CURLY 
     *             ( SP )* genericOption ( SP )*
     *             ( 
     *                 SEP ( SP )* genericOption ( SP )* 
     *             )* 
     *         CLOSE_CURLY ( SP )* 
     *     )?
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The trigger specification string to parse
     * @param pos The position in the string
     * @return The parsed Stored Procedure specification instance
     * @throws ParseException If the input was incorrect
     */
    private SPSpecModifier parseCallNameOptionList( boolean action, String spec, Position pos )
            throws ParseException
    {
        // The 'call' token must be present
        String token = getToken( spec, pos );
        
        if ( !ID_CALL.equalsIgnoreCase( token ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_11006_MISSING_CALL_TOKEN, token ), pos.start );
        }
        
        if ( !skipSpaces( spec, pos, ONE_N ) )
        {
            throw new ParseException( I18n.err( I18n.ERR_11004_MISSING_MANDATORY_SPACE, spec ), pos.start );
        }
        
        // The procedure name
        String procedureName = parseQuotedSafeUtf8( spec, pos );
        
        skipSpaces( spec, pos, ZERO_N );
        
        SPSpecModifier spSpecModifier = null;
        
        if ( action == PARSE )
        {
            spSpecModifier = new SPSpecModifier();
            spSpecModifier.setName( procedureName );
        }

        // Check if we have options, if so we have an opening '{'
        if ( isMatchChar( spec, LCURLY, pos ) )
        {
            boolean isFirst = true;
            
            while ( !isMatchChar( spec, RCURLY, pos ) )
            {
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    // The ',' separator, or get our
                    matchChar( spec, SEP, pos );
                }
                
                skipSpaces( spec, pos, ZERO_N );
                
                parseGenericOption( action, spec, pos, spSpecModifier );
                
                skipSpaces( spec, pos, ZERO_N );
            }
            
            // We must have a closing '}'
            skipSpaces( spec, pos, ZERO_N );
        }
        
        return spSpecModifier;
    }


    /**
     * Parse an ADD operation and SP calls, following this grammar:
     * 
     * <pre>
     * addParameterList ::=
     *     addParameter ( SP )* ( SEP ( SP )* addSPParameter ( SP )* )*
     * addParameter ::=
     *     “$entry” | "$attributes" |  "$ldapcontext" ( SP )+ DN | "$operationprincipal"
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The trigger specification string to parse
     * @param pos The position in the string
     * @param spSpecModifier The SPSpec modifier
     * @throws ParseException If the input was incorrect
     */
    private void parseAddParamList( 
            boolean action, String spec, Position pos, SPSpecModifier spSpecModifier )
            throws ParseException
    {
        boolean isFirst = true;
        
        // The list of parameters is followed by a closing ')'
        while ( hasMoreChars( pos ) && ( spec.charAt( pos.start ) != RPAREN ) )
        {
            if ( isFirst )
            { 
                isFirst = false;
            }
            else
            {
                matchChar( spec, SEP, pos );
                skipSpaces( spec, pos, ZERO_N );
            }
            
            String token = getDollarToken( spec, pos );
            
            switch ( Strings.toLowerCaseAscii( token ) )
            {
                case ID_ENTRY:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.Add_ENTRY.instance() );
                    }

                    break;
                    
                case ID_ATTRIBUTES:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.Add_ATTRIBUTES.instance() );
                    }
                    
                    break;
                    
                case ID_LDAP_CONTEXT:
                    // Get the DN
                    skipSpaces( spec, pos, ONE_N );
                    String dnStr = parseQuotedSafeUtf8( token, pos );
                    
                    if ( action == PARSE )
                    {
                        Dn ldapContext = null;
                    
                        try
                        {
                            ldapContext = new Dn( schemaManager, dnStr );
                        }
                        catch ( LdapInvalidDnException ldie )
                        {
                            // 
                            throw new ParseException( I18n.err( I18n.ERR_11008_INVALID_DN, dnStr ), pos.start );
                        }

                        spSpecModifier.addParameter( 
                                StoredProcedureParameter.Generic_LDAP_CONTEXT.instance( ldapContext ) );
                    }
                    
                    break;
                    
                case ID_OPERATION_PRINCIPAL:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( 
                                StoredProcedureParameter.Generic_OPERATION_PRINCIPAL.instance() );
                    }
                    
                    break;
                    
                default:
                    // Error, we need a closing ')'
            }
            
            skipSpaces( spec, pos, ZERO_N );
        }
    }


    /**
     * Parse an DELETE operation and SP calls, following this grammar:
     * 
     * <pre>
     * deleteParameterList =
     *    deleteParameter ( SP )*
     *        ( SEP ( SP )* deleteParameter ( SP )* )*
     *        
     * deleteParameter =
     *    "$name" | "$deletedentry" | "$ldapcontext" ( SP )+ DN | "$operationprincipal"
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The trigger specification string to parse
     * @param pos The position in the string
     * @param spSpecModifier The SPSpec modifier
     * @throws ParseException If the input was incorrect
     */
    private void parseDeleteParamList( 
            boolean action, String spec, Position pos, SPSpecModifier spSpecModifier )
            throws ParseException
    {
        boolean isFirst = true;
        
        // The list of parameters is followed by a closing ')'
        while ( hasMoreChars( pos ) && ( spec.charAt( pos.start ) != RPAREN ) )
        {
            if ( isFirst )
            { 
                isFirst = false;
            }
            else
            {
                matchChar( spec, SEP, pos );
                skipSpaces( spec, pos, ZERO_N );
            }
            
            String token = getDollarToken( spec, pos );
            
            switch ( Strings.toLowerCaseAscii( token ) )
            {
                case ID_NAME:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.Delete_NAME.instance() );
                    }

                    break;
                    
                case ID_DELETED_ENTRY:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.Delete_DELETED_ENTRY.instance() );
                    }
                    
                    break;
                    
                case ID_LDAP_CONTEXT:
                    // Get the DN
                    skipSpaces( spec, pos, ONE_N );
                    String dnStr = parseQuotedSafeUtf8( spec, pos );
                    
                    if ( action == PARSE )
                    {
                        Dn ldapContext = null;
                    
                        try
                        {
                            ldapContext = new Dn( schemaManager, dnStr );
                        }
                        catch ( LdapInvalidDnException ldie )
                        {
                            // 
                            throw new ParseException( I18n.err( I18n.ERR_11008_INVALID_DN, dnStr ), pos.start );
                        }

                        spSpecModifier.addParameter( 
                                StoredProcedureParameter.Generic_LDAP_CONTEXT.instance( ldapContext ) );
                    }
                    
                    break;
                    
                case ID_OPERATION_PRINCIPAL:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( 
                                StoredProcedureParameter.Generic_OPERATION_PRINCIPAL.instance() );
                    }
                    
                    break;
                    
                default:
                    // Error, we need a closing ')'
            }
            
            skipSpaces( spec, pos, ZERO_N );
        }
    }


    /**
     * Parse a MODIFY operation and SP calls, following this grammar:
     * 
     * <pre>
     * modifyParameterList =
     *    modifyParameter ( SP )*
     *        ( SEP ( SP )* modifyParameter ( SP )* )*
     *        
     * modifyParameter =
     *    "$object" | "$modification"| "$oldentry"  | "$newentry" | "$ldapcontext" ( SP )+ DN | "$operationprincipal"
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The trigger specification string to parse
     * @param pos The position in the string
     * @param spSpecModifier The SPSpec modifier
     * @throws ParseException If the input was incorrect
     */
    private void parseModifyParamList( 
            boolean action, String spec, Position pos, SPSpecModifier spSpecModifier )
            throws ParseException
    {
        boolean isFirst = true;
        
        // The list of parameters is followed by a closing ')'
        while ( hasMoreChars( pos ) && ( spec.charAt( pos.start ) != RPAREN ) )
        {
            if ( isFirst )
            { 
                isFirst = false;
            }
            else
            {
                matchChar( spec, SEP, pos );
                skipSpaces( spec, pos, ZERO_N );
            }
            
            String token = getDollarToken( spec, pos );
            
            switch ( Strings.toLowerCaseAscii( token ) )
            {
                case ID_OBJECT:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.Modify_OBJECT.instance() );
                    }

                    break;
                    
                case ID_MODIFICATION:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.Modify_MODIFICATION.instance() );
                    }
                    
                    break;
                    
                    
                case ID_OLD_ENTRY:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.Modify_OLD_ENTRY.instance() );
                    }
                    
                    break;
                    
                    
                case ID_NEW_ENTRY:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.Modify_NEW_ENTRY.instance() );
                    }
                    
                    break;
                    
                case ID_LDAP_CONTEXT:
                    // Get the DN
                    skipSpaces( spec, pos, ONE_N );
                    String dnStr = parseQuotedSafeUtf8( spec, pos );
                    
                    if ( action == PARSE )
                    {
                        Dn ldapContext = null;
                    
                        try
                        {
                            ldapContext = new Dn( schemaManager, dnStr );
                        }
                        catch ( LdapInvalidDnException ldie )
                        {
                            // 
                            throw new ParseException( I18n.err( I18n.ERR_11008_INVALID_DN, dnStr ), pos.start );
                        }

                        spSpecModifier.addParameter( 
                                StoredProcedureParameter.Generic_LDAP_CONTEXT.instance( ldapContext ) );
                    }
                    
                    break;
                    
                case ID_OPERATION_PRINCIPAL:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( 
                                StoredProcedureParameter.Generic_OPERATION_PRINCIPAL.instance() );
                    }
                    
                    break;
                    
                default:
                    // Error, we need a closing ')'
            }
            
            skipSpaces( spec, pos, ZERO_N );
        }
    }


    /**
     * Parse a MODIFYDN operation and SP calls, following this grammar:
     * 
     * <pre>
     * modifyDNParameterList =
     *    modifyDNParameter ( SP )*
     *        ( SEP ( SP )* modifyDNParameter ( SP )* )*
     *        
     *    
     * modifyDNParameter =
     *    "$entry" | "$newrdn" | "$deleteoldrdn" | "$newSuperior" | "$oldRdn" | 
     *    "$oldSuperiorDn" | "$newDn"  | "$ldapcontext" ( SP )+ DN | "$operationprincipal"
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec trigger specification string to parse
     * @param pos The position in the string
     * @param spSpecModifier The SPSpec modifier
     * @throws ParseException If the input was incorrect
     */
    private void parseModifyDNParamList( 
            boolean action, String spec, Position pos, SPSpecModifier spSpecModifier )
            throws ParseException
    {
        boolean isFirst = true;
        
        // The list of parameters is followed by a closing ')'
        while ( hasMoreChars( pos ) && ( spec.charAt( pos.start ) != RPAREN ) )
        {
            if ( isFirst )
            { 
                isFirst = false;
            }
            else
            {
                matchChar( spec, SEP, pos );
                skipSpaces( spec, pos, ZERO_N );
            }
            
            String token = getDollarToken( spec, pos );
            
            switch ( Strings.toLowerCaseAscii( token ) )
            {
                case ID_ENTRY:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.ModifyDN_ENTRY.instance() );
                    }

                    break;
                    
                case ID_NEW_RDN:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.ModifyDN_NEW_RDN.instance() );
                    }
                    
                    break;
                    
                    
                case ID_DELETE_OLD_RDN:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.ModifyDN_DELETE_OLD_RDN.instance() );
                    }
                    
                    break;
                    
                    
                case ID_NEW_SUPERIOR:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.ModifyDN_NEW_SUPERIOR.instance() );
                    }
                    
                    break;
                    
                case ID_OLD_RDN:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.ModifyDN_OLD_RDN.instance() );
                    }
                    
                    break;
                    
                case ID_OLD_SUPERIOR_DN:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.ModifyDN_OLD_SUPERIOR_DN.instance() );
                    }
                    
                    break;
                    
                case ID_NEW_DN:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( StoredProcedureParameter.ModifyDN_NEW_DN.instance() );
                    }
                    
                    break;
                    
                case ID_LDAP_CONTEXT:
                    // Get the DN
                    skipSpaces( spec, pos, ONE_N );
                    String dnStr = parseQuotedSafeUtf8( spec, pos );
                    
                    if ( action == PARSE )
                    {
                        Dn ldapContext = null;
                    
                        try
                        {
                            ldapContext = new Dn( schemaManager, dnStr );
                        }
                        catch ( LdapInvalidDnException ldie )
                        {
                            // 
                            throw new ParseException( I18n.err( I18n.ERR_11008_INVALID_DN, dnStr ), pos.start );
                        }

                        spSpecModifier.addParameter( 
                                StoredProcedureParameter.Generic_LDAP_CONTEXT.instance( ldapContext ) );
                    }
                    
                    break;
                    
                case ID_OPERATION_PRINCIPAL:
                    if ( action == PARSE )
                    {
                        spSpecModifier.addParameter( 
                                StoredProcedureParameter.Generic_OPERATION_PRINCIPAL.instance() );
                    }
                    
                    break;
                    
                default:
                    // Error, we need a closing ')'
            }
            
            skipSpaces( spec, pos, ZERO_N );
        }
    }


    /**
     * Parse an ADD operation and SP calls, following this grammar:
     * 
     * <pre>
     * addOperationCalls =
     *    "add" ( SP )+
     *    ( 
     *      callNameOptionList
     *      OPEN_PAREN ( SP )*
     *        ( addParameterList )?
     *      CLOSE_PAREN ( SP )* SEMI ( SP )*
     *    )+
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The trigger specification string to parse
     * @param pos The position in the string
     * @param tsModifier The TriggerSpecification modifier
     * @throws ParseException If the input was incorrect
     */
    private void parseAddOperationCalls( 
            boolean action, String spec, Position pos, TriggerSpecificationModifier tsModifier )
            throws ParseException
    {
        // The "add" token has already been parsed,
        // we need to skip the mandatory spaces that follow
        if ( !skipSpaces( spec, pos, ONE_N ) )
        {
            // Error
            throw new ParseException( I18n.err( I18n.ERR_11004_MISSING_MANDATORY_SPACE, spec ), pos.start );
        }
        
        // Loop until the end
        while ( hasMoreChars( pos ) )
        {
            SPSpecModifier spSpecModifier = parseCallNameOptionList( action, spec, pos );

            // The opening '('
            matchChar( spec, LPAREN, pos );
            skipSpaces( spec, pos, ZERO_N );
            
            parseAddParamList( action, spec, pos, spSpecModifier );
            
            if ( action == PARSE )
            {
                tsModifier.addSPSpec( spSpecModifier.getSPSpec() ); 
            }

            // The closing ')'
            matchChar( spec, RPAREN, pos );
            skipSpaces( spec, pos, ZERO_N );
            matchChar( spec, SEMI_COLON, pos );
            skipSpaces( spec, pos, ZERO_N );
        }
        
        // This should be the end
    }
    
    
    /**
     * Parse a DELETE operation and SP calls, following this grammar:
     * 
     * <pre>
     * deleteOperationCalls =
     *    "delete" ( SP )
     *    ( 
     *      callNameOptionList
     *      OPEN_PAREN ( SP )*
     *        ( deleteSPParameterList )?
     *      CLOSE_PAREN ( SP )* SEMI ( SP )*
     *    )+
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The trigger specification string to parse
     * @param pos The position in the string
     * @param tsModifier The TriggerSpecification modifier
     * @throws ParseException If the input was incorrect
     */
    private void parseDeleteOperationCalls( 
            boolean action, String spec, Position pos, TriggerSpecificationModifier tsModifier )
            throws ParseException
    {
        // The "add" token has already been parsed,
        // we need to skip the mandatory spaces that follow
        if ( !skipSpaces( spec, pos, ONE_N ) )
        {
            // Error
            throw new ParseException( I18n.err( I18n.ERR_11004_MISSING_MANDATORY_SPACE, spec ), pos.start );
        }
        
        // Loop until the end
        while ( hasMoreChars( pos ) )
        {
            SPSpecModifier spSpecModifier = parseCallNameOptionList( action, spec, pos );

            // The opening '('
            matchChar( spec, LPAREN, pos );
            skipSpaces( spec, pos, ZERO_N );
            
            parseDeleteParamList( action, spec, pos, spSpecModifier );
            
            if ( action == PARSE )
            {
                tsModifier.addSPSpec( spSpecModifier.getSPSpec() ); 
            }

            // The closing ')'
            matchChar( spec, RPAREN, pos );
            skipSpaces( spec, pos, ZERO_N );
            matchChar( spec, SEMI_COLON, pos );
            skipSpaces( spec, pos, ZERO_N );
        }
        
        // This should be the end
    }
    
    
    /**
     * Parse a MODIFY operation and SP calls, following this grammar:
     * 
     * <pre>
     * modifyOperationCalls =
     *    "modify" ( SP )+
     *    ( 
     *      callNameOptionList
     *      OPEN_PAREN ( SP )*
     *        ( modifySPParameterList )?
     *      CLOSE_PAREN ( SP )* SEMI ( SP )* 
     *    )+
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The trigger specification string to parse
     * @param pos The position in the string
     * @param tsModifier The TriggerSpecification modifier
     * @throws ParseException If the input was incorrect
     */
    private void parseModifyOperationCalls( 
            boolean action, String spec, Position pos, TriggerSpecificationModifier tsModifier )
            throws ParseException
    {
        // The "add" token has already been parsed,
        // we need to skip the mandatory spaces that follow
        if ( !skipSpaces( spec, pos, ONE_N ) )
        {
            // Error
            throw new ParseException( I18n.err( I18n.ERR_11004_MISSING_MANDATORY_SPACE, spec ), pos.start );
        }
        
        // Loop until the end
        while ( hasMoreChars( pos ) )
        {
            SPSpecModifier spSpecModifier = parseCallNameOptionList( action, spec, pos );

            // The opening '('
            matchChar( spec, LPAREN, pos );
            skipSpaces( spec, pos, ZERO_N );
            
            parseModifyParamList( action, spec, pos, spSpecModifier );
            
            if ( action == PARSE )
            {
                tsModifier.addSPSpec( spSpecModifier.getSPSpec() ); 
            }

            // The closing ')'
            matchChar( spec, RPAREN, pos );
            skipSpaces( spec, pos, ZERO_N );
            matchChar( spec, SEMI_COLON, pos );
            skipSpaces( spec, pos, ZERO_N );
        }
    }
    
    
    /**
     * Parse a MODDN operation and SP calls, following this grammar:
     * 
     * <pre>
     * modifyDNOperationCalls =
     *    "modify" DOT ( "rename" | "export" | "import" )
     *    ( 
     *      ( SP )+ callNameOptionList
     *      OPEN_PAREN ( SP )*
     *        ( modifyDNSPParameterList )?
     *      CLOSE_PAREN ( SP )* SEMI ( SP )*
     *    )+
     * </pre>
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The trigger specification string to parse
     * @param pos The position in the string
     * @param tsModifier The TriggerSpecification modifier
     * @throws ParseException If the input was incorrect
     */
    private void parseModifyDNOperationCalls( 
            boolean action, String spec, Position pos, TriggerSpecificationModifier tsModifier )
            throws ParseException
    {
        String token = getToken( spec, pos );
        
        switch ( Strings.toLowerCaseAscii( token ) )
        {
            case ID_MODIFY_DN_EXPORT:
                if ( action == PARSE )
                {
                    tsModifier.setLdapOperation( LdapOperation.MODIFYDN_EXPORT );
                }
                
                break;
                
            case ID_MODIFY_DN_IMPORT:
                if ( action == PARSE )
                {
                    tsModifier.setLdapOperation( LdapOperation.MODIFYDN_IMPORT );
                }
                
                break;
                
            case ID_MODIFY_DN_RENAME:
                if ( action == PARSE )
                {
                    tsModifier.setLdapOperation( LdapOperation.MODIFYDN_RENAME );
                }
                
                break;
            
            default:
                // error
                throw new ParseException( I18n.err( I18n.ERR_11010_MISSING_MODIFY_DN_OPERATION, token ), pos.start );
        }
        
        // we need to skip the mandatory spaces that follow
        if ( !skipSpaces( spec, pos, ONE_N ) )
        {
            // Error
            throw new ParseException( I18n.err( I18n.ERR_11004_MISSING_MANDATORY_SPACE, spec ), pos.start );
        }
        
        // Loop until the end
        while ( hasMoreChars( pos ) )
        {
            SPSpecModifier spSpecModifier = parseCallNameOptionList( action, spec, pos );

            // The opening '('
            matchChar( spec, LPAREN, pos );
            skipSpaces( spec, pos, ZERO_N );
            
            parseModifyDNParamList( action, spec, pos, spSpecModifier );
            
            if ( action == PARSE )
            {
                tsModifier.addSPSpec( spSpecModifier.getSPSpec() ); 
            }

            // The closing ')'
            matchChar( spec, RPAREN, pos );
            skipSpaces( spec, pos, ZERO_N );
            matchChar( spec, SEMI_COLON, pos );
            skipSpaces( spec, pos, ZERO_N );
        }
    }

    
    /**
     * Parse Ldap operation and SP calls, following this grammar:
     * 
     * <pre>
     * ldapOperationCalls =
     *              addOperationCalls | 
     *              deleteOperationCalls |
     *              modifyOperationCalls |
     *              modifyDNOperationCalls
     * </pre
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The trigger specification string to parse
     * @param pos The position in the string
     * @param tsModifier The TriggerSpecification modifier to feed
     * @return The parsed TriggerSpecification
     * @throws ParseException If the input was incorrect
     */
    private TriggerSpecification parseLdapOperationCalls( 
            boolean action, String spec, Position pos, TriggerSpecificationModifier tsModifier )
            throws ParseException
    {
        String token = getToken( spec, pos );
        
        switch ( Strings.toLowerCaseAscii( token ) )
        {
            case ID_ADD:
                if ( action == PARSE )
                {
                    tsModifier.setLdapOperation( LdapOperation.ADD );
                }
                
                parseAddOperationCalls( action, spec, pos, tsModifier );
                
                break;
                
            case ID_DELETE:
                if ( action == PARSE )
                {
                    tsModifier.setLdapOperation( LdapOperation.DELETE );
                }
                
                parseDeleteOperationCalls( action, spec, pos, tsModifier );
                
                break;

            case ID_MODIFY:
                if ( action == PARSE )
                {
                    tsModifier.setLdapOperation( LdapOperation.MODIFY );
                }
                
                parseModifyOperationCalls( action, spec, pos, tsModifier );
                
                break;

            case ID_MODIFY_DN:
                // The "modifyDN" token has already been parsed, we need a DOT
                matchChar( spec, DOT, pos );

                parseModifyDNOperationCalls( action, spec, pos, tsModifier );
                
                break;

            default:
                // An error
                throw new ParseException( I18n.err( I18n.ERR_11005_UNKNOW_TRIGGER_OPERATION, token ), pos.start );
        }
        
        return tsModifier.create();
    }
    
    
    /**
     * Parse a TriggerSpecification, following this grammar:
     * 
     * <pre>
     *   triggerSpecification = ( SP )* "after" ( SP )+ ldapOperationCalls
     * </pre
     * 
     * @action Tells if we parse or validate the spec
     * @param spec The Trigger specification string to parse
     * @param pos The position in the string
     * @return The parsed TriggerSpecification
     * @throws ParseException If the input was incorrect
     */
    private TriggerSpecification parse( boolean action, String spec, Position pos ) throws ParseException
    {
        // SKip the leading spaces
        skipSpaces( spec, pos, ZERO_N );
        
        // The actionTime
        String token = getToken( spec, pos );
        
        if ( !ID_AFTER.equalsIgnoreCase( token ) )
        {
            // We need an 'after' token
            throw new ParseException( I18n.err( I18n.ERR_11009_MISSING_AFTER, token ), pos.start );
        }
        
        TriggerSpecificationModifier tsModifier = null;
        
        if ( action == PARSE )
        {
            tsModifier = new TriggerSpecificationModifier();
            tsModifier.setActionTime( ActionTime.AFTER );
        }
        
        // Some mandatory spaces now
        if ( !skipSpaces( spec, pos, ONE_N ) )
        {
            // Error
            throw new ParseException( I18n.err( I18n.ERR_11004_MISSING_MANDATORY_SPACE, spec ), pos.start );
        }

        // and the following LDAP operations and stored procedure calls
        return parseLdapOperationCalls( action, spec, pos, tsModifier );
    }


    /**
     * Parses an TriggerSpecification without exhausting the parser.
     * 
     * @param spec the specification to be parsed
     * @return the specification instance
     * @throws ParseException if there is any syntax error
     */
    public TriggerSpecification parse( String spec ) throws ParseException
    {
        if ( Strings.isEmpty( spec ) )
        {
            return null;
        }
        
        Position pos = new Position();
        pos.length = spec.length();

        TriggerSpecification triggerSpecification = parse( PARSE, spec, pos );

        return triggerSpecification;
    }


    /**
     * Checks an TriggerSpecification to see if it's valid.
     * 
     * @param spec the specification to be checked
     * @return <code>true</code> if the TriggerSpecification is valid, <code>false</code> otherwise
     */
    public boolean check( String spec )
    {
        if ( Strings.isEmpty( spec ) )
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
    public boolean isNormalizing()
    {
        return this.isNormalizing;
    }
}
