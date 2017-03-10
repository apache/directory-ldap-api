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
package org.apache.directory.api.ldap.model.schema.syntaxCheckers;


import java.text.ParseException;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.ldap.model.schema.parsers.MatchingRuleUseDescriptionSchemaParser;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A SyntaxChecker which verifies that a value follows the
 * matching rule use descripton syntax according to RFC 4512, par 4.2.4:
 * 
 * <pre>
 * MatchingRuleUseDescription = LPAREN WSP
 *    numericoid                 ; object identifier
 *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
 *    [ SP "DESC" SP qdstring ]  ; description
 *    [ SP "OBSOLETE" ]          ; not active
 *    SP "APPLIES" SP oids       ; attribute types
 *    extensions WSP RPAREN      ; extensions
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public class MatchingRuleUseDescriptionSyntaxChecker extends SyntaxChecker
{
    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( MatchingRuleUseDescriptionSyntaxChecker.class );

    /** The schema parser used to parse the MatchingRuleUseDescription Syntax */
    private MatchingRuleUseDescriptionSchemaParser schemaParser = new MatchingRuleUseDescriptionSchemaParser();
    
    /**
     * A static instance of MatchingRuleUseDescriptionSyntaxChecker
     */
    public static final MatchingRuleUseDescriptionSyntaxChecker INSTANCE = new MatchingRuleUseDescriptionSyntaxChecker();

    
    /**
     * 
     * Creates a new instance of MatchingRuleUseDescriptionSchemaParser.
     *
     */
    public MatchingRuleUseDescriptionSyntaxChecker()
    {
        super( SchemaConstants.MATCHING_RULE_USE_DESCRIPTION_SYNTAX );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isValidSyntax( Object value )
    {
        String strValue;

        if ( value == null )
        {
            LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, "null" ) );
            return false;
        }

        if ( value instanceof String )
        {
            strValue = ( String ) value;
        }
        else if ( value instanceof byte[] )
        {
            strValue = Strings.utf8ToString( ( byte[] ) value );
        }
        else
        {
            strValue = value.toString();
        }

        try
        {
            schemaParser.parseMatchingRuleUseDescription( strValue );
            LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );

            return true;
        }
        catch ( ParseException pe )
        {
            LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            return false;
        }
    }

}
