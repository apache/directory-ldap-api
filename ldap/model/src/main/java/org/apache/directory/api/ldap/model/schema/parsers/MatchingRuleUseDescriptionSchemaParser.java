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
package org.apache.directory.api.ldap.model.schema.parsers;


import java.text.ParseException;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.schema.MatchingRuleUse;

import antlr.RecognitionException;
import antlr.TokenStreamException;


/**
 * A parser for RFC 4512 matching rule use descriptions.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MatchingRuleUseDescriptionSchemaParser extends AbstractSchemaParser<MatchingRuleUse>
{

    /**
     * Creates a schema parser instance.
     */
    public MatchingRuleUseDescriptionSchemaParser()
    {
        super( MatchingRuleUse.class, I18n.ERR_04245, I18n.ERR_04246, I18n.ERR_04247 );
    }


    /**
     * Parses a matching rule use description according to RFC 4512:
     * 
     * <pre>
     * MatchingRuleUseDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    SP "APPLIES" SP oids       ; attribute types
     *    extensions WSP RPAREN      ; extensions
     * 
     * extensions = *( SP xstring SP qdstrings )
     * xstring = "X" HYPHEN 1*( ALPHA / HYPHEN / USCORE ) 
     * </pre>
     * 
     * @param matchingRuleUseDescription the matching rule use description to be parsed
     * @return the parsed MatchingRuleUseDescription bean
     * @throws ParseException if there are any recognition errors (bad syntax)
     */
    public MatchingRuleUse parseMatchingRuleUseDescription( String matchingRuleUseDescription ) throws ParseException
    {
        return super.parse( matchingRuleUseDescription );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    protected MatchingRuleUse doParse() throws RecognitionException, TokenStreamException
    {
        return parser.matchingRuleUseDescription();
    }

}
