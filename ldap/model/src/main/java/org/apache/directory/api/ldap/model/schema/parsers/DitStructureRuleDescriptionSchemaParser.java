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
import org.apache.directory.api.ldap.model.schema.DitStructureRule;


/**
 * A parser for RFC 4512 DIT structure rule descriptions.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DitStructureRuleDescriptionSchemaParser extends AbstractSchemaParser<DitStructureRule>
{

    /**
     * Creates a schema parser instance.
     */
    public DitStructureRuleDescriptionSchemaParser()
    {
        super( DitStructureRule.class, I18n.ERR_13836_CANNOT_PARSE_NULL_DSR, I18n.ERR_13837_DSR_PARSING_FAILURE, 
            I18n.ERR_13838_DSR_DESC_PARSING_FAILURE );
    }


    /**
     * Parses a DIT structure rule description according to RFC 4512:
     * 
     * <pre>
     * DITStructureRuleDescription = LPAREN WSP
     *   ruleid                     ; rule identifier
     *   [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *   [ SP "DESC" SP qdstring ]  ; description
     *   [ SP "OBSOLETE" ]          ; not active
     *   SP "FORM" SP oid           ; NameForm
     *   [ SP "SUP" ruleids ]       ; superior rules
     *   extensions WSP RPAREN      ; extensions
     *
     * ruleids = ruleid / ( LPAREN WSP ruleidlist WSP RPAREN )
     * ruleidlist = ruleid *( SP ruleid )
     * ruleid = numbers
     * </pre>
     * 
     * @param ditStructureRuleDescription the DIT structure rule description to be parsed
     * @return the parsed DITStructureRuleDescription bean
     * @throws ParseException if there are any recognition errors (bad syntax)
     */
    public DitStructureRule parse( String ditStructureRuleDescription ) throws ParseException
    {
        DitStructureRule ditStructureRule = fastParser.parseDitStructureRule( ditStructureRuleDescription );
        ditStructureRule.setSpecification( ditStructureRuleDescription );

        // Update the schemaName
        updateSchemaName( ditStructureRule );

        return ditStructureRule;
    }
}
