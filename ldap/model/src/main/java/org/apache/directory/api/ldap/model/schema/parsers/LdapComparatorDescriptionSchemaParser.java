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

import antlr.RecognitionException;
import antlr.TokenStreamException;


/**
 * A parser for ApacheDS comparator descriptions.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapComparatorDescriptionSchemaParser extends AbstractSchemaParser<LdapComparatorDescription>
{

    /**
     * Creates a schema parser instance.
     */
    public LdapComparatorDescriptionSchemaParser()
    {
        super( LdapComparatorDescription.class, I18n.ERR_04236, I18n.ERR_04237, I18n.ERR_04238 );
    }


    /**
     * Parses an comparator description:
     * 
     * <pre>
     * ComparatorDescription = LPAREN WSP
     *     numericoid                           ; object identifier
     *     [ SP "DESC" SP qdstring ]            ; description
     *     SP "FQCN" SP fqcn                    ; fully qualified class name
     *     [ SP "BYTECODE" SP base64 ]          ; optional base64 encoded bytecode
     *     extensions WSP RPAREN                ; extensions
     * 
     * base64          = *(4base64-char)
     * base64-char     = ALPHA / DIGIT / "+" / "/"
     * fqcn = fqcnComponent 1*( DOT fqcnComponent )
     * fqcnComponent = ???
     * 
     * extensions = *( SP xstring SP qdstrings )
     * xstring = "X" HYPHEN 1*( ALPHA / HYPHEN / USCORE ) 
     * </pre>
     * 
     * @param comparatorDescription the comparator description to be parsed
     * @return the parsed ComparatorDescription bean
     * @throws ParseException if there are any recognition errors (bad syntax)
     */
    public LdapComparatorDescription parseComparatorDescription( String comparatorDescription ) throws ParseException
    {
        return super.parse( comparatorDescription );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    protected LdapComparatorDescription doParse() throws RecognitionException, TokenStreamException
    {
        return parser.ldapComparator();
    }

}
