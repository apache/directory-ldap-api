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
import org.apache.directory.api.ldap.model.schema.AttributeType;

import antlr.RecognitionException;
import antlr.TokenStreamException;


/**
 * A parser for RFC 4512 attribute type descriptions.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AttributeTypeDescriptionSchemaParser extends AbstractSchemaParser<AttributeType>
{

    /**
     * Creates a schema parser instance.
     */
    public AttributeTypeDescriptionSchemaParser()
    {
        super( AttributeType.class, I18n.ERR_04227, I18n.ERR_04228, I18n.ERR_04229 );

    }


    /**
     * Parses a attribute type description according to RFC 4512:
     * 
     * <pre>
     * AttributeTypeDescription = LPAREN WSP
     *     numericoid                    ; object identifier
     *     [ SP "NAME" SP qdescrs ]      ; short names (descriptors)
     *     [ SP "DESC" SP qdstring ]     ; description
     *     [ SP "OBSOLETE" ]             ; not active
     *     [ SP "SUP" SP oid ]           ; supertype
     *     [ SP "EQUALITY" SP oid ]      ; equality matching rule
     *     [ SP "ORDERING" SP oid ]      ; ordering matching rule
     *     [ SP "SUBSTR" SP oid ]        ; substrings matching rule
     *     [ SP "SYNTAX" SP noidlen ]    ; value syntax
     *     [ SP "SINGLE-VALUE" ]         ; single-value
     *     [ SP "COLLECTIVE" ]           ; collective
     *     [ SP "NO-USER-MODIFICATION" ] ; not user modifiable
     *     [ SP "USAGE" SP usage ]       ; usage
     *     extensions WSP RPAREN         ; extensions
     * 
     * usage = "userApplications"     /  ; user
     *         "directoryOperation"   /  ; directory operational
     *         "distributedOperation" /  ; DSA-shared operational
     *         "dSAOperation"            ; DSA-specific operational     
     * 
     * extensions = *( SP xstring SP qdstrings )
     * xstring = "X" HYPHEN 1*( ALPHA / HYPHEN / USCORE ) 
     * </pre>
     * 
     * @param attributeTypeDescription the attribute type description to be parsed
     * @return the parsed AttributeTypeDescription bean
     * @throws ParseException if there are any recognition errors (bad syntax)
     */
    public AttributeType parseAttributeTypeDescription( String attributeTypeDescription ) throws ParseException
    {
        return super.parse( attributeTypeDescription );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    protected AttributeType doParse() throws RecognitionException, TokenStreamException
    {
        return parser.attributeTypeDescription();
    }

}
