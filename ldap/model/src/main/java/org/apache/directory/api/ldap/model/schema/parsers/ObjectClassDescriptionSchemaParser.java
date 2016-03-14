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
import org.apache.directory.api.ldap.model.schema.ObjectClass;

import antlr.RecognitionException;
import antlr.TokenStreamException;


/**
 * A parser for RFC 4512 object class descriptons
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ObjectClassDescriptionSchemaParser extends AbstractSchemaParser<ObjectClass>
{

    /**
     * Creates a schema parser instance.
     */
    public ObjectClassDescriptionSchemaParser()
    {
        super( ObjectClass.class, I18n.ERR_04254, I18n.ERR_04255, I18n.ERR_04256 );
    }


    /**
     * Parses a object class definition according to RFC 4512:
     * 
     * <pre>
     * ObjectClassDescription = LPAREN WSP
     *     numericoid                 ; object identifier
     *     [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *     [ SP "DESC" SP qdstring ]  ; description
     *     [ SP "OBSOLETE" ]          ; not active
     *     [ SP "SUP" SP oids ]       ; superior object classes
     *     [ SP kind ]                ; kind of class
     *     [ SP "MUST" SP oids ]      ; attribute types
     *     [ SP "MAY" SP oids ]       ; attribute types
     *     extensions WSP RPAREN
     *
     * kind = "ABSTRACT" / "STRUCTURAL" / "AUXILIARY"
     * 
     * extensions = *( SP xstring SP qdstrings )
     * xstring = "X" HYPHEN 1*( ALPHA / HYPHEN / USCORE )
     * </pre>
     * 
     * @param objectClassDescription the object class description to be parsed
     * @return the parsed ObjectClassDescription bean
     * @throws ParseException if there are any recognition errors (bad syntax)
     */
    public ObjectClass parseObjectClassDescription( String objectClassDescription ) throws ParseException
    {
        return super.parse( objectClassDescription );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    protected ObjectClass doParse() throws RecognitionException, TokenStreamException
    {
        return parser.objectClassDescription();
    }

}
