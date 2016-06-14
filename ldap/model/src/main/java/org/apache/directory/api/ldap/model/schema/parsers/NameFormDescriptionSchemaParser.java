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
import org.apache.directory.api.ldap.model.schema.NameForm;

import antlr.RecognitionException;
import antlr.TokenStreamException;


/**
 * A parser for RFC 4512 name form descriptions
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class NameFormDescriptionSchemaParser extends AbstractSchemaParser<NameForm>
{

    /**
     * Creates a schema parser instance.
     */
    public NameFormDescriptionSchemaParser()
    {
        super( NameForm.class, I18n.ERR_04248, I18n.ERR_04249, I18n.ERR_04250 );
    }


    /**
     * Parses a name form description according to RFC 4512:
     * 
     * <pre>
     * NameFormDescription = LPAREN WSP
     *    numericoid                 ; object identifier
     *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
     *    [ SP "DESC" SP qdstring ]  ; description
     *    [ SP "OBSOLETE" ]          ; not active
     *    SP "OC" SP oid             ; structural object class
     *    SP "MUST" SP oids          ; attribute types
     *    [ SP "MAY" SP oids ]       ; attribute types
     *    extensions WSP RPAREN      ; extensions
     * </pre>
     * 
     * @param nameFormDescription the name form description to be parsed
     * @return the parsed NameForm bean
     * @throws ParseException if there are any recognition errors (bad syntax)
     */
    public NameForm parseNameFormDescription( String nameFormDescription ) throws ParseException
    {
        return super.parse( nameFormDescription );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    protected NameForm doParse() throws RecognitionException, TokenStreamException
    {
        return parser.nameFormDescription();
    }

}
