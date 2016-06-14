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
 * A parser for ApacheDS normalizer descriptions.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class NormalizerDescriptionSchemaParser extends AbstractSchemaParser<NormalizerDescription>
{

    /**
     * Creates a schema parser instance.
     */
    public NormalizerDescriptionSchemaParser()
    {
        super( NormalizerDescription.class, I18n.ERR_04251, I18n.ERR_04252, I18n.ERR_04253 );
    }


    /**
     * Parses a normalizer description:
     * 
     * <pre>
     * NormalizerDescription = LPAREN WSP
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
     * @param normalizerDescription the normalizer description to be parsed
     * @return the parsed NormalizerDescription bean
     * @throws ParseException if there are any recognition errors (bad syntax)
     */
    public NormalizerDescription parseNormalizerDescription( String normalizerDescription ) throws ParseException
    {
        return super.parse( normalizerDescription );
    }


    @Override
    protected NormalizerDescription doParse() throws RecognitionException, TokenStreamException
    {
        return parser.normalizerDescription();
    }

}
