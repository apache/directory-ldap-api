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

package org.apache.directory.api.ldap.model.subtree;


import java.io.StringReader;
import java.text.ParseException;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.schema.NormalizerMappingResolver;
import org.apache.directory.api.ldap.model.schema.SchemaManager;

import antlr.RecognitionException;
import antlr.TokenStreamException;


/**
 * A reusable wrapper around the antlr generated parser for an LDAP subtree
 * specification as defined by <a href="http://www.faqs.org/rfcs/rfc3672.html">
 * RFC 3672</a>. This class enables the reuse of the antlr parser/lexer pair
 * without having to recreate the pair every time.
 * 
 * @see <a href="http://www.faqs.org/rfcs/rfc3672.html">RFC 3672</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SubtreeSpecificationParser
{
    /** the antlr generated parser being wrapped */
    private ReusableAntlrSubtreeSpecificationParser parser;

    /** the antlr generated lexer being wrapped */
    private ReusableAntlrSubtreeSpecificationLexer lexer;

    private final boolean isNormalizing;


    /**
     * Creates a subtree specification parser.
     * 
     * @param schemaManager The SchemaManager
     */
    public SubtreeSpecificationParser( SchemaManager schemaManager )
    {
        // place holder for the first input
        StringReader in = new StringReader( "" );
        this.lexer = new ReusableAntlrSubtreeSpecificationLexer( in );
        this.parser = new ReusableAntlrSubtreeSpecificationParser( lexer );
        // this method MUST be called while we cannot do
        // constructor overloading for antlr generated parser
        this.parser.init( schemaManager );
        this.isNormalizing = false;
    }


    /**
     * Creates a normalizing subtree specification parser.
     * 
     * @param resolver The resolver to use
     * @param schemaManager The SchemaManager
     */
    public SubtreeSpecificationParser( @SuppressWarnings("rawtypes") NormalizerMappingResolver resolver,
        SchemaManager schemaManager )
    {
        // place holder for the first input
        StringReader in = new StringReader( "" );
        this.lexer = new ReusableAntlrSubtreeSpecificationLexer( in );
        this.parser = new ReusableAntlrSubtreeSpecificationParser( lexer );
        this.parser.setNormalizerMappingResolver( resolver );
        // this method MUST be called while we cannot do
        // constructor overloading for antlr generated parser
        this.parser.init( schemaManager );
        this.isNormalizing = true;
    }


    /**
     * Initializes the plumbing by creating a pipe and coupling the parser/lexer
     * pair with it. param spec the specification to be parsed
     */
    private synchronized void reset( String spec )
    {
        // append end of input token
        StringReader in = new StringReader( spec + "end" );
        this.lexer.prepareNextInput( in );
        this.parser.resetState();
    }


    /**
     * Parses a subtree specification without exhausting the parser.
     * 
     * @param spec
     *            the specification to be parsed
     * @return the specification bean
     * @throws ParseException
     *             if there are any recognition errors (bad syntax)
     */
    public synchronized SubtreeSpecification parse( String spec ) throws ParseException
    {
        SubtreeSpecification ss;

        if ( ( spec == null ) || ( spec.trim().length() == 0 ) )
        {
            return null;
        }

        // reset and initialize the parser / lexer pair
        reset( spec );

        try
        {
            ss = this.parser.wrapperEntryPoint();
        }
        catch ( TokenStreamException | RecognitionException e )
        {
            String msg = I18n.err( I18n.ERR_04329, spec, e.getLocalizedMessage() );
            throw new ParseException( msg, 0 );
        }

        return ss;
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
