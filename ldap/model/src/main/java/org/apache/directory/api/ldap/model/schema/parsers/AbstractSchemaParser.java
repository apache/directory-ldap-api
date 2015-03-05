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


import java.io.StringReader;
import java.text.ParseException;
import java.util.List;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.MetaSchemaConstants;
import org.apache.directory.api.ldap.model.schema.SchemaObject;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import antlr.RecognitionException;
import antlr.TokenStreamException;
import antlr.TokenStreamRecognitionException;


/**
 * Base class of all schema parsers.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractSchemaParser<T extends SchemaObject>
{
    /** The LoggerFactory used by this class */
    protected static final Logger LOG = LoggerFactory.getLogger( AbstractSchemaParser.class );

    /** the monitor to use for this parser */
    protected ParserMonitor monitor = new ParserMonitorAdapter();

    /** the antlr generated parser being wrapped */
    protected ReusableAntlrSchemaParser parser;

    /** the antlr generated lexer being wrapped */
    protected ReusableAntlrSchemaLexer lexer;

    /** the schema object sub-type */
    private Class<T> schemaObjectType;

    /** error code used when schema descritpion is null */
    private I18n errorCodeOnNull;

    /** error code used on parse error when position is known */
    private I18n errorCodeOnParseExceptionWithPosition;

    /** error code used on parse error when position is unknown */
    private I18n errorCodeOnParseException;


    /**
     * Instantiates a new abstract schema parser.
     * @param errorCodeOnNull error code used when schema element is null
     * @param errorCodeOnParseExceptionWithPosition error code used on parse error when position is known
     * @param errorCodeOnParseException error code used on parse error when position is unknown
     */
    protected AbstractSchemaParser( Class<T> schemaObjectType, I18n errorCodeOnNull, I18n errorCodeOnParseExceptionWithPosition,
        I18n errorCodeOnParseException )
    {
        this.schemaObjectType = schemaObjectType;
        this.errorCodeOnNull = errorCodeOnNull;
        this.errorCodeOnParseExceptionWithPosition = errorCodeOnParseExceptionWithPosition;
        this.errorCodeOnParseException = errorCodeOnParseException;
        lexer = new ReusableAntlrSchemaLexer( new StringReader( "" ) );
        parser = new ReusableAntlrSchemaParser( lexer );
    }


    /**
     * Initializes the plumbing by creating a pipe and coupling the parser/lexer
     * pair with it. param spec the specification to be parsed
     *
     * @param spec the spec
     */
    protected void reset( String spec )
    {
        StringReader in = new StringReader( spec );
        lexer.prepareNextInput( in );
        parser.resetState();
    }


    /**
     * Sets the parser monitor.
     * 
     * @param parserMonitor the new parser monitor
     */
    public void setParserMonitor( ParserMonitor parserMonitor )
    {
        this.monitor = parserMonitor;
        parser.setParserMonitor( parserMonitor );
    }


    /**
     * Sets the quirks mode. 
     * 
     * If enabled the parser accepts non-numeric OIDs and some 
     * special characters in descriptions.
     * 
     * @param enabled the new quirks mode
     */
    public void setQuirksMode( boolean enabled )
    {
        parser.setQuirksMode( enabled );
    }


    /**
     * Checks if quirks mode is enabled.
     * 
     * @return true, if is quirks mode is enabled
     */
    public boolean isQuirksMode()
    {
        return parser.isQuirksMode();
    }


    /**
     * Parse a SchemaObject description and returns back an instance of SchemaObject.
     * 
     * @param schemaDescription The SchemaObject description
     * @return A SchemaObject instance
     * @throws ParseException If the parsing failed
     */
    public synchronized T parse( String schemaDescription ) throws ParseException
    {
        LOG.debug( "Parsing a {} : {}", schemaObjectType.getClass().getSimpleName(), schemaDescription );

        if ( schemaDescription == null )
        {
            LOG.error( I18n.err( errorCodeOnNull ) );
            throw new ParseException( "Null", 0 );
        }

        reset( schemaDescription ); // reset and initialize the parser / lexer pair

        try
        {
            T schemaObject = doParse();
            schemaObject.setSpecification( schemaDescription );

            // Update the schemaName
            updateSchemaName( schemaObject );

            return schemaObject;
        }
        catch ( RecognitionException re )
        {
            ParseException parseException = wrapRecognitionException( schemaDescription, re );
            throw parseException;
        }
        catch ( TokenStreamRecognitionException tsre )
        {
            if ( tsre.recog != null )
            {
                ParseException parseException = wrapRecognitionException( schemaDescription, tsre.recog );
                throw parseException;
            }
            else
            {
                ParseException parseException = wrapTokenStreamException( schemaDescription, tsre );
                throw parseException;
            }
        }
        catch ( TokenStreamException tse )
        {
            ParseException parseException = wrapTokenStreamException( schemaDescription, tse );
            throw parseException;
        }
    }


    private ParseException wrapRecognitionException( String schemaDescription, RecognitionException re )
    {
        String msg = I18n.err( errorCodeOnParseExceptionWithPosition, schemaDescription, re.getMessage(),
            re.getColumn() );
        LOG.error( msg );
        ParseException parseException = new ParseException( msg, re.getColumn() );
        parseException.initCause( re );
        return parseException;
    }


    private ParseException wrapTokenStreamException( String schemaDescription, TokenStreamException tse )
    {
        String msg = I18n.err( errorCodeOnParseException, schemaDescription, tse.getMessage() );
        LOG.error( msg );
        ParseException parseException = new ParseException( msg, 0 );
        parseException.initCause( tse );
        return parseException;
    }


    /**
     * Parse a SchemaObject description and returns back an instance of SchemaObject.
     * 
     * @return A SchemaObject instance
     * @throws RecognitionException the native antlr exception
     * @throws TokenStreamException the native antlr exception
     */
    protected abstract T doParse() throws RecognitionException, TokenStreamException;


    /**
     * Update the schemaName for the given SchemaObject, accordingly to the X-SCHEMA parameter. If
     * not present, default to 'other'
     *
     * @param schemaObject the schema object where the name should be updated
     */
    private void updateSchemaName( SchemaObject schemaObject )
    {
        // Update the Schema if we have the X-SCHEMA extension
        List<String> schemaExtension = schemaObject.getExtension( MetaSchemaConstants.X_SCHEMA_AT );

        if ( schemaExtension != null )
        {
            String schemaName = schemaExtension.get( 0 );

            if ( Strings.isEmpty( schemaName ) )
            {
                schemaObject.setSchemaName( MetaSchemaConstants.SCHEMA_OTHER );
            }
            else
            {
                schemaObject.setSchemaName( schemaName );
            }
        }
        else
        {
            schemaObject.setSchemaName( MetaSchemaConstants.SCHEMA_OTHER );
        }
    }
}
