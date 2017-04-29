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
package org.apache.directory.api.dsmlv2;


import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.directory.api.dsmlv2.response.BatchResponseDsml;
import org.apache.directory.api.dsmlv2.response.Dsmlv2ResponseGrammar;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.util.Strings;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;


/**
 * This class represents the DSMLv2 Parser.
 * It can be used to parse a DSMLv2 Response input.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Dsmlv2ResponseParser
{
    /** The associated DSMLv2 container */
    private Dsmlv2Container container;


    /**
     * Creates a new instance of Dsmlv2ResponseParser.
     *
     * @param codec The Ldap Service to use
     * @throws XmlPullParserException if an error occurs while the initialization of the parser
     */
    public Dsmlv2ResponseParser( LdapApiService codec ) throws XmlPullParserException
    {
        this.container = new Dsmlv2Container( codec );

        this.container.setGrammar( Dsmlv2ResponseGrammar.getInstance() );

        XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
        factory.setNamespaceAware( true );
        XmlPullParser xpp = factory.newPullParser();

        container.setParser( xpp );
    }


    /**
     * Sets the input string the parser is going to parse
     *
     * @param str the string the parser is going to parse
     * @throws XmlPullParserException if an error occurs in the parser
     */
    public void setInput( String str ) throws XmlPullParserException
    {
        container.getParser().setInput( new StringReader( str ) );
    }


    /**
     * Sets the input file the parser is going to parse. Default charset is used.
     *
     * @param fileName the name of the file
     * @throws FileNotFoundException if the file does not exist
     * @throws XmlPullParserException if an error occurs in the parser
     */
    public void setInputFile( String fileName ) throws IOException, XmlPullParserException
    {
        try ( Reader reader = new InputStreamReader( Files.newInputStream( Paths.get( fileName ) ), 
            Charset.defaultCharset() ) )
        {
            container.getParser().setInput( reader );
        }
    }


    /**
     * Sets the input stream the parser is going to process
     *
     * @param inputStream contains a raw byte input stream of possibly unknown encoding (when inputEncoding is null)
     * @param inputEncoding if not null it MUST be used as encoding for inputStream
     * @throws XmlPullParserException if an error occurs in the parser
     */
    public void setInput( InputStream inputStream, String inputEncoding ) throws XmlPullParserException
    {
        container.getParser().setInput( inputStream, inputEncoding );
    }


    /**
     * Launches the parsing on the input
     * 
     * @throws XmlPullParserException when an unrecoverable error occurs
     * @throws IOException when an IO exception occurs
     */
    public void parse() throws XmlPullParserException, IOException
    {
        Dsmlv2ResponseGrammar grammar = Dsmlv2ResponseGrammar.getInstance();

        grammar.executeAction( container );
    }


    /**
     * Launches the parsing of the Batch Response only
     *
     * @throws XmlPullParserException if an error occurs in the parser
     */
    public void parseBatchResponse() throws XmlPullParserException
    {
        XmlPullParser xpp = container.getParser();

        int eventType = xpp.getEventType();
        
        do
        {
            switch ( eventType )
            {
                case XmlPullParser.START_DOCUMENT :
                    container.setState( Dsmlv2StatesEnum.INIT_GRAMMAR_STATE );
                    break;

                case XmlPullParser.END_DOCUMENT :
                    container.setState( Dsmlv2StatesEnum.GRAMMAR_END );
                    break;

                case XmlPullParser.START_TAG :
                    processTag( container, Tag.START );
                    break;

                case XmlPullParser.END_TAG :
                    processTag( container, Tag.END );
                    break;

                default:
                    break;
            }
            
            try
            {
                eventType = xpp.next();
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03037, ioe.getLocalizedMessage() ), xpp, ioe );
            }
        }
        while ( container.getState() != Dsmlv2StatesEnum.BATCH_RESPONSE_LOOP );
    }


    /**
     * Processes the task required in the grammar to the given tag type
     *
     * @param container the DSML container
     * @param tagType the tag type
     * @throws XmlPullParserException when an error occurs during the parsing
     */
    private static void processTag( Dsmlv2Container container, int tagType ) throws XmlPullParserException
    {
        XmlPullParser xpp = container.getParser();

        String tagName = Strings.lowerCase( xpp.getName() );

        GrammarTransition transition = container.getTransition( container.getState(), new Tag( tagName, tagType ) );

        if ( transition != null )
        {
            container.setState( transition.getNextState() );

            if ( transition.hasAction() )
            {
                transition.getAction().action( container );
            }
        }
        else
        {
            throw new XmlPullParserException( I18n.err( I18n.ERR_03036, new Tag( tagName, tagType ) ), xpp, null );
        }
    }


    /**
     * Gets the Batch Response or null if the it has not been parsed yet
     *
     * @return the Batch Response or null if the it has not been parsed yet
     */
    public BatchResponseDsml getBatchResponse()
    {
        return container.getBatchResponse();
    }


    /**
     * Returns the next Request or null if there's no more request
     * @return the next Request or null if there's no more request
     * @throws XmlPullParserException when an error occurs during the parsing
     */
    public DsmlDecorator<? extends Response> getNextResponse() throws XmlPullParserException
    {
        if ( container.getBatchResponse() == null )
        {
            parseBatchResponse();
        }

        XmlPullParser xpp = container.getParser();

        int eventType = xpp.getEventType();
        do
        {
            while ( eventType == XmlPullParser.TEXT )
            {
                try
                {
                    xpp.next();
                }
                catch ( IOException ioe )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03037, ioe.getLocalizedMessage() ), xpp, ioe );
                }
                eventType = xpp.getEventType();
            }

            switch ( eventType )
            {
                case XmlPullParser.START_DOCUMENT :
                    container.setState( Dsmlv2StatesEnum.INIT_GRAMMAR_STATE );
                    break;

                case XmlPullParser.END_DOCUMENT :
                    container.setState( Dsmlv2StatesEnum.GRAMMAR_END );
                    return null;

                case XmlPullParser.START_TAG :
                    processTag( container, Tag.START );
                    break;

                case XmlPullParser.END_TAG :
                    processTag( container, Tag.END );
                    break;

                default:
                    break;
            }
            
            try
            {
                eventType = xpp.next();
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03037, ioe.getLocalizedMessage() ), xpp, ioe );
            }
        }
        while ( container.getState() != Dsmlv2StatesEnum.BATCH_RESPONSE_LOOP );

        return container.getBatchResponse().getCurrentResponse();
    }


    /**
     * Parses all the responses
     *
     * @throws XmlPullParserException when an error occurs during the parsing
     */
    public void parseAllResponses() throws XmlPullParserException
    {
        while ( getNextResponse() != null )
        {
            continue;
        }
    }
}
