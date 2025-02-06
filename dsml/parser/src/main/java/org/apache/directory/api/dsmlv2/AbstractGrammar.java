/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 * 
 *    https://www.apache.org/licenses/LICENSE-2.0
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
import java.util.HashMap;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.util.Strings;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;


/**
 * The abstract Grammar which is the Mother of all the grammars. It contains
 * the transitions table.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractGrammar implements Grammar
{
    /**
     * Table of transitions. It's a two dimension array, the first dimension
     * indexes the states, the second dimension indexes the Tag value, so it is
     * 256 wide.
     */
    protected HashMap<Tag, GrammarTransition>[] transitions;

    /** The grammar name */
    protected String name;

    /**
     * Default constructor
     */
    public AbstractGrammar() 
    {
        // Nothing to do
    }


    /**
     * Returns the grammar's name
     * 
     * @return The grammar name
     */
    @Override
    public String getName()
    {
        return name;
    }


    /**
     * Sets the grammar's name
     * 
     * @param name the name to set
     */
    @Override
    public void setName( String name )
    {
        this.name = name;
    }


    /**
     * Gets the transition associated with the state and tag
     * 
     * @param state The current state
     * @param tag The current tag
     * @return A valid transition if any, or null.
     */
    public GrammarTransition getTransition( Enum<Dsmlv2StatesEnum> state, Tag tag )
    {
        return transitions[state.ordinal()].get( tag );
    }


    /**
     * Gets the states of the current grammar
     * 
     * @return Returns the statesEnum.
     */
    @Override
    public Enum<Dsmlv2StatesEnum>[] getStatesEnum()
    {
        return Dsmlv2StatesEnum.values();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void executeAction( Dsmlv2Container container ) throws XmlPullParserException, IOException
    {
        XmlPullParser xpp = container.getParser();

        int eventType = xpp.getEventType();

        do
        {
            switch ( eventType )
            {
                case XmlPullParser.START_DOCUMENT:
                    container.setState( Dsmlv2StatesEnum.INIT_GRAMMAR_STATE );
                    break;

                case XmlPullParser.END_DOCUMENT:
                    container.setState( Dsmlv2StatesEnum.GRAMMAR_END );
                    break;

                case XmlPullParser.START_TAG:
                    processTag( container, Tag.START );
                    break;

                case XmlPullParser.END_TAG:
                    processTag( container, Tag.END );
                    break;

                default:
                    break;
            }

            eventType = xpp.next();
        }
        while ( eventType != XmlPullParser.END_DOCUMENT );
    }


    /**
     * Processes the task required in the grammar to the given tag type
     *
     * @param container the DSML container
     * @param tagType the tag type
     * @throws XmlPullParserException when an error occurs during the parsing
     */
    private void processTag( Dsmlv2Container container, int tagType ) throws XmlPullParserException
    {
        XmlPullParser xpp = container.getParser();

        String tagName = Strings.toLowerCaseAscii( xpp.getName() );

        GrammarTransition transition = getTransition( container.getState(), new Tag( tagName, tagType ) );

        if ( transition != null )
        {
            container.setState( transition.getNextState() );

            if ( transition.hasAction() )
            {
                GrammarAction action = transition.getAction();
                action.action( container );
            }
        }
        else
        {
            throw new XmlPullParserException( I18n.err( I18n.ERR_03036_MISSING_TAG, new Tag( tagName, tagType ) ), xpp, null );
        }
    }
}
