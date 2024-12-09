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
package org.apache.directory.api.ldap.codec.controls.search.pagedSearch;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoder;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoderException;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements the PagedSearchControl. All the actions are declared in
 * this class. As it is a singleton, these declaration are only done once.
 * 
 * The decoded grammar is the following :
 * 
 * realSearchControlValue ::= SEQUENCE {
 *     size   INTEGER,
 *     cookie OCTET STRING,
 * }
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class PagedResultsGrammar extends AbstractGrammar<PagedResultsContainer>
{
    /** The logger */
    static final Logger LOG = LoggerFactory.getLogger( PagedResultsGrammar.class );

    /** The instance of grammar. PagedSearchControlGrammar is a singleton */
    private static Grammar<?> instance = new PagedResultsGrammar();


    /**
     * Creates a new PagedSearchControlGrammar object.
     */
    @SuppressWarnings("unchecked")
    private PagedResultsGrammar()
    {
        setName( PagedResultsGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[PagedResultsStates.LAST_PAGED_SEARCH_STATE.ordinal()][256];

        /** 
         * Transition from initial state to PagedSearch sequence
         * realSearchControlValue ::= SEQUENCE OF {
         *     ...
         *     
         * Nothing to do
         */
        super.transitions[PagedResultsStates.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<PagedResultsContainer>( PagedResultsStates.START_STATE,
                PagedResultsStates.PAGED_SEARCH_SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(), null, FollowUp.OPTIONAL );

        /** 
         * Transition from PagedSearch sequence to size
         * 
         * realSearchControlValue ::= SEQUENCE OF {
         *     size  INTEGER,  -- INTEGER (0..maxInt),
         *     ...
         *     
         * Stores the size value
         */
        super.transitions[PagedResultsStates.PAGED_SEARCH_SEQUENCE_STATE.ordinal()][UniversalTag.INTEGER.getValue()] =
            new GrammarTransition<PagedResultsContainer>( PagedResultsStates.PAGED_SEARCH_SEQUENCE_STATE,
                PagedResultsStates.SIZE_STATE,
                UniversalTag.INTEGER.getValue(),
                new GrammarAction<PagedResultsContainer>( "Set PagedSearchControl size" )
                {
                    public void action( PagedResultsContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            // Check that the value is into the allowed interval
                            int size = IntegerDecoder.parse( value, Integer.MIN_VALUE, Integer.MAX_VALUE );

                            // We allow negative value to absorb a bug in some M$ client.
                            // Those negative values will be transformed to Integer.MAX_VALUE.
                            if ( size < 0 )
                            {
                                size = Integer.MAX_VALUE;
                            }

                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_05303_SIZE, size ) );
                            }

                            container.getPagedResults().setSize( size );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            String msg = I18n.err( I18n.ERR_05306_PAGED_SEARCH_SIZE_DECODING_ERROR );
                            LOG.error( msg, ide );
                            throw new DecoderException( msg, ide );
                        }
                    }
                }, FollowUp.OPTIONAL );

        /** 
         * Transition from size to cookie
         * realSearchControlValue ::= SEQUENCE OF {
         *     ...
         *     cookie   OCTET STRING
         * }
         *     
         * Stores the cookie flag
         */
        super.transitions[PagedResultsStates.SIZE_STATE.ordinal()][UniversalTag.OCTET_STRING.getValue()] =
            new GrammarTransition<PagedResultsContainer>( PagedResultsStates.SIZE_STATE,
                PagedResultsStates.COOKIE_STATE, UniversalTag.OCTET_STRING.getValue(),
                new GrammarAction<PagedResultsContainer>( "Set PagedSearchControl cookie" )
                {
                    public void action( PagedResultsContainer container )
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        if ( container.getCurrentTLV().getLength() == 0 )
                        {
                            container.getPagedResults().setCookie( Strings.EMPTY_BYTES );
                        }
                        else
                        {
                            container.getPagedResults().setCookie( value.getData() );
                        }

                        // We can have an END transition
                        container.setGrammarEndAllowed( true );
                    }
                }, FollowUp.OPTIONAL );
    }


    /**
     * This class is a singleton.
     * 
     * @return An instance on this grammar
     */
    public static Grammar<?> getInstance()
    {
        return instance;
    }
}
