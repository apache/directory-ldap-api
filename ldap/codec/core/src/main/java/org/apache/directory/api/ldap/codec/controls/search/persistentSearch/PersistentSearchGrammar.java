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
package org.apache.directory.api.ldap.codec.controls.search.persistentSearch;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.BooleanDecoder;
import org.apache.directory.api.asn1.ber.tlv.BooleanDecoderException;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoder;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoderException;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.message.controls.PersistentSearch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements the PSearchControl. All the actions are declared in
 * this class. As it is a singleton, these declaration are only done once.
 * 
 * The decoded grammar is the following :
 * 
 * PersistenceSearch ::= SEQUENCE {
 *     changeTypes  INTEGER,  -- an OR combinaison of 0, 1, 2 and 4 --
 *     changeOnly   BOOLEAN,
 *     returnECs    BOOLEAN
 * }
 * 
 * The changeTypes field is the logical OR of one or more of these values:
 * add    (1), 
 * delete (2), 
 * modify (4), 
 * modDN  (8).
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class PersistentSearchGrammar extends AbstractGrammar<PersistentSearchContainer>
{
    /** The logger */
    static final Logger LOG = LoggerFactory.getLogger( PersistentSearchGrammar.class );

    /** The instance of grammar. PSearchControlGrammar is a singleton */
    private static Grammar<?> instance = new PersistentSearchGrammar();


    /**
     * Creates a new PSearchControlGrammar object.
     */
    @SuppressWarnings("unchecked")
    private PersistentSearchGrammar()
    {
        setName( PersistentSearchGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[PersistentSearchStates.LAST_PSEARCH_STATE.ordinal()][256];

        /** 
         * Transition from initial state to Psearch sequence
         * PSearch ::= SEQUENCE OF {
         *     ...
         *     
         * Initialize the persistence search object
         */
        super.transitions[PersistentSearchStates.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<PersistentSearchContainer>( PersistentSearchStates.START_STATE,
                PersistentSearchStates.PSEARCH_SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(), null, FollowUp.OPTIONAL );

        /** 
         * Transition from Psearch sequence to Change types
         * PSearch ::= SEQUENCE OF {
         *     changeTypes  INTEGER,  -- an OR combinaison of 0, 1, 2 and 4 --
         *     ...
         *     
         * Stores the change types value
         */
        super.transitions[PersistentSearchStates.PSEARCH_SEQUENCE_STATE.ordinal()][UniversalTag.INTEGER.getValue()] =
            new GrammarTransition<PersistentSearchContainer>( PersistentSearchStates.PSEARCH_SEQUENCE_STATE,
                PersistentSearchStates.CHANGE_TYPES_STATE,
                UniversalTag.INTEGER.getValue(),
                new GrammarAction<PersistentSearchContainer>( "Set PSearchControl changeTypes" )
                {
                    public void action( PersistentSearchContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            // Check that the value is into the allowed interval
                            int changeTypes = IntegerDecoder.parse( value,
                                PersistentSearch.CHANGE_TYPES_MIN,
                                PersistentSearch.CHANGE_TYPES_MAX );

                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_05304_CHANGE_TYPES, changeTypes ) );
                            }

                            container.getPersistentSearch().setChangeTypes( changeTypes );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            String msg = I18n.err( I18n.ERR_05307_CHANGE_TYPES_DECODING_ERROR );
                            LOG.error( msg, ide );
                            throw new DecoderException( msg, ide );
                        }
                    }
                }, FollowUp.OPTIONAL );

        /** 
         * Transition from Change types to Changes only
         * PSearch ::= SEQUENCE OF {
         *     ...
         *     changeOnly   BOOLEAN,
         *     ...
         *     
         * Stores the change only flag
         */
        super.transitions[PersistentSearchStates.CHANGE_TYPES_STATE.ordinal()][UniversalTag.BOOLEAN.getValue()] =
            new GrammarTransition<PersistentSearchContainer>( PersistentSearchStates.CHANGE_TYPES_STATE,
                PersistentSearchStates.CHANGES_ONLY_STATE, UniversalTag.BOOLEAN.getValue(),
                new GrammarAction<PersistentSearchContainer>( "Set PSearchControl changesOnly" )
                {
                    public void action( PersistentSearchContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            boolean changesOnly = BooleanDecoder.parse( value );

                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_05305_CHANGES_ONLY, changesOnly ) );
                            }

                            container.getPersistentSearch().setChangesOnly( changesOnly );
                        }
                        catch ( BooleanDecoderException bde )
                        {
                            String msg = I18n.err( I18n.ERR_05308_CHANGE_ONLY_DECODING_ERROR );
                            LOG.error( msg, bde );
                            throw new DecoderException( msg, bde );
                        }
                    }
                }, FollowUp.OPTIONAL );

        /** 
         * Transition from Change types to Changes only
         * PSearch ::= SEQUENCE OF {
         *     ...
         *     returnECs    BOOLEAN 
         * }
         *     
         * Stores the return ECs flag 
         */
        super.transitions[PersistentSearchStates.CHANGES_ONLY_STATE.ordinal()][UniversalTag.BOOLEAN.getValue()] =
            new GrammarTransition<PersistentSearchContainer>( PersistentSearchStates.CHANGES_ONLY_STATE,
                PersistentSearchStates.RETURN_ECS_STATE, UniversalTag.BOOLEAN.getValue(),
                new GrammarAction<PersistentSearchContainer>( "Set PSearchControl returnECs" )
                {
                    public void action( PersistentSearchContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            boolean returnECs = BooleanDecoder.parse( value );

                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_05306_RETURN_ECS, returnECs ) );
                            }

                            container.getPersistentSearch().setReturnECs( returnECs );

                            // We can have an END transition
                            container.setGrammarEndAllowed( true );
                        }
                        catch ( BooleanDecoderException bde )
                        {
                            String msg = I18n.err( I18n.ERR_05309_RETURN_ECS_DECODING_ERROR );
                            LOG.error( msg, bde );
                            throw new DecoderException( msg, bde );
                        }
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
