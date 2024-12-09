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
package org.apache.directory.api.ldap.codec.controls.search.entryChange;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoder;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoderException;
import org.apache.directory.api.asn1.ber.tlv.LongDecoder;
import org.apache.directory.api.asn1.ber.tlv.LongDecoderException;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.controls.ChangeType;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements the EntryChangeControl. All the actions are declared in
 * this class. As it is a singleton, these declaration are only done once.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class EntryChangeGrammar extends AbstractGrammar<EntryChangeContainer>
{
    /** The logger */
    static final Logger LOG = LoggerFactory.getLogger( EntryChangeGrammar.class );

    /** The instance of grammar. EntryChangeGrammar is a singleton */
    private static Grammar<?> instance = new EntryChangeGrammar();


    /**
     * Creates a new EntryChangeGrammar object.
     */
    @SuppressWarnings("unchecked")
    private EntryChangeGrammar()
    {
        setName( EntryChangeGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[EntryChangeStates.LAST_EC_STATE.ordinal()][256];

        // ============================================================================================
        // Transition from start state to Entry Change sequence
        // ============================================================================================
        // EntryChangeNotification ::= SEQUENCE {
        //     ...
        //
        // Initialization of the structure
        super.transitions[EntryChangeStates.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<EntryChangeContainer>( EntryChangeStates.START_STATE,
                EntryChangeStates.EC_SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(), null, FollowUp.OPTIONAL );

        // ============================================================================================
        // transition from Entry Change sequence to Change Type
        // ============================================================================================
        // EntryChangeNotification ::= SEQUENCE {
        //     changeType ENUMERATED {
        //     ...
        //
        // Evaluates the changeType
        super.transitions[EntryChangeStates.EC_SEQUENCE_STATE.ordinal()][UniversalTag.ENUMERATED.getValue()] =
            new GrammarTransition<EntryChangeContainer>( EntryChangeStates.EC_SEQUENCE_STATE,
                EntryChangeStates.CHANGE_TYPE_STATE,
                UniversalTag.ENUMERATED.getValue(),
                new GrammarAction<EntryChangeContainer>( "Set EntryChangeControl changeType" )
                {
                    public void action( EntryChangeContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            int change = IntegerDecoder.parse( value, 1, 8 );

                            switch ( ChangeType.getChangeType( change ) )
                            {
                                case ADD:
                                case DELETE:
                                case MODDN:
                                case MODIFY:
                                    ChangeType changeType = ChangeType.getChangeType( change );

                                    if ( LOG.isDebugEnabled() )
                                    {
                                        LOG.debug( I18n.msg( I18n.MSG_05300_CHANGE_TYPE, changeType ) );
                                    }

                                    container.getEntryChange().setChangeType( changeType );
                                    break;

                                default:
                                    String msg = I18n.err( I18n.ERR_05300_CANT_DECODE_CHANGE_TYPE );
                                    LOG.error( msg );
                                    throw new DecoderException( msg );
                            }

                            // We can have an END transition
                            container.setGrammarEndAllowed( true );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            String msg = I18n.err( I18n.ERR_05300_CANT_DECODE_CHANGE_TYPE );
                            LOG.error( msg, ide );
                            throw new DecoderException( msg, ide );
                        }
                        catch ( IllegalArgumentException iae )
                        {
                            throw new DecoderException( iae.getLocalizedMessage(), iae );
                        }
                    }
                }, FollowUp.OPTIONAL );

        // ============================================================================================
        // Transition from Change Type to Previous Dn
        // ============================================================================================
        // EntryChangeNotification ::= SEQUENCE {
        //     ...
        //     previousDN LDAPDN OPTIONAL,
        //     ...
        //
        // Set the previousDN into the structure. We first check that it's a
        // valid Dn
        super.transitions[EntryChangeStates.CHANGE_TYPE_STATE.ordinal()][UniversalTag.OCTET_STRING.getValue()] =
            new GrammarTransition<EntryChangeContainer>( EntryChangeStates.CHANGE_TYPE_STATE,
                EntryChangeStates.PREVIOUS_DN_STATE,
                UniversalTag.OCTET_STRING.getValue(),
                new GrammarAction<EntryChangeContainer>( "Set EntryChangeControl previousDN" )
                {
                    public void action( EntryChangeContainer container ) throws DecoderException
                    {
                        ChangeType changeType = container.getEntryChange().getChangeType();

                        if ( changeType != ChangeType.MODDN )
                        {
                            LOG.error( I18n.err( I18n.ERR_05301_INVALID_PREVIOUS_DN ) );
                            throw new DecoderException( I18n.err( I18n.ERR_05302_PREVIOUS_DN_NOT_ALLOWED ) );
                        }
                        else
                        {
                            BerValue value = container.getCurrentTLV().getValue();
                            Dn previousDn;

                            try
                            {
                                previousDn = new Dn( Strings.utf8ToString( value.getData() ) );
                            }
                            catch ( LdapInvalidDnException ine )
                            {
                                LOG.error( I18n.err( I18n.ERR_05303_BAD_PREVIOUS_DN, Strings.dumpBytes( value.getData() ) ) );
                                throw new DecoderException( I18n.err( I18n.ERR_05304_FAILED_TO_DECODE_PREVIOUS_DN ), ine );
                            }

                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_05301_PREVIOUS_DN, previousDn ) );
                            }

                            container.getEntryChange().setPreviousDn( previousDn );

                            // We can have an END transition
                            container.setGrammarEndAllowed( true );
                        }
                    }
                }, FollowUp.OPTIONAL );

        // Change Number action
        GrammarAction<EntryChangeContainer> setChangeNumberAction = new GrammarAction<EntryChangeContainer>(
            "Set EntryChangeControl changeNumber" )
        {
            public void action( EntryChangeContainer container ) throws DecoderException
            {
                BerValue value = container.getCurrentTLV().getValue();

                try
                {
                    long changeNumber = LongDecoder.parse( value );

                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.msg( I18n.MSG_05302_CHANGE_NUMBER, changeNumber ) );
                    }

                    container.getEntryChange().setChangeNumber( changeNumber );

                    // We can have an END transition
                    container.setGrammarEndAllowed( true );
                }
                catch ( LongDecoderException lde )
                {
                    String msg = I18n.err( I18n.ERR_05305_CHANGE_NUMBER_DECODING_ERROR );
                    LOG.error( msg, lde );
                    throw new DecoderException( msg, lde );
                }
            }
        };

        // ============================================================================================
        // Transition from Previous Dn to Change Number
        // ============================================================================================
        // EntryChangeNotification ::= SEQUENCE {
        //     ...
        //     changeNumber INTEGER OPTIONAL
        // }
        //
        // Set the changeNumber into the structure
        super.transitions[EntryChangeStates.PREVIOUS_DN_STATE.ordinal()][UniversalTag.INTEGER.getValue()] =
            new GrammarTransition<EntryChangeContainer>( EntryChangeStates.PREVIOUS_DN_STATE,
                EntryChangeStates.CHANGE_NUMBER_STATE,
                UniversalTag.INTEGER.getValue(),
                setChangeNumberAction, FollowUp.OPTIONAL );

        // ============================================================================================
        // Transition from Previous Dn to Change Number
        // ============================================================================================
        // EntryChangeNotification ::= SEQUENCE {
        //     ...
        //     changeNumber INTEGER OPTIONAL
        // }
        //
        // Set the changeNumber into the structure
        super.transitions[EntryChangeStates.CHANGE_TYPE_STATE.ordinal()][UniversalTag.INTEGER.getValue()] =
            new GrammarTransition<EntryChangeContainer>( EntryChangeStates.CHANGE_TYPE_STATE,
                EntryChangeStates.CHANGE_NUMBER_STATE,
                UniversalTag.INTEGER.getValue(),
                setChangeNumberAction, FollowUp.OPTIONAL );
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
