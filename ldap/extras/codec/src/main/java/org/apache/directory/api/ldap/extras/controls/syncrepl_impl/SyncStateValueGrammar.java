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
package org.apache.directory.api.ldap.extras.controls.syncrepl_impl;


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
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncState.SyncStateTypeEnum;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements the SyncStateValueControl. All the actions are declared in
 * this class. As it is a singleton, these declaration are only done once.
 * 
 * The decoded grammar is the following :
 * 
 *  syncStateValue ::= SEQUENCE {
 *       state ENUMERATED {
 *            present (0),
 *            add (1),
 *            modify (2),
 *            delete (3)
 *       },
 *       entryUUID syncUUID,
 *       cookie    syncCookie OPTIONAL
 *  }
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class SyncStateValueGrammar extends AbstractGrammar<SyncStateValueContainer>
{
    /** The logger */
    static final Logger LOG = LoggerFactory.getLogger( SyncStateValueGrammar.class );

    /** The instance of grammar. SyncStateValueControlGrammar is a singleton */
    private static Grammar<SyncStateValueContainer> instance = new SyncStateValueGrammar();


    /**
     * Creates a new SyncStateValueControlGrammar object.
     */
    @SuppressWarnings("unchecked")
    private SyncStateValueGrammar()
    {
        setName( SyncStateValueGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[SyncStateValueStatesEnum.LAST_SYNC_STATE_VALUE_STATE.ordinal()][256];

        /** 
         * Transition from initial state to SyncStateValue sequence
         * SyncRequestValue ::= SEQUENCE OF {
         *     ...
         *     
         * Initialize the syncStateValue object
         */
        super.transitions[SyncStateValueStatesEnum.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] = new GrammarTransition<SyncStateValueContainer>(
            SyncStateValueStatesEnum.START_STATE, SyncStateValueStatesEnum.SYNC_STATE_VALUE_SEQUENCE_STATE,
            UniversalTag.SEQUENCE.getValue(), null );

        /** 
         * Transition from SyncStateValue sequence to state type enum
         * SyncRequestValue ::= SEQUENCE OF {
         *       state ENUMERATED {
         *            present (0),
         *            add (1),
         *            modify (2),
         *            delete (3)
         *       },
         *     ...
         *     
         * Stores the sync state type value
         */
        super.transitions[SyncStateValueStatesEnum.SYNC_STATE_VALUE_SEQUENCE_STATE.ordinal()][UniversalTag.ENUMERATED
            .getValue()] = 
            new GrammarTransition<SyncStateValueContainer>(
                SyncStateValueStatesEnum.SYNC_STATE_VALUE_SEQUENCE_STATE,
                SyncStateValueStatesEnum.SYNC_TYPE_STATE, UniversalTag.ENUMERATED.getValue(),
                new GrammarAction<SyncStateValueContainer>( "Set SyncStateValueControl state type" )
                {
                    public void action( SyncStateValueContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();
    
                        try
                        {
                            // Check that the value is into the allowed interval
                            int syncStateType = IntegerDecoder.parse( value, SyncStateTypeEnum.PRESENT.getValue(),
                                SyncStateTypeEnum.MODDN.getValue() );
    
                            SyncStateTypeEnum syncStateTypeEnum = SyncStateTypeEnum.getSyncStateType( syncStateType );
    
                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_08105_SYNC_STATE_TYPE, syncStateTypeEnum ) );
                            }
    
                            container.getSyncStateValue().setSyncStateType( syncStateTypeEnum );
    
                            // move on to the entryUUID transition
                            container.setGrammarEndAllowed( false );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            String msg = I18n.err( I18n.ERR_08102_SYNC_STATE_VALUE_MODE_DECODING_FAILED );
                            LOG.error( msg, ide );
                            throw new DecoderException( msg, ide );
                        }
                    }
                },
                FollowUp.MANDATORY );

        /** 
         * Transition from sync state tpe to entryUUID
         * SyncStateValue ::= SEQUENCE OF {
         *     ...
         *     entryUUID     syncUUID
         *     ...
         *     
         * Stores the entryUUID
         */
        super.transitions[SyncStateValueStatesEnum.SYNC_TYPE_STATE.ordinal()][UniversalTag.OCTET_STRING.getValue()] = 
            new GrammarTransition<SyncStateValueContainer>(
                SyncStateValueStatesEnum.SYNC_TYPE_STATE, SyncStateValueStatesEnum.SYNC_UUID_STATE,
                UniversalTag.OCTET_STRING.getValue(),
                new GrammarAction<SyncStateValueContainer>( "Set SyncStateValueControl entryUUID" )
                {
                    public void action( SyncStateValueContainer container )
                    {
                        BerValue value = container.getCurrentTLV().getValue();
    
                        byte[] entryUUID = value.getData();
    
                        if ( LOG.isDebugEnabled() )
                        {
                            LOG.debug( I18n.msg( I18n.MSG_08106_ENTRY_UUID, Strings.dumpBytes( entryUUID ) ) );
                        }
    
                        container.getSyncStateValue().setEntryUUID( entryUUID );
    
                        // We can have an END transition
                        container.setGrammarEndAllowed( true );
                    }
                },
                FollowUp.OPTIONAL );

        /** 
         * Transition from entryUUID to cookie
         * SyncRequestValue ::= SEQUENCE OF {
         *     ...
         *     cookie    syncCookie OPTIONAL
         * }
         *     
         * Stores the reloadHint flag
         */
        super.transitions[SyncStateValueStatesEnum.SYNC_UUID_STATE.ordinal()][UniversalTag.OCTET_STRING.getValue()] = 
            new GrammarTransition<SyncStateValueContainer>(
                SyncStateValueStatesEnum.SYNC_UUID_STATE, SyncStateValueStatesEnum.COOKIE_STATE,
                UniversalTag.OCTET_STRING.getValue(),
                new GrammarAction<SyncStateValueContainer>( "Set SyncStateValueControl cookie value" )
                {
                    public void action( SyncStateValueContainer container )
                    {
                        BerValue value = container.getCurrentTLV().getValue();
    
                        byte[] cookie = value.getData();
    
                        if ( LOG.isDebugEnabled() )
                        {
                            LOG.debug( I18n.msg( I18n.MSG_08000_COOKIE, Strings.dumpBytes( cookie ) ) );
                        }
    
                        container.getSyncStateValue().setCookie( cookie );
    
                        // terminal state
                        container.setGrammarEndAllowed( true );
                    }
                },
                FollowUp.OPTIONAL );
    }


    /**
     * This class is a singleton.
     * 
     * @return An instance on this grammar
     */
    public static Grammar<SyncStateValueContainer> getInstance()
    {
        return instance;
    }
}
