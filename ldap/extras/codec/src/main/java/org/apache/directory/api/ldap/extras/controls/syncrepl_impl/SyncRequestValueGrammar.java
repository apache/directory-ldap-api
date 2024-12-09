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
import org.apache.directory.api.asn1.ber.tlv.BooleanDecoder;
import org.apache.directory.api.asn1.ber.tlv.BooleanDecoderException;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoder;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoderException;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.extras.controls.SynchronizationModeEnum;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements the SyncRequestValueControl. All the actions are declared in
 * this class. As it is a singleton, these declaration are only done once.
 * 
 * The decoded grammar is the following :
 * 
 * syncRequestValue ::= SEQUENCE {
 *     mode ENUMERATED {
 *     -- 0 unused
 *     refreshOnly       (1),
 *     -- 2 reserved
 *     refreshAndPersist (3)
 *     },
 *     cookie     syncCookie OPTIONAL,
 *     reloadHint BOOLEAN DEFAULT FALSE
 * }
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class SyncRequestValueGrammar extends AbstractGrammar<SyncRequestValueContainer>
{
    /** The logger */
    static final Logger LOG = LoggerFactory.getLogger( SyncRequestValueGrammar.class );

    /** The instance of grammar. SyncRequestValueControlGrammar is a singleton */
    private static Grammar<SyncRequestValueContainer> instance = new SyncRequestValueGrammar();


    /**
     * Creates a new SyncRequestValueControlGrammar object.
     */
    @SuppressWarnings("unchecked")
    private SyncRequestValueGrammar()
    {
        setName( SyncRequestValueGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[SyncRequestValueStatesEnum.LAST_SYNC_REQUEST_VALUE_STATE.ordinal()][256];

        /** 
         * Transition from initial state to SyncRequestValue sequence
         * SyncRequestValue ::= SEQUENCE OF {
         *     ...
         *     
         * Initialize the syncRequestValue object
         */
        super.transitions[SyncRequestValueStatesEnum.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<SyncRequestValueContainer>( 
                SyncRequestValueStatesEnum.START_STATE,
                SyncRequestValueStatesEnum.SYNC_REQUEST_VALUE_SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(),
                null,
                FollowUp.OPTIONAL );

        /** 
         * Transition from SyncRequestValue sequence to Change types
         * SyncRequestValue ::= SEQUENCE OF {
         *     mode ENUMERATED {
         *         -- 0 unused
         *         refreshOnly       (1),
         *         -- 2 reserved
         *         refreshAndPersist (3)
         *     },
         *     ...
         *     
         * Stores the mode value
         */
        super.transitions[SyncRequestValueStatesEnum.SYNC_REQUEST_VALUE_SEQUENCE_STATE.ordinal()][UniversalTag.ENUMERATED
            .getValue()] =
            new GrammarTransition<SyncRequestValueContainer>(
                SyncRequestValueStatesEnum.SYNC_REQUEST_VALUE_SEQUENCE_STATE,
                SyncRequestValueStatesEnum.MODE_STATE,
                UniversalTag.ENUMERATED.getValue(),
                new GrammarAction<SyncRequestValueContainer>( "Set SyncRequestValueControl mode" )
                {
                    public void action( SyncRequestValueContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            // Check that the value is into the allowed interval
                            int mode = IntegerDecoder.parse( value,
                                SynchronizationModeEnum.UNUSED.getValue(),
                                SynchronizationModeEnum.REFRESH_AND_PERSIST.getValue() );

                            SynchronizationModeEnum modeEnum = SynchronizationModeEnum.getSyncMode( mode );

                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_08100_MODE, modeEnum ) );
                            }

                            container.getSyncRequestValue().setMode( modeEnum );

                            // We can have an END transition
                            container.setGrammarEndAllowed( true );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            String msg = I18n.err( I18n.ERR_08100_SYNC_REQUEST_VALUE_MODE_DECODING_FAILED );
                            LOG.error( msg, ide );
                            throw new DecoderException( msg, ide );
                        }
                    }
                },
                FollowUp.OPTIONAL );

        /** 
         * Transition from mode to cookie
         * SyncRequestValue ::= SEQUENCE OF {
         *     ...
         *     cookie     syncCookie OPTIONAL,
         *     ...
         *     
         * Stores the cookie
         */
        super.transitions[SyncRequestValueStatesEnum.MODE_STATE.ordinal()][UniversalTag.OCTET_STRING.getValue()] =
            new GrammarTransition<SyncRequestValueContainer>( 
                SyncRequestValueStatesEnum.MODE_STATE,
                SyncRequestValueStatesEnum.COOKIE_STATE, 
                UniversalTag.OCTET_STRING.getValue(),
                new GrammarAction<SyncRequestValueContainer>( "Set SyncRequestValueControl cookie" )
                {
                    public void action( SyncRequestValueContainer container )
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] cookie = value.getData();

                        if ( LOG.isDebugEnabled() )
                        {
                            LOG.debug( I18n.msg( I18n.MSG_08000_COOKIE, Strings.dumpBytes( cookie ) ) );
                        }

                        container.getSyncRequestValue().setCookie( cookie );

                        // We can have an END transition
                        container.setGrammarEndAllowed( true );
                    }
                },
                FollowUp.OPTIONAL );

        /** 
         * Transition from mode to reloadHint
         * SyncRequestValue ::= SEQUENCE OF {
         *     ...
         *     reloadHint BOOLEAN DEFAULT FALSE
         * }
         *     
         * Stores the reloadHint flag
         */
        super.transitions[SyncRequestValueStatesEnum.MODE_STATE.ordinal()][UniversalTag.BOOLEAN.getValue()] =
            new GrammarTransition<SyncRequestValueContainer>( 
                SyncRequestValueStatesEnum.MODE_STATE,
                SyncRequestValueStatesEnum.RELOAD_HINT_STATE, 
                UniversalTag.BOOLEAN.getValue(),
                new GrammarAction<SyncRequestValueContainer>( "Set SyncRequestValueControl reloadHint flag" )
                {
                    public void action( SyncRequestValueContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            boolean reloadHint = BooleanDecoder.parse( value );

                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_08104_RELOAD_HINT, reloadHint ) );
                            }

                            container.getSyncRequestValue().setReloadHint( reloadHint );

                            // We can have an END transition
                            container.setGrammarEndAllowed( true );
                        }
                        catch ( BooleanDecoderException bde )
                        {
                            String msg = I18n.err( I18n.ERR_08101_RELOAD_HINT_DECODING_FAILED );
                            LOG.error( msg, bde );
                            throw new DecoderException( msg, bde );
                        }
                    }
                },
                FollowUp.OPTIONAL );

        /** 
         * Transition from cookie to reloadHint
         * SyncRequestValue ::= SEQUENCE OF {
         *     ...
         *     reloadHint BOOLEAN DEFAULT FALSE
         * }
         *     
         * Stores the reloadHint flag
         */
        super.transitions[SyncRequestValueStatesEnum.COOKIE_STATE.ordinal()][UniversalTag.BOOLEAN.getValue()] =
            new GrammarTransition<SyncRequestValueContainer>( 
                SyncRequestValueStatesEnum.COOKIE_STATE,
                SyncRequestValueStatesEnum.RELOAD_HINT_STATE, 
                UniversalTag.BOOLEAN.getValue(),
                new GrammarAction<SyncRequestValueContainer>( "Set SyncRequestValueControl reloadHint flag" )
                {
                    public void action( SyncRequestValueContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            boolean reloadHint = BooleanDecoder.parse( value );

                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_08104_RELOAD_HINT, reloadHint ) );
                            }

                            container.getSyncRequestValue().setReloadHint( reloadHint );

                            // We can have an END transition
                            container.setGrammarEndAllowed( true );
                        }
                        catch ( BooleanDecoderException bde )
                        {
                            String msg = I18n.err( I18n.ERR_08101_RELOAD_HINT_DECODING_FAILED );
                            LOG.error( msg, bde );
                            throw new DecoderException( msg, bde );
                        }
                    }
                },
                FollowUp.OPTIONAL );
    }


    /**
     * This class is a singleton.
     * 
     * @return An instance on this grammar
     */
    public static Grammar<SyncRequestValueContainer> getInstance()
    {
        return instance;
    }
}
