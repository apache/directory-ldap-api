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
package org.apache.directory.api.ldap.extras.controls.ad_impl;

import java.util.Set;

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
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncResponseFlag;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 *
 * Implementation of AdDirSync Response Control. All the actions are declared in
 * this class. As it is a singleton, these declaration are only done once.
 *
 *  The decoded grammar is as follows :
 *
 *  <pre>
 * realReplControlValue ::= SEQUENCE {
 *     flag                  integer
 *     maxReturnLength       integer
 *     cookie                OCTET STRING
 * }
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class AdDirSyncResponseGrammar extends AbstractGrammar<AdDirSyncResponseContainer>
{

    /** the logger */
    private static final Logger LOG = LoggerFactory.getLogger( AdDirSyncResponseGrammar.class );

    /** AdDirSyncResponseControlGrammar singleton instance */
    private static final AdDirSyncResponseGrammar INSTANCE = new AdDirSyncResponseGrammar();


    /**
     *
     * Creates a new instance of AdDirSyncResponseControlGrammar.
     *
     */
    @SuppressWarnings("unchecked")
    private AdDirSyncResponseGrammar()
    {
        setName( AdDirSyncResponseGrammar.class.getName() );

        super.transitions = new GrammarTransition[AdDirSyncResponseStatesEnum.LAST_AD_DIR_SYNC_RESPONSE_STATE.ordinal()][256];

        /**
         * Transition from initial state to AdDirSyncResponse sequence
         * AdDirSync ::= SEQUENCE {
         *     ...
         *
         * Initialize the adDirSyncResponse object
         */
        super.transitions[AdDirSyncResponseStatesEnum.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<AdDirSyncResponseContainer>(
            AdDirSyncResponseStatesEnum.START_STATE, AdDirSyncResponseStatesEnum.AD_DIR_SYNC_RESPONSE_SEQUENCE_STATE,
            UniversalTag.SEQUENCE.getValue(),
            new GrammarAction<AdDirSyncResponseContainer>( "Initialization" )
            {
                @Override
                public void action( AdDirSyncResponseContainer container ) throws DecoderException
                {
                }
            },
            FollowUp.MANDATORY );


        /**
         * transition from start to flag
         * realReplControlValue ::= SEQUENCE {
         *     flag            integer
         *    ....
         * }
         */
        super.transitions[AdDirSyncResponseStatesEnum.AD_DIR_SYNC_RESPONSE_SEQUENCE_STATE.ordinal()][UniversalTag.INTEGER
            .getValue()] =
            new GrammarTransition<AdDirSyncResponseContainer>( AdDirSyncResponseStatesEnum.AD_DIR_SYNC_RESPONSE_SEQUENCE_STATE,
                AdDirSyncResponseStatesEnum.FLAG_STATE, UniversalTag.INTEGER.getValue(),
                new GrammarAction<AdDirSyncResponseContainer>( "Set AdDirSyncResponseControl flag" )
                {
                    @Override
                    public void action( AdDirSyncResponseContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            int flagValue = IntegerDecoder.parse( value );

                            Set<AdDirSyncResponseFlag> flags = AdDirSyncResponseFlag.getFlags( flagValue );

                            if ( flags == null )
                            {
                                String msg = I18n.err( I18n.ERR_08104_AD_DIR_SYNC_FLAG_DECODING_FAILURE, flagValue );
                                LOG.error( msg );
                                throw new DecoderException( msg );
                            }

                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_08101_FLAGS, flags.toString() ) );
                            }

                            container.getAdDirSyncResponseControl().setFlags( flags );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            String msg = I18n.err( I18n.ERR_08105_AD_DIR_SYNC_FLAG_DECODING_ERROR, ide.getMessage() );
                            LOG.error( msg, ide );
                            throw new DecoderException( msg, ide );
                        }
                    }
                },
                FollowUp.MANDATORY );


        /**
         * transition from flag to maxReturnLength
         * realReplControlValue ::= SEQUENCE {
         *     flag                    integer
         *     maxReturnLength         integer
         *    ....
         * }
         */
        super.transitions[AdDirSyncResponseStatesEnum.FLAG_STATE.ordinal()][UniversalTag.INTEGER
            .getValue()] =
            new GrammarTransition<AdDirSyncResponseContainer>( AdDirSyncResponseStatesEnum.FLAG_STATE,
                AdDirSyncResponseStatesEnum.MAX_RETURN_LENGTH_STATE, UniversalTag.INTEGER.getValue(),
                new GrammarAction<AdDirSyncResponseContainer>( "Set AdDirSyncResponseControl maxReturnLength" )
                {
                    @Override
                    public void action( AdDirSyncResponseContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            int maxReturnLength = IntegerDecoder.parse( value );

                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_08102_MAX_RETURN_LENGTH, maxReturnLength ) );
                            }

                            container.getAdDirSyncResponseControl().setMaxReturnLength( maxReturnLength );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            String msg = I18n.err( I18n.ERR_08106_AD_DIR_SYNC_MAX_RETURN_LENGTH_DECODING_ERROR, ide.getMessage() );
                            LOG.error( msg, ide );
                            throw new DecoderException( msg, ide );
                        }
                    }
                },
                FollowUp.MANDATORY );


        /**
         * transition from maxReturnLength to cookie
         *     ...
         *     maxReturnLength         integer
         *     cookie                  OCTET STRING
         * }
         */
        super.transitions[AdDirSyncResponseStatesEnum.MAX_RETURN_LENGTH_STATE.ordinal()][UniversalTag.OCTET_STRING
            .getValue()] =
            new GrammarTransition<AdDirSyncResponseContainer>( AdDirSyncResponseStatesEnum.MAX_RETURN_LENGTH_STATE,
                AdDirSyncResponseStatesEnum.COOKIE_STATE, UniversalTag.OCTET_STRING.getValue(),
                new GrammarAction<AdDirSyncResponseContainer>( "Set AdDirSyncResponseControl cookie" )
                {
                    @Override
                    public void action( AdDirSyncResponseContainer container )
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] cookie = value.getData();

                        if ( LOG.isDebugEnabled() )
                        {
                            LOG.debug( I18n.msg( I18n.MSG_08000_COOKIE, Strings.dumpBytes( cookie ) ) );
                        }

                        container.getAdDirSyncResponseControl().setCookie( cookie );

                        container.setGrammarEndAllowed( true );
                    }
                },
                FollowUp.OPTIONAL );
    }


    /**
     * @return the singleton instance of the AdDirSyncControlGrammar
     */
    public static Grammar<AdDirSyncResponseContainer> getInstance()
    {
        return INSTANCE;
    }
}
