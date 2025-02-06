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
 *
 * Implementation of AdDirSync Request Control. All the actions are declared in
 * this class. As it is a singleton, these declaration are only done once.
 *
 *  The decoded grammar is as follows :
 *
 *  <pre>
 * realReplControlValue ::= SEQUENCE {
 *     parentsFirst          integer
 *     maxAttributeCount     integer
 *     cookie                OCTET STRING
 * }
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class AdDirSyncRequestGrammar extends AbstractGrammar<AdDirSyncRequestContainer>
{

    /** the logger */
    private static final Logger LOG = LoggerFactory.getLogger( AdDirSyncRequestGrammar.class );

    /** AdDirSyncRequestControlGrammar singleton instance */
    private static final AdDirSyncRequestGrammar INSTANCE = new AdDirSyncRequestGrammar();


    /**
     *
     * Creates a new instance of AdDirSyncRequestControlGrammar.
     *
     */
    @SuppressWarnings("unchecked")
    private AdDirSyncRequestGrammar()
    {
        setName( AdDirSyncRequestGrammar.class.getName() );

        super.transitions = new GrammarTransition[AdDirSyncRequestStatesEnum.LAST_AD_DIR_SYNC_REQUEST_STATE.ordinal()][256];

        /**
         * Transition from initial state to AdDirSyncRequest sequence
         * AdDirSync ::= SEQUENCE {
         *     ...
         *
         * Initialize the adDirSyncRequest object
         */
        super.transitions[AdDirSyncRequestStatesEnum.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<AdDirSyncRequestContainer>(
            AdDirSyncRequestStatesEnum.START_STATE, AdDirSyncRequestStatesEnum.AD_DIR_SYNC_REQUEST_SEQUENCE_STATE,
            UniversalTag.SEQUENCE.getValue(),
            new GrammarAction<AdDirSyncRequestContainer>( "Initialization" )
            {
                @Override
                public void action( AdDirSyncRequestContainer container ) throws DecoderException
                {
                }
            },
            FollowUp.MANDATORY );


        /**
         * transition from start to parentsFirst
         * realReplControlValue ::= SEQUENCE {
         *     parentsFirst          integer
         *    ....
         * }
         */
        super.transitions[AdDirSyncRequestStatesEnum.AD_DIR_SYNC_REQUEST_SEQUENCE_STATE.ordinal()][UniversalTag.INTEGER
            .getValue()] =
            new GrammarTransition<AdDirSyncRequestContainer>( AdDirSyncRequestStatesEnum.AD_DIR_SYNC_REQUEST_SEQUENCE_STATE,
                AdDirSyncRequestStatesEnum.PARENTS_FIRST_STATE, UniversalTag.INTEGER.getValue(),
                new GrammarAction<AdDirSyncRequestContainer>( "Set AdDirSyncRequestControl parentsFirst" )
                {
                    @Override
                    public void action( AdDirSyncRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            int parentsFirst = IntegerDecoder.parse( value );

                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_08108_PARENTS_FIRST, parentsFirst ) );
                            }

                            container.getAdDirSyncRequest().setParentsFirst( parentsFirst );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            String msg = I18n.err( I18n.ERR_08107_AD_DIR_SYNC_PARENTS_FIRST_DECODING_ERROR, ide.getMessage() );
                            LOG.error( msg, ide );
                            throw new DecoderException( msg, ide );
                        }
                    }
                },
                FollowUp.MANDATORY );


        /**
         * transition from flag to maxAttributeCount
         * realReplControlValue ::= SEQUENCE {
         *     parentsFirst          integer
         *     maxAttributeCount     integer
         *    ....
         * }
         */
        super.transitions[AdDirSyncRequestStatesEnum.PARENTS_FIRST_STATE.ordinal()][UniversalTag.INTEGER
            .getValue()] =
            new GrammarTransition<AdDirSyncRequestContainer>( AdDirSyncRequestStatesEnum.PARENTS_FIRST_STATE,
                AdDirSyncRequestStatesEnum.MAX_ATTRIBUTE_COUNT_STATE, UniversalTag.INTEGER.getValue(),
                new GrammarAction<AdDirSyncRequestContainer>( "Set AdDirSyncRequestControl maxAttributeCount" )
                {
                    @Override
                    public void action( AdDirSyncRequestContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            int maxAttributeCount = IntegerDecoder.parse( value );

                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.msg( I18n.MSG_08109_MAX_ATTRIBUTE_COUNT, maxAttributeCount ) );
                            }

                            container.getAdDirSyncRequest().setMaxAttributeCount( maxAttributeCount );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            String msg = I18n.err( I18n.ERR_08108_AD_DIR_SYNC_MAX_ATTRIBUTE_COUNT_DECODING_ERROR, ide.getMessage() );
                            LOG.error( msg, ide );
                            throw new DecoderException( msg, ide );
                        }
                    }
                },
                FollowUp.MANDATORY );


        /**
         * transition from maxAttributeCount to cookie
         *     ...
         *     maxAttributeCount         integer
         *     cookie                  OCTET STRING
         * }
         */
        super.transitions[AdDirSyncRequestStatesEnum.MAX_ATTRIBUTE_COUNT_STATE.ordinal()][UniversalTag.OCTET_STRING
            .getValue()] =
            new GrammarTransition<AdDirSyncRequestContainer>( AdDirSyncRequestStatesEnum.MAX_ATTRIBUTE_COUNT_STATE,
                AdDirSyncRequestStatesEnum.COOKIE_STATE, UniversalTag.OCTET_STRING.getValue(),
                new GrammarAction<AdDirSyncRequestContainer>( "Set AdDirSyncRequestControl cookie" )
                {
                    @Override
                    public void action( AdDirSyncRequestContainer container )
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] cookie = value.getData();

                        if ( LOG.isDebugEnabled() )
                        {
                            LOG.debug( I18n.msg( I18n.MSG_08000_COOKIE, Strings.dumpBytes( cookie ) ) );
                        }

                        container.getAdDirSyncRequest().setCookie( cookie );

                        container.setGrammarEndAllowed( true );
                    }
                },
                FollowUp.OPTIONAL );
    }


    /**
     * Get the grammar instance
     * 
     * @return the singleton instance of the AdDirSyncControlGrammar
     */
    public static Grammar<AdDirSyncRequestContainer> getInstance()
    {
        return INSTANCE;
    }
}
