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
package org.apache.directory.api.ldap.extras.controls.ad;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoder;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoderException;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * 
 * Implementation of AdDirSyncResponse Control. All the actions are declared in
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

    /** speedup for logger */
    private static final boolean IS_DEBUG = LOG.isDebugEnabled();

    /** AdDirSyncControlGrammar singleton instance */
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
         * AdDirSyncResponse ::= SEQUENCE {
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
                public void action( AdDirSyncResponseContainer container ) throws DecoderException
                {
                }
            } );

        
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
                new GrammarAction<AdDirSyncResponseContainer>( "Set AdDirSyncResponseControl parentFirst" )
                {
                    public void action( AdDirSyncResponseContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            int flagValue = IntegerDecoder.parse( value );
                            
                            AdDirSyncFlag flag = AdDirSyncFlag.getFlag( flagValue );
                            
                            if ( flag == null )
                            {
                                String msg = "Error while decoding the AdDirSync flag, unknown value : " + flagValue;
                                LOG.error( msg );
                                throw new DecoderException( msg );
                            }
                            
                            if ( IS_DEBUG )
                            {
                                LOG.debug( "flag = {}", flagValue );
                            }
                            
                            container.getAdDirSyncResponseControl().setFlag( flag );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            String msg = "Error while decoding the AdDirSyncResponse flag : " + ide.getMessage();
                            LOG.error( msg, ide );
                            throw new DecoderException( msg );
                        }
                    }
                } );

        
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
                    public void action( AdDirSyncResponseContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        try
                        {
                            int maxReturnLength = IntegerDecoder.parse( value );
                            
                            if ( IS_DEBUG )
                            {
                                LOG.debug( "maxReturnLength = {}", maxReturnLength );
                            }
                            
                            container.getAdDirSyncResponseControl().setMaxReturnLength( maxReturnLength );
                        }
                        catch ( IntegerDecoderException ide )
                        {
                            String msg = "Error while decoding the AdDirSyncResponse maxReturnLength : " + ide.getMessage();
                            LOG.error( msg, ide );
                            throw new DecoderException( msg );
                        }
                    }
                } );
        
        
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
                    public void action( AdDirSyncResponseContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        byte[] cookie = value.getData();

                        if ( IS_DEBUG )
                        {
                            LOG.debug( "cookie = {}", Strings.dumpBytes( cookie ) );
                        }

                        container.getAdDirSyncResponseControl().setCookie( cookie );

                        container.setGrammarEndAllowed( true );
                    }
                } );
    }


    /**
     * @return the singleton instance of the AdDirSyncResponseControlGrammar
     */
    public static Grammar<AdDirSyncResponseContainer> getInstance()
    {
        return INSTANCE;
    }
}
