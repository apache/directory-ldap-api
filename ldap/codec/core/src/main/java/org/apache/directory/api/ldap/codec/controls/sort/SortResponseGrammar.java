/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.codec.controls.sort;


import static org.apache.directory.api.ldap.codec.controls.sort.SortResponseFactory.ATTRIBUTE_TYPE_TAG;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Grammar for decoding SortResponseControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class SortResponseGrammar extends AbstractGrammar<SortResponseContainer>
{
    /** The logger */
    static final Logger LOG = LoggerFactory.getLogger( SortRequestGrammar.class );

    /** The instance of grammar. SortResponseGrammar is a singleton */
    private static Grammar<SortResponseContainer> instance = new SortResponseGrammar();


    @SuppressWarnings("unchecked")
    private SortResponseGrammar()
    {
        setName( SortResponseGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[SortResponseStates.END_STATE.ordinal()][256];

        super.transitions[SortResponseStates.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] =
            new GrammarTransition<SortResponseContainer>( SortResponseStates.START_STATE,
                SortResponseStates.SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(), null, FollowUp.OPTIONAL );

        super.transitions[SortResponseStates.SEQUENCE_STATE.ordinal()][UniversalTag.ENUMERATED.getValue()] =
            new GrammarTransition<SortResponseContainer>( SortResponseStates.SEQUENCE_STATE,
                SortResponseStates.RESULT_CODE_STATE,
                UniversalTag.ENUMERATED.getValue(), new StoreSortResponseResultCode<SortResponseContainer>(), FollowUp.OPTIONAL );

        super.transitions[SortResponseStates.RESULT_CODE_STATE.ordinal()][ATTRIBUTE_TYPE_TAG] =
            new GrammarTransition<SortResponseContainer>( SortResponseStates.RESULT_CODE_STATE,
                SortResponseStates.AT_DESC_STATE,
                ATTRIBUTE_TYPE_TAG, new GrammarAction<SortResponseContainer>()
                {

                    @Override
                    public void action( SortResponseContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        String atType = Strings.utf8ToString( value.getData() );

                        if ( LOG.isDebugEnabled() )
                        {
                            LOG.debug( I18n.msg( I18n.MSG_05310_ATTRIBUTE_TYPE, atType ) );
                        }

                        container.getControl().setAttributeName( atType );
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
