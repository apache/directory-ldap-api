/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Grammar for decoding SortResponseControl. It's defined in https://tools.ietf.org/html/rfc2891
 * 
 * <pre>
 *       SortResult ::= SEQUENCE {
 *       sortResult  ENUMERATED {
 *           success                   (0), -- results are sorted
 *           operationsError           (1), -- server internal failure
 *           timeLimitExceeded         (3), -- timelimit reached before
 *                                          -- sorting was completed
 *           strongAuthRequired        (8), -- refused to return sorted
 *                                          -- results via insecure
 *                                          -- protocol
 *           adminLimitExceeded       (11), -- too many matching entries
 $                                          -- for the server to sort
 *           noSuchAttribute          (16), -- unrecognized attribute
 *                                          -- type in sort key
 *           inappropriateMatching    (18), -- unrecognized or
 *                                          -- inappropriate matching
 *                                          -- rule in sort key
 *           insufficientAccessRights (50), -- refused to return sorted
 *                                          -- results to this client
 *           busy                     (51), -- too busy to process
 *           unwillingToPerform       (53), -- unable to sort
 *           other                    (80)
 *           },
 *     attributeType [0] AttributeDescription OPTIONAL }
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class SortResponseGrammar extends AbstractGrammar<SortResponseContainer>
{
    /** The logger */
    static final Logger LOG = LoggerFactory.getLogger( SortRequestGrammar.class );

    /** Speedup for logs */
    static final boolean IS_DEBUG = LOG.isDebugEnabled();

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
                UniversalTag.SEQUENCE.getValue(), null );
        
        super.transitions[SortResponseStates.SEQUENCE_STATE.ordinal()][UniversalTag.ENUMERATED.getValue()] =
            new GrammarTransition<SortResponseContainer>( SortResponseStates.SEQUENCE_STATE,
                SortResponseStates.RESULT_CODE_STATE,
                UniversalTag.ENUMERATED.getValue(), new StoreSortResponseResultCode<SortResponseContainer>() );

        super.transitions[SortResponseStates.RESULT_CODE_STATE.ordinal()][UniversalTag.OCTET_STRING.getValue()] =
            new GrammarTransition<SortResponseContainer>( SortResponseStates.RESULT_CODE_STATE,
                SortResponseStates.AT_DESC_STATE,
                UniversalTag.OCTET_STRING.getValue(), new GrammarAction<SortResponseContainer>()
                {

                    @Override
                    public void action( SortResponseContainer container ) throws DecoderException
                    {
                        BerValue value = container.getCurrentTLV().getValue();

                        String atType = Strings.utf8ToString( value.getData() );
                        if ( IS_DEBUG )
                        {
                            LOG.debug( "AttributeType = " + atType );
                        }
                        
                        container.getControl().setAttributeName( atType );
                        container.setGrammarEndAllowed( true );
                    }
                } );

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
