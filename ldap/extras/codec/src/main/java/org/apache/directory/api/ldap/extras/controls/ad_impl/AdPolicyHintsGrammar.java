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
package org.apache.directory.api.ldap.extras.controls.ad_impl;


import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The AdPolicyHints grammar
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class AdPolicyHintsGrammar extends AbstractGrammar<AdPolicyHintsContainer>
{
    static final Logger LOG = LoggerFactory.getLogger( AdPolicyHintsGrammar.class );

    static final boolean IS_DEBUG = LOG.isDebugEnabled();

    private static Grammar<?> instance = new AdPolicyHintsGrammar();


    @SuppressWarnings("unchecked")
    private AdPolicyHintsGrammar()
    {
        setName( AdPolicyHintsGrammar.class.getName() );

        super.transitions = new GrammarTransition[AdPolicyHintsStates.END_STATE.ordinal()][256];

        super.transitions[AdPolicyHintsStates.START_STATE.ordinal()][UniversalTag.SEQUENCE
            .getValue()] = new GrammarTransition<AdPolicyHintsContainer>(
                AdPolicyHintsStates.START_STATE, AdPolicyHintsStates.AD_POLICY_HINTS_SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(), null );

        super.transitions[AdPolicyHintsStates.AD_POLICY_HINTS_SEQUENCE_STATE.ordinal()][UniversalTag.INTEGER
            .getValue()] = new GrammarTransition<AdPolicyHintsContainer>(
                AdPolicyHintsStates.AD_POLICY_HINTS_SEQUENCE_STATE,
                AdPolicyHintsStates.AD_POLICY_HINTS_FLAGS_STATE, UniversalTag.INTEGER.getValue(),
                new StoreFlags() );
    }


    /**
     * @return the singleton instance of the AdPolicyHintsGrammar
     */
    public static Grammar<?> getInstance()
    {
        return instance;
    }
} 