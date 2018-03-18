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
package org.apache.directory.api.ldap.extras.controls.policyHints_impl;


import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The LdapServerPolicyHintsOid grammar
 *
 */
public final class LdapServerPolicyHintsOidGrammar extends AbstractGrammar<LdapServerPolicyHintsOidContainer>
{
    static final Logger LOG = LoggerFactory.getLogger( LdapServerPolicyHintsOidGrammar.class );

    static final boolean IS_DEBUG = LOG.isDebugEnabled();

    private static Grammar<?> instance = new LdapServerPolicyHintsOidGrammar();


    @SuppressWarnings("unchecked")
    private LdapServerPolicyHintsOidGrammar()
    {
        setName( LdapServerPolicyHintsOidGrammar.class.getName() );

        super.transitions = new GrammarTransition[LdapServerPolicyHintsOidStates.END_STATE.ordinal()][256];

        super.transitions[LdapServerPolicyHintsOidStates.START_STATE.ordinal()][UniversalTag.SEQUENCE
            .getValue()] = new GrammarTransition<LdapServerPolicyHintsOidContainer>(
                LdapServerPolicyHintsOidStates.START_STATE, LdapServerPolicyHintsOidStates.LSPHO_SEQUENCE_STATE,
                UniversalTag.SEQUENCE.getValue(), null );

        super.transitions[LdapServerPolicyHintsOidStates.LSPHO_SEQUENCE_STATE.ordinal()][UniversalTag.INTEGER
            .getValue()] = new GrammarTransition<LdapServerPolicyHintsOidContainer>(
                LdapServerPolicyHintsOidStates.LSPHO_SEQUENCE_STATE,
                LdapServerPolicyHintsOidStates.LSPHO_FLAGS_STATE, UniversalTag.INTEGER.getValue(),
                new StoreFlags() );
    }


    /**
     * @return the singleton instance of the LdapServerPolicyHintsOidGrammar
     */
    public static Grammar<?> getInstance()
    {
        return instance;
    }
}