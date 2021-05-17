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

package org.apache.directory.api.ldap.extras.controls.ppolicy_impl;


import org.apache.directory.api.asn1.actions.CheckNotNullLength;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;


/**
 * Grammar for decoding PasswordPolicyResponseControl.
 *
 * PasswordPolicyResponseValue ::= SEQUENCE {
 *      warning [0] CHOICE {
 *         timeBeforeExpiration [0] INTEGER (0 .. maxInt),
 *         graceAuthNsRemaining [1] INTEGER (0 .. maxInt) 
 *      } OPTIONAL,
 *      error   [1] ENUMERATED {
 *          passwordExpired             (0),
 *          accountLocked               (1),
 *          changeAfterReset            (2),
 *          passwordModNotAllowed       (3),
 *          mustSupplyOldPassword       (4),
 *          insufficientPasswordQuality (5),
 *          passwordTooShort            (6),
 *          passwordTooYoung            (7),
 *          passwordInHistory           (8) 
 *      } OPTIONAL 
 * }
 *          
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class PasswordPolicyResponseGrammar extends AbstractGrammar<PasswordPolicyResponseContainer>
{
    /** PasswordPolicyResponseControlGrammar singleton instance */
    private static final PasswordPolicyResponseGrammar INSTANCE = new PasswordPolicyResponseGrammar();


    @SuppressWarnings("unchecked")
    private PasswordPolicyResponseGrammar()
    {
        setName( PasswordPolicyResponseGrammar.class.getName() );

        super.transitions = new GrammarTransition[PasswordPolicyResponseStates.END_STATE.ordinal()][256];

        // PasswordPolicyResponseValue ::= SEQUENCE {
        // ...
        super.transitions[PasswordPolicyResponseStates.START_STATE.ordinal()][UniversalTag.SEQUENCE.getValue()] = new GrammarTransition<PasswordPolicyResponseContainer>(
            PasswordPolicyResponseStates.START_STATE, PasswordPolicyResponseStates.PPOLICY_RESP_SEQ_STATE,
            UniversalTag.SEQUENCE.getValue(),
            new PPolicyResponseInit() );

        // PasswordPolicyResponseValue ::= SEQUENCE {
        //              warning [0] CHOICE {
        super.transitions[PasswordPolicyResponseStates.PPOLICY_RESP_SEQ_STATE.ordinal()][PasswordPolicyTags.PPOLICY_WARNING_TAG
            .getValue()] = new GrammarTransition<PasswordPolicyResponseContainer>(
            PasswordPolicyResponseStates.PPOLICY_RESP_SEQ_STATE, PasswordPolicyResponseStates.PPOLICY_RESP_WARNING_TAG_STATE,
            PasswordPolicyTags.PPOLICY_WARNING_TAG.getValue(),
            new CheckNotNullLength<PasswordPolicyResponseContainer>() );

        // PasswordPolicyResponseValue ::= SEQUENCE {
        //              ...
        //              error   [1] ENUMERATED {
        super.transitions[PasswordPolicyResponseStates.PPOLICY_RESP_SEQ_STATE.ordinal()][PasswordPolicyTags.PPOLICY_ERROR_TAG
            .getValue()] = new GrammarTransition<PasswordPolicyResponseContainer>(
            PasswordPolicyResponseStates.PPOLICY_RESP_SEQ_STATE, PasswordPolicyResponseStates.PPOLICY_RESP_ERROR_TAG_STATE,
            PasswordPolicyTags.PPOLICY_ERROR_TAG.getValue(),
            new StoreError<PasswordPolicyResponseContainer>() );

        // PasswordPolicyResponseValue ::= SEQUENCE {
        //              warning [0] CHOICE {
        //                      timeBeforeExpiration [0] INTEGER (0 .. maxInt),
        super.transitions[PasswordPolicyResponseStates.PPOLICY_RESP_WARNING_TAG_STATE.ordinal()][PasswordPolicyTags.TIME_BEFORE_EXPIRATION_TAG
            .getValue()] = new GrammarTransition<PasswordPolicyResponseContainer>(
            PasswordPolicyResponseStates.PPOLICY_RESP_WARNING_TAG_STATE, PasswordPolicyResponseStates.PPOLICY_RESP_TIME_BEFORE_EXPIRATION_STATE,
            PasswordPolicyTags.TIME_BEFORE_EXPIRATION_TAG.getValue(),
            new StoreTimeBeforeExpiration() );

        // PasswordPolicyResponseValue ::= SEQUENCE {
        //              warning [0] CHOICE {
        //                      ...
        //                      graceAuthNsRemaining [1] INTEGER (0 .. maxInt) } OPTIONAL,
        super.transitions[PasswordPolicyResponseStates.PPOLICY_RESP_WARNING_TAG_STATE.ordinal()][PasswordPolicyTags.GRACE_AUTHNS_REMAINING_TAG
            .getValue()] = new GrammarTransition<PasswordPolicyResponseContainer>(
            PasswordPolicyResponseStates.PPOLICY_RESP_WARNING_TAG_STATE, PasswordPolicyResponseStates.PPOLICY_RESP_GRACE_AUTHNS_REMAINING_STATE,
            PasswordPolicyTags.GRACE_AUTHNS_REMAINING_TAG.getValue(),
            new StoreGraceAuthNRemaining() );

        // PasswordPolicyResponseValue ::= SEQUENCE {
        //              ...
        //              error   [1] ENUMERATED {
        super.transitions[PasswordPolicyResponseStates.PPOLICY_RESP_TIME_BEFORE_EXPIRATION_STATE.ordinal()][PasswordPolicyTags.PPOLICY_ERROR_TAG
            .getValue()] = new GrammarTransition<PasswordPolicyResponseContainer>(
            PasswordPolicyResponseStates.PPOLICY_RESP_TIME_BEFORE_EXPIRATION_STATE, PasswordPolicyResponseStates.PPOLICY_RESP_ERROR_TAG_STATE,
            PasswordPolicyTags.PPOLICY_ERROR_TAG.getValue(),
            new StoreError<PasswordPolicyResponseContainer>() );

        // PasswordPolicyResponseValue ::= SEQUENCE {
        //              ...
        //              error   [1] ENUMERATED {
        super.transitions[PasswordPolicyResponseStates.PPOLICY_RESP_GRACE_AUTHNS_REMAINING_STATE.ordinal()][PasswordPolicyTags.GRACE_AUTHNS_REMAINING_TAG
            .getValue()] = new GrammarTransition<PasswordPolicyResponseContainer>(
            PasswordPolicyResponseStates.PPOLICY_RESP_GRACE_AUTHNS_REMAINING_STATE, PasswordPolicyResponseStates.PPOLICY_RESP_ERROR_TAG_STATE,
            PasswordPolicyTags.GRACE_AUTHNS_REMAINING_TAG.getValue(),
            new StoreError<PasswordPolicyResponseContainer>() );
    }


    /**
     * @return the singleton instance of the PasswordPolicyResponseGrammar
     */
    public static Grammar<PasswordPolicyResponseContainer> getInstance()
    {
        return INSTANCE;
    }
}
