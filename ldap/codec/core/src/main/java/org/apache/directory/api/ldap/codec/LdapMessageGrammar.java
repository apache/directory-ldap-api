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
package org.apache.directory.api.ldap.codec;


import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.BOOLEAN;
import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.ENUMERATED;
import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.INTEGER;
import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.OCTET_STRING;
import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.SEQUENCE;
import static org.apache.directory.api.asn1.ber.tlv.UniversalTag.SET;

import org.apache.directory.api.asn1.actions.CheckNotNullLength;
import org.apache.directory.api.asn1.ber.grammar.AbstractGrammar;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.GrammarTransition;
import org.apache.directory.api.ldap.codec.actions.AllowGrammarEnd;
import org.apache.directory.api.ldap.codec.actions.CheckLengthNotNull;
import org.apache.directory.api.ldap.codec.actions.controls.StoreControlName;
import org.apache.directory.api.ldap.codec.actions.controls.InitControls;
import org.apache.directory.api.ldap.codec.actions.controls.StoreControlCriticality;
import org.apache.directory.api.ldap.codec.actions.controls.StoreControlValue;
import org.apache.directory.api.ldap.codec.actions.ldapMessage.InitLdapMessage;
import org.apache.directory.api.ldap.codec.actions.ldapMessage.StoreMessageId;
import org.apache.directory.api.ldap.codec.actions.ldapResult.AddReferral;
import org.apache.directory.api.ldap.codec.actions.ldapResult.InitReferrals;
import org.apache.directory.api.ldap.codec.actions.ldapResult.StoreErrorMessage;
import org.apache.directory.api.ldap.codec.actions.ldapResult.StoreMatchedDN;
import org.apache.directory.api.ldap.codec.actions.ldapResult.StoreResultCode;
import org.apache.directory.api.ldap.codec.actions.request.abandon.InitAbandonRequest;
import org.apache.directory.api.ldap.codec.actions.request.add.AddAddRequestAttributeType;
import org.apache.directory.api.ldap.codec.actions.request.add.AddAttributeValue;
import org.apache.directory.api.ldap.codec.actions.request.add.InitAddRequest;
import org.apache.directory.api.ldap.codec.actions.request.add.StoreAddRequestEntryName;
import org.apache.directory.api.ldap.codec.actions.request.bind.InitBindRequest;
import org.apache.directory.api.ldap.codec.actions.request.bind.InitSaslBind;
import org.apache.directory.api.ldap.codec.actions.request.bind.StoreName;
import org.apache.directory.api.ldap.codec.actions.request.bind.StoreSaslCredentials;
import org.apache.directory.api.ldap.codec.actions.request.bind.StoreSaslMechanism;
import org.apache.directory.api.ldap.codec.actions.request.bind.StoreSimpleAuth;
import org.apache.directory.api.ldap.codec.actions.request.bind.StoreVersion;
import org.apache.directory.api.ldap.codec.actions.request.compare.InitCompareRequest;
import org.apache.directory.api.ldap.codec.actions.request.compare.StoreCompareRequestAssertionValue;
import org.apache.directory.api.ldap.codec.actions.request.compare.StoreCompareRequestAttributeDesc;
import org.apache.directory.api.ldap.codec.actions.request.compare.StoreCompareRequestEntryName;
import org.apache.directory.api.ldap.codec.actions.request.del.InitDelRequest;
import org.apache.directory.api.ldap.codec.actions.request.extended.InitExtendedRequest;
import org.apache.directory.api.ldap.codec.actions.request.extended.StoreExtendedRequestName;
import org.apache.directory.api.ldap.codec.actions.request.extended.StoreExtendedRequestValue;
import org.apache.directory.api.ldap.codec.actions.request.modify.AddModifyRequestAttribute;
import org.apache.directory.api.ldap.codec.actions.request.modify.InitAttributeVals;
import org.apache.directory.api.ldap.codec.actions.request.modify.InitModifyRequest;
import org.apache.directory.api.ldap.codec.actions.request.modify.StoreModifyRequestAttributeValue;
import org.apache.directory.api.ldap.codec.actions.request.modify.StoreModifyRequestObjectName;
import org.apache.directory.api.ldap.codec.actions.request.modify.StoreOperationType;
import org.apache.directory.api.ldap.codec.actions.request.modifydn.InitModifyDnRequest;
import org.apache.directory.api.ldap.codec.actions.request.modifydn.StoreModifyDnRequestDeleteOldRdn;
import org.apache.directory.api.ldap.codec.actions.request.modifydn.StoreModifyDnRequestEntryName;
import org.apache.directory.api.ldap.codec.actions.request.modifydn.StoreModifyDnRequestNewRdn;
import org.apache.directory.api.ldap.codec.actions.request.modifydn.StoreModifyDnRequestNewSuperior;
import org.apache.directory.api.ldap.codec.actions.request.search.InitSearchRequest;
import org.apache.directory.api.ldap.codec.actions.request.search.InitSearchRequestAttributeDescList;
import org.apache.directory.api.ldap.codec.actions.request.search.StoreSearchRequestAttributeDesc;
import org.apache.directory.api.ldap.codec.actions.request.search.StoreSearchRequestBaseObject;
import org.apache.directory.api.ldap.codec.actions.request.search.StoreSearchRequestDerefAlias;
import org.apache.directory.api.ldap.codec.actions.request.search.StoreSearchRequestScope;
import org.apache.directory.api.ldap.codec.actions.request.search.StoreSearchRequestSizeLimit;
import org.apache.directory.api.ldap.codec.actions.request.search.StoreSearchRequestTimeLimit;
import org.apache.directory.api.ldap.codec.actions.request.search.StoreSearchRequestTypesOnly;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.InitAndFilter;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.InitApproxMatchFilter;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.InitAssertionValueFilter;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.InitAttributeDescFilter;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.InitEqualityMatchFilter;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.InitExtensibleMatchFilter;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.InitGreaterOrEqualFilter;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.InitLessOrEqualFilter;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.InitNotFilter;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.InitOrFilter;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.InitPresentFilter;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.InitSubstringsFilter;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.StoreAny;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.StoreFinal;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.StoreInitial;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.StoreMatchValue;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.StoreMatchingRuleDnAttributes;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.StoreMatchingRuleId;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.StoreSubstringFilterType;
import org.apache.directory.api.ldap.codec.actions.request.search.filter.StoreMatchingRuleType;
import org.apache.directory.api.ldap.codec.actions.request.unbind.InitUnbindRequest;
import org.apache.directory.api.ldap.codec.actions.response.add.InitAddResponse;
import org.apache.directory.api.ldap.codec.actions.response.bind.InitBindResponse;
import org.apache.directory.api.ldap.codec.actions.response.bind.StoreServerSASLCreds;
import org.apache.directory.api.ldap.codec.actions.response.compare.InitCompareResponse;
import org.apache.directory.api.ldap.codec.actions.response.del.InitDelResponse;
import org.apache.directory.api.ldap.codec.actions.response.extended.InitExtendedResponse;
import org.apache.directory.api.ldap.codec.actions.response.extended.StoreExtendedResponseName;
import org.apache.directory.api.ldap.codec.actions.response.extended.StoreExtendedResponseValue;
import org.apache.directory.api.ldap.codec.actions.response.intermediate.InitIntermediateResponse;
import org.apache.directory.api.ldap.codec.actions.response.intermediate.StoreIntermediateResponseName;
import org.apache.directory.api.ldap.codec.actions.response.intermediate.StoreIntermediateResponseValue;
import org.apache.directory.api.ldap.codec.actions.response.modify.InitModifyResponse;
import org.apache.directory.api.ldap.codec.actions.response.modifydn.InitModifyDnResponse;
import org.apache.directory.api.ldap.codec.actions.response.search.done.InitSearchResultDone;
import org.apache.directory.api.ldap.codec.actions.response.search.entry.AddAttributeType;
import org.apache.directory.api.ldap.codec.actions.response.search.entry.InitSearchResultEntry;
import org.apache.directory.api.ldap.codec.actions.response.search.entry.StoreSearchResultAttributeValue;
import org.apache.directory.api.ldap.codec.actions.response.search.entry.StoreSearchResultEntryObjectName;
import org.apache.directory.api.ldap.codec.actions.response.search.reference.InitSearchResultReference;
import org.apache.directory.api.ldap.codec.actions.response.search.reference.StoreReference;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.model.message.AbstractMessage;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements the LdapMessage message. All the actions are declared
 * in this class. As it is a singleton, these declaration are only done once. If
 * an action is to be added or modified, this is where the work is to be done !
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class LdapMessageGrammar extends
    AbstractGrammar<LdapMessageContainer<AbstractMessage>>
{
    /** The logger */
    static final Logger LOG = LoggerFactory.getLogger( LdapMessageGrammar.class );

    /** The instance of grammar. LdapMessageGrammar is a singleton */
    private static Grammar<LdapMessageContainer<AbstractMessage>> instance =
        new LdapMessageGrammar();


    /**
     * Creates a new LdapMessageGrammar object.
     */
    @SuppressWarnings(
        { "unchecked", "rawtypes" })
    private LdapMessageGrammar()
    {
        setName( LdapMessageGrammar.class.getName() );

        // Create the transitions table
        super.transitions = new GrammarTransition[LdapStatesEnum.LAST_LDAP_STATE.ordinal()][256];

        // ============================================================================================
        // Transition from START to LdapMessage
        // ============================================================================================
        // This is the starting state :
        // LDAPMessage --> SEQUENCE { ...
        //
        // We have a LDAPMessage, and the tag must be 0x30.
        //
        // The next state will be LDAP_MESSAGE_STATE
        //
        // We will just check that the length is not null
        super.transitions[LdapStatesEnum.START_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.START_STATE,
                LdapStatesEnum.LDAP_MESSAGE_STATE,
                SEQUENCE,
                new InitLdapMessage(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from LdapMessage to Message ID
        // --------------------------------------------------------------------------------------------
        // LDAPMessage --> ... MessageId ...
        //
        // Checks that MessageId is in [0 .. 2147483647] and store the value in
        // the LdapMessage Object
        //
        // (2147483647 = Integer.MAX_VALUE)
        // The next state will be MESSAGE_ID_STATE
        //
        // The message ID will be temporarily stored in the container, because we can't store it
        // into an object.
        super.transitions[LdapStatesEnum.LDAP_MESSAGE_STATE.ordinal()][INTEGER.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.LDAP_MESSAGE_STATE,
                LdapStatesEnum.MESSAGE_ID_STATE,
                INTEGER,
                new StoreMessageId(),
                FollowUp.MANDATORY );

        // ********************************************************************************************
        // We have a ProtocolOp :
        // If the Tag is 0x42, then it's an UnBindRequest.
        // If the Tag is 0x4A, then it's a DelRequest.
        // If the Tag is 0x50, then it's an AbandonRequest.
        // If the Tag is 0x60, then it's a BindRequest.
        // If the Tag is 0x61, then it's a BindResponse.
        // If the Tag is 0x63, then it's a SearchRequest.
        // If the Tag is 0x64, then it's a SearchResultEntry.
        // If the Tag is 0x65, then it's a SearchResultDone
        // If the Tag is 0x66, then it's a ModifyRequest
        // If the Tag is 0x67, then it's a ModifyResponse.
        // If the Tag is 0x68, then it's an AddRequest.
        // If the Tag is 0x69, then it's an AddResponse.
        // If the Tag is 0x6B, then it's a DelResponse.
        // If the Tag is 0x6C, then it's a ModifyDNRequest.
        // If the Tag is 0x6D, then it's a ModifyDNResponse.
        // If the Tag is 0x6E, then it's a CompareRequest
        // If the Tag is 0x6F, then it's a CompareResponse.
        // If the Tag is 0x73, then it's a SearchResultReference.
        // If the Tag is 0x77, then it's an ExtendedRequest.
        // If the Tag is 0x78, then it's an ExtendedResponse.
        // If the Tag is 0x79, then it's an IntermediateResponse.
        //
        // We create the associated object in this transition, and store it into the container.
        // ********************************************************************************************

        // --------------------------------------------------------------------------------------------
        // Transition from Message ID to UnBindRequest Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... UnBindRequest ...
        // unbindRequest ::= [APPLICATION 2] NULL
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.UNBIND_REQUEST_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.UNBIND_REQUEST_STATE,
                LdapCodecConstants.UNBIND_REQUEST_TAG,
                new InitUnbindRequest(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // transition from UnBindRequest Message to Controls.
        // --------------------------------------------------------------------------------------------
        //         unbindRequest   UnbindRequest,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        super.transitions[LdapStatesEnum.UNBIND_REQUEST_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.UNBIND_REQUEST_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Message ID to DelRequest Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... DelRequest ...
        // delRequest ::= [APPLICATION 10] LDAPDN
        //
        // We store the Dn to bve deleted into the DelRequest object
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.DEL_REQUEST_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.DEL_REQUEST_STATE,
                LdapCodecConstants.DEL_REQUEST_TAG,
                new InitDelRequest(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // transition from DelRequest Message to Controls.
        // --------------------------------------------------------------------------------------------
        //         delRequest   DelRequest,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        super.transitions[LdapStatesEnum.DEL_REQUEST_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.DEL_REQUEST_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Message ID to AbandonRequest Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... AbandonRequest ...
        // AbandonRequest ::= [APPLICATION 16] MessageID
        //
        // Create the AbandonRequest object, and store the ID in it
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.ABANDON_REQUEST_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.ABANDON_REQUEST_STATE,
                LdapCodecConstants.ABANDON_REQUEST_TAG,
                new InitAbandonRequest(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // transition from AbandonRequest Message to Controls.
        // --------------------------------------------------------------------------------------------
        //         abandonRequest   AbandonRequest,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        super.transitions[LdapStatesEnum.ABANDON_REQUEST_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ABANDON_REQUEST_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Message ID to BindRequest Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... BindRequest ...
        // BindRequest ::= [APPLICATION 0] SEQUENCE { ...
        //
        // We have to allocate a BindRequest
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.BIND_REQUEST_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.BIND_REQUEST_STATE,
                LdapCodecConstants.BIND_REQUEST_TAG,
                new InitBindRequest(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from BindRequest to version
        // --------------------------------------------------------------------------------------------
        // BindRequest ::= [APPLICATION 0] SEQUENCE {
        //     version                 INTEGER (1 ..  127),
        //     ....
        //
        // The Ldap version is parsed and stored into the BindRequest object
        super.transitions[LdapStatesEnum.BIND_REQUEST_STATE.ordinal()][INTEGER.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.BIND_REQUEST_STATE,
                LdapStatesEnum.VERSION_STATE,
                INTEGER,
                new StoreVersion(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from version to name
        // --------------------------------------------------------------------------------------------
        // BindRequest ::= [APPLICATION 0] SEQUENCE {
        //     ....
        //     name                    LDAPDN,
        //     ....
        //
        // The Ldap name is stored into the BindRequest object
        super.transitions[LdapStatesEnum.VERSION_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.VERSION_STATE,
                LdapStatesEnum.NAME_STATE,
                OCTET_STRING,
                new StoreName(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from name to Simple Authentication
        // --------------------------------------------------------------------------------------------
        // BindRequest ::= [APPLICATION 0] SEQUENCE {
        //     ....
        //     authentication          AuthenticationChoice }
        //
        // AuthenticationChoice ::= CHOICE {
        //     simple                  [0] OCTET STRING,
        //     ...
        //
        // We have to create an Authentication Object to store the credentials.
        super.transitions[LdapStatesEnum.NAME_STATE.ordinal()][LdapCodecConstants.BIND_REQUEST_SIMPLE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NAME_STATE,
                LdapStatesEnum.SIMPLE_STATE,
                LdapCodecConstants.BIND_REQUEST_SIMPLE_TAG,
                new StoreSimpleAuth(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // transition from Simple Authentication to Controls.
        // --------------------------------------------------------------------------------------------
        //         bindRequest   BindRequest,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        super.transitions[LdapStatesEnum.SIMPLE_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.SIMPLE_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from name to SASL Authentication
        // --------------------------------------------------------------------------------------------
        // BindRequest ::= [APPLICATION 0] SEQUENCE {
        //     ....
        //     authentication          AuthenticationChoice }
        //
        // AuthenticationChoice ::= CHOICE {
        //     ...
        //     sasl                  [3] SaslCredentials }
        //     ...
        //
        // We have to create an Authentication Object to store the credentials.
        super.transitions[LdapStatesEnum.NAME_STATE.ordinal()][LdapCodecConstants.BIND_REQUEST_SASL_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NAME_STATE,
                LdapStatesEnum.SASL_STATE,
                LdapCodecConstants.BIND_REQUEST_SASL_TAG,
                new InitSaslBind(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from SASL Authentication to Mechanism
        // --------------------------------------------------------------------------------------------
        // SaslCredentials ::= SEQUENCE {
        //     mechanism   LDAPSTRING,
        //     ...
        //
        // We have to store the mechanism.
        super.transitions[LdapStatesEnum.SASL_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.SASL_STATE,
                LdapStatesEnum.MECHANISM_STATE,
                OCTET_STRING,
                new StoreSaslMechanism(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Mechanism to Credentials
        // --------------------------------------------------------------------------------------------
        // SaslCredentials ::= SEQUENCE {
        //     ...
        //     credentials OCTET STRING OPTIONAL }
        //
        // We have to store the mechanism.
        super.transitions[LdapStatesEnum.MECHANISM_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.MECHANISM_STATE,
                LdapStatesEnum.CREDENTIALS_STATE,
                OCTET_STRING,
                new StoreSaslCredentials(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // transition from from Mechanism to Controls.
        // --------------------------------------------------------------------------------------------
        //         bindRequest   BindRequest,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        super.transitions[LdapStatesEnum.MECHANISM_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MECHANISM_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // transition from credentials to Controls.
        // --------------------------------------------------------------------------------------------
        //         bindRequest   BindRequest,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        super.transitions[LdapStatesEnum.CREDENTIALS_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.CREDENTIALS_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from MessageId to BindResponse message
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... BindResponse ...
        // BindResponse ::= [APPLICATION 1] SEQUENCE { ...
        // We have to switch to the BindResponse grammar
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.BIND_RESPONSE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.BIND_RESPONSE_STATE,
                LdapCodecConstants.BIND_RESPONSE_TAG,
                new InitBindResponse(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from BindResponse message to Result Code BR
        // --------------------------------------------------------------------------------------------
        // BindResponse ::= [APPLICATION 1] SEQUENCE {
        //     COMPONENTS OF LDAPResult,
        //     ...
        //
        // LDAPResult ::= SEQUENCE {
        //     resultCode ENUMERATED {
        //         ...
        //
        // Stores the result code into the Bind Response object
        super.transitions[LdapStatesEnum.BIND_RESPONSE_STATE.ordinal()][ENUMERATED.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.BIND_RESPONSE_STATE,
                LdapStatesEnum.RESULT_CODE_BR_STATE,
                ENUMERATED,
                new StoreResultCode(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Result Code BR to Matched Dn BR
        // --------------------------------------------------------------------------------------------
        // LDAPResult ::= SEQUENCE {
        //     ...
        //     matchedDN LDAPDN,
        //     ...
        //
        // Stores the matched Dn
        super.transitions[LdapStatesEnum.RESULT_CODE_BR_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.RESULT_CODE_BR_STATE,
                LdapStatesEnum.MATCHED_DN_BR_STATE,
                OCTET_STRING,
                new StoreMatchedDN(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Matched Dn BR to diagnosticMessage BR
        // --------------------------------------------------------------------------------------------
        // LDAPResult ::= SEQUENCE {
        //     ...
        //     diagnosticMessage LDAPString,
        //     ...
        //
        // Stores the diagnosticMessage
        super.transitions[LdapStatesEnum.MATCHED_DN_BR_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.MATCHED_DN_BR_STATE,
                LdapStatesEnum.DIAGNOSTIC_MESSAGE_BR_STATE,
                OCTET_STRING,
                new StoreErrorMessage(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from DiagnosticMessage BR to Server SASL credentials
        // --------------------------------------------------------------------------------------------
        // BindResponse ::= APPLICATION 1] SEQUENCE {
        //     ...
        //     serverSaslCreds [7] OCTET STRING OPTIONAL }
        //
        // Stores the sasl credentials
        super.transitions[LdapStatesEnum.DIAGNOSTIC_MESSAGE_BR_STATE.ordinal()][LdapCodecConstants.SERVER_SASL_CREDENTIAL_TAG] =
            new GrammarTransition(
                LdapStatesEnum.DIAGNOSTIC_MESSAGE_BR_STATE,
                LdapStatesEnum.SERVER_SASL_CREDENTIALS_STATE,
                LdapCodecConstants.SERVER_SASL_CREDENTIAL_TAG,
                new StoreServerSASLCreds(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from DiagnosticMessage BR to Referral BR
        // --------------------------------------------------------------------------------------------
        // LDAPResult ::= SEQUENCE {
        //     ...
        //     referral   [3] Referral OPTIONAL }
        //
        // Initialiaze the referrals list
        super.transitions[LdapStatesEnum.DIAGNOSTIC_MESSAGE_BR_STATE.ordinal()][LdapCodecConstants.LDAP_RESULT_REFERRAL_SEQUENCE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.DIAGNOSTIC_MESSAGE_BR_STATE,
                LdapStatesEnum.REFERRAL_BR_STATE,
                LdapCodecConstants.LDAP_RESULT_REFERRAL_SEQUENCE_TAG,
                new InitReferrals(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Referral BR to URI BR
        // --------------------------------------------------------------------------------------------
        // Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI (RFC 4511)
        // URI ::= LDAPString
        //
        // Add a first Referral
        super.transitions[LdapStatesEnum.REFERRAL_BR_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.REFERRAL_BR_STATE,
                LdapStatesEnum.URI_BR_STATE,
                OCTET_STRING,
                new AddReferral(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from URI BR to URI BR
        // --------------------------------------------------------------------------------------------
        // Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI (RFC 4511)
        // URI ::= LDAPString
        //
        // Adda new Referral
        super.transitions[LdapStatesEnum.URI_BR_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.URI_BR_STATE,
                LdapStatesEnum.URI_BR_STATE,
                OCTET_STRING,
                new AddReferral(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from URI BR to Server SASL Credentials
        // --------------------------------------------------------------------------------------------
        // Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI (RFC 4511)
        // URI ::= LDAPString
        //
        // Adda new Referral
        super.transitions[LdapStatesEnum.URI_BR_STATE.ordinal()][LdapCodecConstants.SERVER_SASL_CREDENTIAL_TAG] =
            new GrammarTransition(
                LdapStatesEnum.URI_BR_STATE,
                LdapStatesEnum.SERVER_SASL_CREDENTIALS_STATE,
                LdapCodecConstants.SERVER_SASL_CREDENTIAL_TAG,
                new StoreServerSASLCreds(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from URI BR to Controls
        // --------------------------------------------------------------------------------------------
        //         bindResponse   BindResponse,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        // Adda new Referral
        super.transitions[LdapStatesEnum.URI_BR_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.URI_BR_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from diagnosticMessage BR to controls
        // --------------------------------------------------------------------------------------------
        //         bindResponse   BindResponse,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        //
        super.transitions[LdapStatesEnum.DIAGNOSTIC_MESSAGE_BR_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.DIAGNOSTIC_MESSAGE_BR_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Server SASL credentials to Controls
        // --------------------------------------------------------------------------------------------
        //         bindResponse   BindResponse,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        super.transitions[LdapStatesEnum.SERVER_SASL_CREDENTIALS_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.SERVER_SASL_CREDENTIALS_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Result Code to Matched Dn
        // --------------------------------------------------------------------------------------------
        // LDAPResult ::= SEQUENCE {
        //     ...
        //     matchedDN LDAPDN,
        //     ...
        //
        // Stores the matched Dn
        super.transitions[LdapStatesEnum.RESULT_CODE_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.RESULT_CODE_STATE,
                LdapStatesEnum.MATCHED_DN_STATE,
                OCTET_STRING,
                new StoreMatchedDN(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Matched Dn to Diagnostic Message
        // --------------------------------------------------------------------------------------------
        // LDAPResult ::= SEQUENCE {
        //     ...
        //     diagnosticMessage LDAPString,
        //     ...
        //
        // Stores the error message
        super.transitions[LdapStatesEnum.MATCHED_DN_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.MATCHED_DN_STATE,
                LdapStatesEnum.DIAGNOSTIC_MESSAGE_STATE,
                OCTET_STRING,
                new StoreErrorMessage(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from diagnosticMessage to Referral
        // --------------------------------------------------------------------------------------------
        // LDAPResult ::= SEQUENCE {
        //     ...
        //     referral   [3] Referral OPTIONNAL }
        //
        // Initialize the referrals list
        super.transitions[LdapStatesEnum.DIAGNOSTIC_MESSAGE_STATE.ordinal()][LdapCodecConstants.LDAP_RESULT_REFERRAL_SEQUENCE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.DIAGNOSTIC_MESSAGE_STATE,
                LdapStatesEnum.REFERRAL_STATE,
                LdapCodecConstants.LDAP_RESULT_REFERRAL_SEQUENCE_TAG,
                new InitReferrals(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from diagnosticMessage to Controls
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= SEQUENCE {
        //     protocolOp      CHOICE {
        //         ...},
        //     controls       [0] Controls OPTIONAL }
        //
        super.transitions[LdapStatesEnum.DIAGNOSTIC_MESSAGE_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.DIAGNOSTIC_MESSAGE_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Referral to URI
        // --------------------------------------------------------------------------------------------
        // Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI (RFC 4511)
        // URI ::= LDAPString
        //
        // Add a first Referral
        super.transitions[LdapStatesEnum.REFERRAL_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.REFERRAL_STATE,
                LdapStatesEnum.URI_STATE,
                OCTET_STRING,
                new AddReferral(),
                FollowUp.OPTIONAL );
        
        // --------------------------------------------------------------------------------------------
        // Transition from URI to URI
        // --------------------------------------------------------------------------------------------
        // Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI (RFC 4511)
        // URI ::= LDAPString
        //
        // Adda new Referral
        super.transitions[LdapStatesEnum.URI_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.URI_STATE,
                LdapStatesEnum.URI_STATE,
                OCTET_STRING,
                new AddReferral(),
                FollowUp.OPTIONAL );
        
        // --------------------------------------------------------------------------------------------
        // Transition from URI to Controls
        // --------------------------------------------------------------------------------------------
        //         xxxResponse   xxxResponse,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        // Adda new Referral
        super.transitions[LdapStatesEnum.URI_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.URI_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from MessageId to SearchResultEntry Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... SearchResultEntry ...
        // SearchResultEntry ::= [APPLICATION 4] SEQUENCE { ...
        //
        // Initialize the searchResultEntry object
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.SEARCH_RESULT_ENTRY_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.SEARCH_RESULT_ENTRY_STATE,
                LdapCodecConstants.SEARCH_RESULT_ENTRY_TAG,
                new InitSearchResultEntry(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from SearchResultEntry Message to ObjectName
        // --------------------------------------------------------------------------------------------
        // SearchResultEntry ::= [APPLICATION 4] SEQUENCE { ...
        // objectName LDAPDN,
        // ...
        //
        // Store the object name.
        super.transitions[LdapStatesEnum.SEARCH_RESULT_ENTRY_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.SEARCH_RESULT_ENTRY_STATE,
                LdapStatesEnum.OBJECT_NAME_STATE,
                OCTET_STRING,
                new StoreSearchResultEntryObjectName(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from ObjectName to AttributesSR
        // --------------------------------------------------------------------------------------------
        // SearchResultEntry ::= [APPLICATION 4] SEQUENCE { ...
        // ...
        // attributes PartialAttributeList }
        //
        // PartialAttributeList ::= *SEQUENCE* OF SEQUENCE {
        // ...
        //
        // We may have no attributes. Just allows the grammar to end
        super.transitions[LdapStatesEnum.OBJECT_NAME_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.OBJECT_NAME_STATE,
                LdapStatesEnum.ATTRIBUTES_SR_STATE,
                SEQUENCE,
                new AllowGrammarEnd(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from AttributesSR to PartialAttributesList
        // --------------------------------------------------------------------------------------------
        // SearchResultEntry ::= [APPLICATION 4] SEQUENCE { ...
        // ...
        // attributes PartialAttributeList }
        //
        // PartialAttributeList ::= SEQUENCE OF partialAttribute PartialAttribute
        //
        // nothing to do
        super.transitions[LdapStatesEnum.ATTRIBUTES_SR_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ATTRIBUTES_SR_STATE,
                LdapStatesEnum.PARTIAL_ATTRIBUTES_LIST_STATE,
                SEQUENCE,
                null,
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from PartialAttributesList to typeSR
        // --------------------------------------------------------------------------------------------
        // SearchResultEntry ::= [APPLICATION 4] SEQUENCE { ...
        // ...
        // attributes PartialAttributeList }
        //
        // PartialAttributeList ::= SEQUENCE OF partialAttribute PartialAttribute
        //
        // PartialAttribute ::= SEQUENCE {
        //     type       OCTET STRING,
        //     ...
        //
        // Store the attribute's name.
        super.transitions[LdapStatesEnum.PARTIAL_ATTRIBUTES_LIST_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.PARTIAL_ATTRIBUTES_LIST_STATE,
                LdapStatesEnum.TYPE_SR_STATE,
                OCTET_STRING,
                new AddAttributeType(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from typeSR to ValsSR
        // --------------------------------------------------------------------------------------------
        // SearchResultEntry ::= [APPLICATION 4] SEQUENCE { ...
        // ...
        // attributes PartialAttributeList }
        //
        // PartialAttributeList ::= SEQUENCE OF partialAttribute PartialAttribute
        //
        // PartialAttribute ::= SEQUENCE {
        //     ...
        //     vals       *SET OF* value OCTET STRING }
        //
        // We may have no value. Just allows the grammar to end
        super.transitions[LdapStatesEnum.TYPE_SR_STATE.ordinal()][SET.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.TYPE_SR_STATE,
                LdapStatesEnum.VALS_SR_STATE,
                SET,
                new AllowGrammarEnd(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ValsSR to AttributeValueSR
        // --------------------------------------------------------------------------------------------
        // PartialAttribute ::= SEQUENCE {
        //     ...
        //     vals       SET OF *value OCTET STRING* }
        //
        // Store the attribute value
        super.transitions[LdapStatesEnum.VALS_SR_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.VALS_SR_STATE,
                LdapStatesEnum.VALUE_SR_STATE,
                OCTET_STRING,
                new StoreSearchResultAttributeValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ValsSR to PartialAttributesList
        // --------------------------------------------------------------------------------------------
        // attributes PartialAttributeList }
        //
        // PartialAttributeList ::= SEQUENCE OF partialAttribute PartialAttribute
        //
        // PartialAttribute ::= SEQUENCE {
        //     ...
        //     vals       SET OF *value OCTET STRING* }
        //
        // Loop when we don't have any attribute value. Nothing to do
        super.transitions[LdapStatesEnum.VALS_SR_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.VALS_SR_STATE,
                LdapStatesEnum.PARTIAL_ATTRIBUTES_LIST_STATE,
                SEQUENCE,
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ValsSR to Controls
        // --------------------------------------------------------------------------------------------
        //     searchResultEntry SearchResultEntry,
        //     ... },
        // controls   [0] Controls OPTIONAL }
        //
        // Initialize the controls
        super.transitions[LdapStatesEnum.VALS_SR_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.VALS_SR_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from AttributeValueSR to AttributeValueSR
        // --------------------------------------------------------------------------------------------
        // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
        //     ...
        //     vals       SET OF *value OCTET STRING* }
        //
        // Store the attribute value
        super.transitions[LdapStatesEnum.VALUE_SR_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.VALUE_SR_STATE,
                LdapStatesEnum.VALUE_SR_STATE,
                OCTET_STRING,
                new StoreSearchResultAttributeValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from AttributeValueSR to PartialAttributesList
        // --------------------------------------------------------------------------------------------
        // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
        //     ...
        //     vals SET OF AttributeValue }
        //
        // Loop when we don't have any attribute value. Nothing to do
        super.transitions[LdapStatesEnum.VALUE_SR_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.VALUE_SR_STATE,
                LdapStatesEnum.PARTIAL_ATTRIBUTES_LIST_STATE,
                SEQUENCE,
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from AttributeValueSR to Controls
        // --------------------------------------------------------------------------------------------
        //     searchResultEntry SearchResultEntry,
        //     ... },
        // controls   [0] Controls OPTIONAL }
        //
        // Initialize the controls
        super.transitions[LdapStatesEnum.VALUE_SR_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.VALUE_SR_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // SearchResultDone Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... SearchResultDone ...
        // SearchResultDone ::= [APPLICATION 5] SEQUENCE { ...
        //
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.SEARCH_RESULT_DONE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.SEARCH_RESULT_DONE_STATE,
                LdapCodecConstants.SEARCH_RESULT_DONE_TAG,
                new InitSearchResultDone(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // SearchResultDone Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... SearchResultDone ...
        // SearchResultDone ::= [APPLICATION 5] LDAPResult
        //
        // LDAPResult ::= SEQUENCE {
        //     resultCode    ENUMERATED {
        //         ...
        //
        // Stores the result code
        super.transitions[LdapStatesEnum.SEARCH_RESULT_DONE_STATE.ordinal()][ENUMERATED.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.SEARCH_RESULT_DONE_STATE,
                LdapStatesEnum.RESULT_CODE_STATE,
                ENUMERATED,
                new StoreResultCode(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Message ID to ModifyRequest Message
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ModifyRequest ...
        // ModifyRequest ::= [APPLICATION 6] SEQUENCE { ...
        //
        // Creates the Modify Request object
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.MODIFY_REQUEST_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.MODIFY_REQUEST_STATE,
                LdapCodecConstants.MODIFY_REQUEST_TAG,
                new InitModifyRequest(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ModifyRequest Message to Object
        // --------------------------------------------------------------------------------------------
        // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        //     object    LDAPDN,
        //     ...
        //
        // Stores the object Dn
        super.transitions[LdapStatesEnum.MODIFY_REQUEST_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.MODIFY_REQUEST_STATE,
                LdapStatesEnum.OBJECT_STATE,
                OCTET_STRING,
                new StoreModifyRequestObjectName(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Object to changes
        // --------------------------------------------------------------------------------------------
        // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        //     ...
        //     changes *SEQUENCE OF* change SEQUENCE {
        //     ...
        //
        // Initialize the modifications list
        super.transitions[LdapStatesEnum.OBJECT_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.OBJECT_STATE,
                LdapStatesEnum.CHANGES_STATE,
                SEQUENCE,
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from changes to change
        // --------------------------------------------------------------------------------------------
        // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        //     ...
        //     changes SEQUENCE OF *change* SEQUENCE {
        //     ...
        //
        // Nothing to do
        super.transitions[LdapStatesEnum.CHANGES_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.CHANGES_STATE,
                LdapStatesEnum.CHANGE_STATE,
                SEQUENCE,
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from change to operation
        // --------------------------------------------------------------------------------------------
        // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        //     ...
        //     changes SEQUENCE OF change SEQUENCE {
        //         operation  ENUMERATED {
        //             ...
        //
        // Store operation type
        super.transitions[LdapStatesEnum.CHANGE_STATE.ordinal()][ENUMERATED.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.CHANGE_STATE,
                LdapStatesEnum.OPERATION_STATE,
                ENUMERATED,
                new StoreOperationType(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from operation to modification
        // --------------------------------------------------------------------------------------------
        // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        //     ...
        //     changes SEQUENCE OF change SEQUENCE {
        //         operation  ENUMERATED {
        //             ...
        //         modification    PartialAttribute } }
        // 
        // PartialAttribute ::= SEQUENCE {
        //     ...
        //
        //
        // Nothing to do
        super.transitions[LdapStatesEnum.OPERATION_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.OPERATION_STATE,
                LdapStatesEnum.MODIFICATION_STATE,
                SEQUENCE,
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from modification to type
        // --------------------------------------------------------------------------------------------
        // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        //     ...
        //     changes SEQUENCE OF change SEQUENCE {
        //         operation  ENUMERATED {
        //             ...
        //         modification    PartialAttribute } }
        //
        // PartialAttribute ::= SEQUENCE {
        //     type       AttributeDescription,
        //     ...
        
        // Stores the type
        super.transitions[LdapStatesEnum.MODIFICATION_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.MODIFICATION_STATE,
                LdapStatesEnum.TYPE_MOD_STATE,
                OCTET_STRING,
                new AddModifyRequestAttribute(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from TypeMod to vals
        // --------------------------------------------------------------------------------------------
        // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        //     ...
        //     changes SEQUENCE OF change SEQUENCE {
        //         operation  ENUMERATED {
        //             ...
        //         modification    PartialAttribute } }
        //
        // PartialAttribute ::= SEQUENCE {
        //     ...
        //     vals       SET OF value AttributeValue }
        //
        // Initialize the list of values
        super.transitions[LdapStatesEnum.TYPE_MOD_STATE.ordinal()][SET.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.TYPE_MOD_STATE,
                LdapStatesEnum.VALS_STATE,
                SET,
                new InitAttributeVals(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from vals to Attribute Value
        // --------------------------------------------------------------------------------------------
        // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        //     ...
        //     changes SEQUENCE OF change SEQUENCE {
        //             ...
        //         modification    PartialAttribute } }
        //
        // PartialAttribute ::= SEQUENCE {
        //     ...
        //     vals       SET OF value AttributeValue }
        //
        //
        // Stores a value
        super.transitions[LdapStatesEnum.VALS_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.VALS_STATE,
                LdapStatesEnum.ATTRIBUTE_VALUE_STATE,
                OCTET_STRING,
                new StoreModifyRequestAttributeValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from vals to change
        // --------------------------------------------------------------------------------------------
        // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        //     ...
        //     changes SEQUENCE OF change SEQUENCE {
        //             ...
        //         modification    PartialAttribute } }
        //
        // PartialAttribute ::= SEQUENCE {
        //     ...
        //     vals       SET OF value AttributeValue }
        //
        // Nothing to do
        super.transitions[LdapStatesEnum.VALS_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.VALS_STATE,
                LdapStatesEnum.CHANGE_STATE,
                SEQUENCE,
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from vals to Controls
        // --------------------------------------------------------------------------------------------
        //     modifyRequest ModifyRequest,
        //     ... },
        // controls   [0] Controls OPTIONAL }
        //
        // Nothing to do
        super.transitions[LdapStatesEnum.VALS_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.VALS_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Attribute Value to Attribute Value
        // --------------------------------------------------------------------------------------------
        // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        //     ...
        //     changes SEQUENCE OF change SEQUENCE {
        //         operation  ENUMERATED {
        //             ...
        //         modification    PartialAttribute } }
        //
        // PartialAttribute ::= SEQUENCE {
        //     ...
        //     vals       SET OF value AttributeValue }
        //
        // AttributeValue ::= OCTET STRING
        //
        // Stores a value
        super.transitions[LdapStatesEnum.ATTRIBUTE_VALUE_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ATTRIBUTE_VALUE_STATE,
                LdapStatesEnum.ATTRIBUTE_VALUE_STATE,
                OCTET_STRING,
                new StoreModifyRequestAttributeValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Attribute Value to change
        // --------------------------------------------------------------------------------------------
        // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
        //     ...
        //     changes SEQUENCE OF change SEQUENCE {
        //         operation  ENUMERATED {
        //             ...
        //         modification    PartialAttribute } }
        //
        // PartialAttribute ::= SEQUENCE {
        //     ...
        //     vals       SET OF value AttributeValue }
        //
        //
        // AttributeValue ::= OCTET STRING
        // Nothing to do
        super.transitions[LdapStatesEnum.ATTRIBUTE_VALUE_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ATTRIBUTE_VALUE_STATE,
                LdapStatesEnum.CHANGE_STATE,
                SEQUENCE,
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Attribute Value to Controls
        // --------------------------------------------------------------------------------------------
        //     modifyRequest ModifyRequest,
        //     ... },
        // controls   [0] Controls OPTIONAL }
        //
        // Nothing to do
        super.transitions[LdapStatesEnum.ATTRIBUTE_VALUE_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ATTRIBUTE_VALUE_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // ModifyResponse Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ModifyResponse ...
        // ModifyResponse ::= [APPLICATION 7] SEQUENCE { ...
        // We have to switch to the ModifyResponse grammar
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.MODIFY_RESPONSE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.MODIFY_RESPONSE_STATE,
                LdapCodecConstants.MODIFY_RESPONSE_TAG,
                new InitModifyResponse(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // ModifyResponse Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ModifyResponse ...
        // ModifyResponse ::= [APPLICATION 7] LDAPResult
        //
        // LDAPResult ::= SEQUENCE {
        //     resultCode    ENUMERATED {
        //         ...
        //
        // Stores the result code
        super.transitions[LdapStatesEnum.MODIFY_RESPONSE_STATE.ordinal()][ENUMERATED.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.MODIFY_RESPONSE_STATE,
                LdapStatesEnum.RESULT_CODE_STATE,
                ENUMERATED,
                new StoreResultCode(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // AddRequest Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... AddRequest ...
        // AddRequest ::= [APPLICATION 8] SEQUENCE { ...
        //
        // Initialize the AddRequest object
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.ADD_REQUEST_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.ADD_REQUEST_STATE,
                LdapCodecConstants.ADD_REQUEST_TAG,
                new InitAddRequest(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Add Request to Entry
        // --------------------------------------------------------------------------------------------
        // AddRequest ::= [APPLICATION 8] SEQUENCE {
        //     entry           LDAPDN,
        //     ...
        //
        // Stores the Dn
        super.transitions[LdapStatesEnum.ADD_REQUEST_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ADD_REQUEST_STATE,
                LdapStatesEnum.ENTRY_STATE,
                OCTET_STRING,
                new StoreAddRequestEntryName(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Entry to Attributes
        // --------------------------------------------------------------------------------------------
        // AddRequest ::= [APPLICATION 8] SEQUENCE {
        //     ...
        //    attributes AttributeList }
        //
        // AttributeList ::= SEQUENCE OF ...
        //
        // Initialize the attribute list
        super.transitions[LdapStatesEnum.ENTRY_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ENTRY_STATE,
                LdapStatesEnum.ATTRIBUTES_STATE,
                SEQUENCE,
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Attributes to Attribute
        // --------------------------------------------------------------------------------------------
        // AttributeList ::= SEQUENCE OF SEQUENCE {
        //
        // We don't do anything in this transition. The attribute will be created when we met the type
        super.transitions[LdapStatesEnum.ATTRIBUTES_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ATTRIBUTES_STATE,
                LdapStatesEnum.ATTRIBUTE_STATE,
                SEQUENCE,
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Attribute to type
        // --------------------------------------------------------------------------------------------
        // AttributeList ::= SEQUENCE OF SEQUENCE {
        //     type    AttributeDescription,
        //     ...
        //
        // AttributeDescription LDAPString
        //
        // We store the type in the current attribute
        super.transitions[LdapStatesEnum.ATTRIBUTE_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ATTRIBUTE_STATE,
                LdapStatesEnum.TYPE_STATE,
                OCTET_STRING,
                new AddAddRequestAttributeType(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from type to vals
        // --------------------------------------------------------------------------------------------
        // AttributeList ::= SEQUENCE OF SEQUENCE {
        //     ...
        //     vals SET OF AttributeValue }
        //
        // Nothing to do here.
        super.transitions[LdapStatesEnum.TYPE_STATE.ordinal()][SET.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.TYPE_STATE,
                LdapStatesEnum.VALUES_STATE,
                SET,
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from vals to Value
        // --------------------------------------------------------------------------------------------
        // AttributeList ::= SEQUENCE OF SEQUENCE {
        //     ...
        //     vals SET OF AttributeValue }
        //
        // AttributeValue OCTET STRING
        //
        // Store the value into the current attribute
        super.transitions[LdapStatesEnum.VALUES_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.VALUES_STATE,
                LdapStatesEnum.VALUE_STATE,
                OCTET_STRING,
                new AddAttributeValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Value to Value
        // --------------------------------------------------------------------------------------------
        // AttributeList ::= SEQUENCE OF SEQUENCE {
        //     ...
        //     vals SET OF AttributeValue }
        //
        // AttributeValue OCTET STRING
        //
        // Store the value into the current attribute
        super.transitions[LdapStatesEnum.VALUE_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.VALUE_STATE,
                LdapStatesEnum.VALUE_STATE,
                OCTET_STRING,
                new AddAttributeValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Value to Attribute
        // --------------------------------------------------------------------------------------------
        // AttributeList ::= SEQUENCE OF SEQUENCE {
        //
        // Nothing to do here.
        super.transitions[LdapStatesEnum.VALUE_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.VALUE_STATE,
                LdapStatesEnum.ATTRIBUTE_STATE,
                SEQUENCE,
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Value to Controls
        // --------------------------------------------------------------------------------------------
        // AttributeList ::= SEQUENCE OF SEQUENCE {
        //
        // Initialize the controls
        super.transitions[LdapStatesEnum.VALUE_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.VALUE_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // AddResponse Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... AddResponse ...
        // AddResponse ::= [APPLICATION 9] LDAPResult
        //
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.ADD_RESPONSE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.ADD_RESPONSE_STATE,
                LdapCodecConstants.ADD_RESPONSE_TAG,
                new InitAddResponse(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // AddResponse Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... AddResponse ...
        // AddResponse ::= [APPLICATION 9] LDAPResult
        //
        // LDAPResult ::= SEQUENCE {
        //     resultCode    ENUMERATED {
        //         ...
        //
        // Stores the result code
        super.transitions[LdapStatesEnum.ADD_RESPONSE_STATE.ordinal()][ENUMERATED.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ADD_RESPONSE_STATE,
                LdapStatesEnum.RESULT_CODE_STATE,
                ENUMERATED,
                new StoreResultCode(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // DelResponse Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... DelResponse ...
        // DelResponse ::= [APPLICATION 11] LDAPResult
        // We have to switch to the DelResponse grammar
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.DEL_RESPONSE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.DEL_RESPONSE_STATE,
                LdapCodecConstants.DEL_RESPONSE_TAG,
                new InitDelResponse(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // DelResponse Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... DelResponse ...
        // DelResponse ::= [APPLICATION 11] LDAPResult
        //
        // LDAPResult ::= SEQUENCE {
        //     resultCode    ENUMERATED {
        //         ...
        //
        // Stores the result code
        super.transitions[LdapStatesEnum.DEL_RESPONSE_STATE.ordinal()][ENUMERATED.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.DEL_RESPONSE_STATE,
                LdapStatesEnum.RESULT_CODE_STATE,
                ENUMERATED,
                new StoreResultCode(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from MessageID to ModifydDNRequest Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ModifyDNRequest ...
        // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE { ...
        //
        // Create the ModifyDNRequest Object
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.MODIFY_DN_REQUEST_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.MODIFY_DN_REQUEST_STATE,
                LdapCodecConstants.MODIFY_DN_REQUEST_TAG,
                new InitModifyDnRequest(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ModifydDNRequest Message to EntryModDN
        // --------------------------------------------------------------------------------------------
        // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE { ...
        //     entry LDAPDN,
        //     ...
        //
        // Stores the entry Dn
        super.transitions[LdapStatesEnum.MODIFY_DN_REQUEST_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.MODIFY_DN_REQUEST_STATE,
                LdapStatesEnum.ENTRY_MOD_DN_STATE,
                OCTET_STRING,
                new StoreModifyDnRequestEntryName(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from EntryModDN to NewRDN
        // --------------------------------------------------------------------------------------------
        // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE { ...
        //     ...
        //     newrdn  RelativeRDN,
        //     ...
        //
        // RelativeRDN :: LDAPString
        //
        // Stores the new Rdn
        super.transitions[LdapStatesEnum.ENTRY_MOD_DN_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ENTRY_MOD_DN_STATE,
                LdapStatesEnum.NEW_RDN_STATE,
                OCTET_STRING,
                new StoreModifyDnRequestNewRdn(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from NewRDN to DeleteOldRDN
        // --------------------------------------------------------------------------------------------
        // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE { ...
        //     ...
        //     deleteoldrdn BOOLEAN,
        //     ...
        //
        // Stores the deleteOldRDN flag
        super.transitions[LdapStatesEnum.NEW_RDN_STATE.ordinal()][BOOLEAN.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.NEW_RDN_STATE,
                LdapStatesEnum.DELETE_OLD_RDN_STATE,
                BOOLEAN,
                new StoreModifyDnRequestDeleteOldRdn(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from DeleteOldRDN to NewSuperior
        // --------------------------------------------------------------------------------------------
        // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE { ...
        //     ...
        //     newSuperior [0] LDAPDN OPTIONAL }
        //
        // Stores the new superior
        super.transitions[LdapStatesEnum.DELETE_OLD_RDN_STATE.ordinal()][LdapCodecConstants.MODIFY_DN_REQUEST_NEW_SUPERIOR_TAG] =
            new GrammarTransition(
                LdapStatesEnum.DELETE_OLD_RDN_STATE,
                LdapStatesEnum.NEW_SUPERIOR_STATE,
                LdapCodecConstants.MODIFY_DN_REQUEST_NEW_SUPERIOR_TAG,
                new StoreModifyDnRequestNewSuperior(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from DeleteOldRDN to Controls
        // --------------------------------------------------------------------------------------------
        //     modifyDNRequest ModifyDNRequest,
        //     ... },
        // controls   [0] Controls OPTIONAL }
        //
        // Stores the new superior
        super.transitions[LdapStatesEnum.DELETE_OLD_RDN_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.DELETE_OLD_RDN_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from DeleteOldRDN to Controls
        // --------------------------------------------------------------------------------------------
        //     modifyDNRequest ModifyDNRequest,
        //     ... },
        // controls   [0] Controls OPTIONAL }
        //
        // Stores the new superior
        super.transitions[LdapStatesEnum.NEW_SUPERIOR_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NEW_SUPERIOR_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from MessageID to ModifyDNResponse Message.
        // --------------------------------------------------------------------------------------------
        // ModifyDNResponse ::= [APPLICATION 13] SEQUENCE {
        //     ...
        //
        // Creates the ModifyDNResponse
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.MODIFY_DN_RESPONSE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.MODIFY_DN_RESPONSE_STATE,
                LdapCodecConstants.MODIFY_DN_RESPONSE_TAG,
                new InitModifyDnResponse(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ModifyDNResponse Message to Result Code
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ModifyDNResponse ...
        // ModifyDNResponse ::= [APPLICATION 13] LDAPResult
        //
        // LDAPResult ::= SEQUENCE {
        //     resultCode    ENUMERATED {
        //         ...
        //
        // Stores the result co        //     modifyDNRequest ModifyDNRequest,
        //     ... },
        // controls   [0] Controls OPTIONAL }
        super.transitions[LdapStatesEnum.MODIFY_DN_RESPONSE_STATE.ordinal()][ENUMERATED.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.MODIFY_DN_RESPONSE_STATE,
                LdapStatesEnum.RESULT_CODE_STATE,
                ENUMERATED,
                new StoreResultCode(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Message ID to CompareResquest
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... CompareRequest ...
        //
        // CompareRequest ::= [APPLICATION 14] SEQUENCE {
        // ...
        //
        // Initialize the Compare Request object
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.COMPARE_REQUEST_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.COMPARE_REQUEST_STATE,
                LdapCodecConstants.COMPARE_REQUEST_TAG,
                new InitCompareRequest(), 
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from CompareResquest to entryComp
        // --------------------------------------------------------------------------------------------
        // CompareRequest ::= [APPLICATION 14] SEQUENCE {
        //     entry    LDAPDN,
        //     ...
        //
        // Stores the compared Dn
        super.transitions[LdapStatesEnum.COMPARE_REQUEST_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.COMPARE_REQUEST_STATE,
                LdapStatesEnum.ENTRY_COMP_STATE,
                OCTET_STRING,
                new StoreCompareRequestEntryName(), 
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from entryComp to ava COMP
        // --------------------------------------------------------------------------------------------
        // CompareRequest ::= [APPLICATION 14] SEQUENCE {
        //     ...
        //     ava AttributeValueAssertion }
        //
        // AttributeValueAssertion ::= SEQUENCE {
        //
        // Nothing to do
        super.transitions[LdapStatesEnum.ENTRY_COMP_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ENTRY_COMP_STATE,
                LdapStatesEnum.AVA_COMP_STATE,
                SEQUENCE,
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ava COMP to AttributeDesc COMP
        // --------------------------------------------------------------------------------------------
        // AttributeValueAssertion ::= SEQUENCE {
        //     attributeDesc AttributeDescription,
        //     ...
        //
        // AttributeDescription LDAPString
        //
        // Stores the attribute description
        super.transitions[LdapStatesEnum.AVA_COMP_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.AVA_COMP_STATE,
                LdapStatesEnum.ATTRIBUTE_DESC_COMP_STATE,
                OCTET_STRING,
                new StoreCompareRequestAttributeDesc(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from AttributeDesc to Assertion Value
        // --------------------------------------------------------------------------------------------
        // AttributeValueAssertion ::= SEQUENCE {
        //     ...
        //     assertionValue AssertionValue }
        //
        // AssertionValue OCTET STRING
        //
        // Stores the attribute value
        super.transitions[LdapStatesEnum.ATTRIBUTE_DESC_COMP_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ATTRIBUTE_DESC_COMP_STATE,
                LdapStatesEnum.ASSERTION_VALUE_COMP_STATE,
                OCTET_STRING,
                new StoreCompareRequestAssertionValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Assertion Value to Controls
        // --------------------------------------------------------------------------------------------
        // AttributeValueAssertion ::= SEQUENCE {
        //     ...
        //     assertionValue AssertionValue }
        //
        // AssertionValue OCTET STRING
        //
        // Stores the attribute value
        super.transitions[LdapStatesEnum.ASSERTION_VALUE_COMP_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ASSERTION_VALUE_COMP_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // CompareResponse Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... CompareResponse ...
        // CompareResponse ::= [APPLICATION 15] LDAPResult
        // We have to switch to the CompareResponse grammar
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.COMPARE_RESPONSE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.COMPARE_RESPONSE_STATE,
                LdapCodecConstants.COMPARE_RESPONSE_TAG,
                new InitCompareResponse(), 
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // CompareResponse Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... CompareResponse ...
        // CompareResponse ::= [APPLICATION 15] LDAPResult
        //
        // LDAPResult ::= SEQUENCE {
        //     resultCode    ENUMERATED {
        //         ...
        //
        // Stores the result code
        super.transitions[LdapStatesEnum.COMPARE_RESPONSE_STATE.ordinal()][ENUMERATED.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.COMPARE_RESPONSE_STATE,
                LdapStatesEnum.RESULT_CODE_STATE,
                ENUMERATED,
                new StoreResultCode(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from MessageID to SearchResultReference Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... SearchResultReference ...
        // SearchResultReference ::= [APPLICATION 19] SEQUENCE SIZE (1..MAX) OF uri OCTET STRING
        //
        // Initialization of SearchResultReference object
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.SEARCH_RESULT_REFERENCE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.SEARCH_RESULT_REFERENCE_STATE,
                LdapCodecConstants.SEARCH_RESULT_REFERENCE_TAG,
                new InitSearchResultReference(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from SearchResultReference Message to Reference
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... SearchResultReference ...
        // SearchResultReference ::= [APPLICATION 19] SEQUENCE SIZE (1..MAX) OF uri OCTET STRING
        //
        // Initialization of SearchResultReference object
        super.transitions[LdapStatesEnum.SEARCH_RESULT_REFERENCE_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.SEARCH_RESULT_REFERENCE_STATE,
                LdapStatesEnum.REFERENCE_STATE,
                OCTET_STRING,
                new StoreReference(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Reference to Reference
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... SearchResultReference ...
        // SearchResultReference ::= [APPLICATION 19] SEQUENCE OF LDAPURL
        //
        // Initialization of SearchResultReference object
        super.transitions[LdapStatesEnum.REFERENCE_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.REFERENCE_STATE,
                LdapStatesEnum.REFERENCE_STATE,
                OCTET_STRING,
                new StoreReference(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Reference to Controls
        // --------------------------------------------------------------------------------------------
        //     searchResultReference SearchResultReference,
        //     ... },
        // controls   [0] Controls OPTIONAL }
        //
        // Initialization the controls
        super.transitions[LdapStatesEnum.REFERENCE_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.REFERENCE_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Message Id to ExtendedRequest Message
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ExtendedRequest ...
        // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
        //
        // Creates the ExtendedRequest object
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.EXTENDED_REQUEST_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.EXTENDED_REQUEST_STATE,
                LdapCodecConstants.EXTENDED_REQUEST_TAG,
                new InitExtendedRequest(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ExtendedRequest Message to RequestName
        // --------------------------------------------------------------------------------------------
        // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
        //     requestName [0] LDAPOID,
        //     ...
        //
        // Stores the name
        super.transitions[LdapStatesEnum.EXTENDED_REQUEST_STATE.ordinal()][LdapCodecConstants.EXTENDED_REQUEST_NAME_TAG] =
            new GrammarTransition(
                LdapStatesEnum.EXTENDED_REQUEST_STATE,
                LdapStatesEnum.REQUEST_NAME_STATE,
                LdapCodecConstants.EXTENDED_REQUEST_NAME_TAG,
                new StoreExtendedRequestName(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from RequestName to RequestValue
        // --------------------------------------------------------------------------------------------
        // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
        //     ...
        //     requestValue  [1] OCTET STRING OPTIONAL }
        //
        // Stores the value
        super.transitions[LdapStatesEnum.REQUEST_NAME_STATE.ordinal()][LdapCodecConstants.EXTENDED_REQUEST_VALUE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.REQUEST_NAME_STATE,
                LdapStatesEnum.REQUEST_VALUE_STATE,
                LdapCodecConstants.EXTENDED_REQUEST_VALUE_TAG,
                new StoreExtendedRequestValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from RequestName to Controls
        // --------------------------------------------------------------------------------------------
        //         extendedRequest   EtendedRequest,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        // Stores the value
        super.transitions[LdapStatesEnum.REQUEST_NAME_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.REQUEST_NAME_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from RequestValue to Controls
        // --------------------------------------------------------------------------------------------
        //         extendedRequest   EtendedRequest,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        // Stores the value
        super.transitions[LdapStatesEnum.REQUEST_VALUE_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.REQUEST_VALUE_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from MessageId to ExtendedResponse Message.
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ExtendedResponse ...
        // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
        //
        // Creates the ExtendeResponse object
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.EXTENDED_RESPONSE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.EXTENDED_RESPONSE_STATE,
                LdapCodecConstants.EXTENDED_RESPONSE_TAG,
                new InitExtendedResponse(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ExtendedResponse Message to Result Code ER
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ExtendedResponse ...
        // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
        //     COMPONENTS OF LDAPResult,
        //     ...
        //
        // Stores the result code
        super.transitions[LdapStatesEnum.EXTENDED_RESPONSE_STATE.ordinal()][ENUMERATED.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.EXTENDED_RESPONSE_STATE,
                LdapStatesEnum.RESULT_CODE_ER_STATE,
                ENUMERATED,
                new StoreResultCode(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Result Code ER to Matched Dn ER
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ExtendedResponse ...
        // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
        //     COMPONENTS OF LDAPResult,
        //     ...
        //
        //
        super.transitions[LdapStatesEnum.RESULT_CODE_ER_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.RESULT_CODE_ER_STATE,
                LdapStatesEnum.MATCHED_DN_ER_STATE,
                OCTET_STRING,
                new StoreMatchedDN(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Matched Dn ER to diagnosticMessage ER
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ExtendedResponse ...
        // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
        //     COMPONENTS OF LDAPResult,
        //     ...
        //
        //
        super.transitions[LdapStatesEnum.MATCHED_DN_ER_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.MATCHED_DN_ER_STATE,
                LdapStatesEnum.DIAGNOSTIC_MESSAGE_ER_STATE,
                OCTET_STRING,
                new StoreErrorMessage(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from diagnosticMessage ER to Referrals ER
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ExtendedResponse ...
        // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
        //     COMPONENTS OF LDAPResult,
        //     ...
        //
        //
        super.transitions[LdapStatesEnum.DIAGNOSTIC_MESSAGE_ER_STATE.ordinal()][LdapCodecConstants.LDAP_RESULT_REFERRAL_SEQUENCE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.DIAGNOSTIC_MESSAGE_ER_STATE,
                LdapStatesEnum.REFERRAL_ER_STATE,
                LdapCodecConstants.LDAP_RESULT_REFERRAL_SEQUENCE_TAG,
                new InitReferrals(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Referrals ER to URI ER
        // --------------------------------------------------------------------------------------------
        // Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI (RFC 4511)
        // URI ::= LDAPString
        //
        // Add a first Referral
        super.transitions[LdapStatesEnum.REFERRAL_ER_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.REFERRAL_ER_STATE,
                LdapStatesEnum.URI_ER_STATE,
                OCTET_STRING,
                new AddReferral(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from URI ER to URI ER
        // --------------------------------------------------------------------------------------------
        // Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI (RFC 4511)
        // URI ::= LDAPString
        //
        // Adda new Referral
        super.transitions[LdapStatesEnum.REFERRAL_ER_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.URI_ER_STATE,
                LdapStatesEnum.URI_ER_STATE,
                OCTET_STRING,
                new AddReferral(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from URI ER to ResponseName
        // --------------------------------------------------------------------------------------------
        // Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI (RFC 4511)
        // URI ::= LDAPString
        //
        // Adda new Referral
        super.transitions[LdapStatesEnum.REFERRAL_ER_STATE.ordinal()][LdapCodecConstants.EXTENDED_RESPONSE_NAME_TAG] =
            new GrammarTransition(
                LdapStatesEnum.URI_ER_STATE,
                LdapStatesEnum.RESPONSE_NAME_STATE,
                LdapCodecConstants.EXTENDED_RESPONSE_NAME_TAG,
                new StoreExtendedResponseName(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from URI ER to ResponseValue
        // --------------------------------------------------------------------------------------------
        // Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI (RFC 4511)
        // URI ::= LDAPString
        //
        // Add a new Referral
        super.transitions[LdapStatesEnum.URI_ER_STATE.ordinal()][LdapCodecConstants.EXTENDED_RESPONSE_VALUE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.URI_ER_STATE,
                LdapStatesEnum.RESPONSE_VALUE_STATE,
                LdapCodecConstants.EXTENDED_RESPONSE_VALUE_TAG,
                new StoreExtendedResponseValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Referral ER to Controls
        // --------------------------------------------------------------------------------------------
        //         extendedResponse   ExtendedResponse,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        // Adda new Referral
        super.transitions[LdapStatesEnum.REFERRAL_ER_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.URI_ER_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from diagnosticMessage ER to Controls
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ExtendedResponse ...
        // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
        //     COMPONENTS OF LDAPResult,
        //     ...
        //
        //
        super.transitions[LdapStatesEnum.DIAGNOSTIC_MESSAGE_ER_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.DIAGNOSTIC_MESSAGE_ER_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from diagnosticMessage ER to ResponseName
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ExtendedResponse ...
        // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
        //     COMPONENTS OF LDAPResult,
        //     responseName   [10] LDAPOID OPTIONAL,
        //     ...
        //
        // Stores the response name
        super.transitions[LdapStatesEnum.DIAGNOSTIC_MESSAGE_ER_STATE.ordinal()][LdapCodecConstants.EXTENDED_RESPONSE_NAME_TAG] =
            new GrammarTransition(
                LdapStatesEnum.DIAGNOSTIC_MESSAGE_ER_STATE,
                LdapStatesEnum.RESPONSE_NAME_STATE,
                LdapCodecConstants.EXTENDED_RESPONSE_NAME_TAG,
                new StoreExtendedResponseName(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Response Name to ResponseValue
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ExtendedResponse ...
        // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
        //     ...
        //     responseName   [10] LDAPOID OPTIONAL,
        //     responseValue  [11] OCTET STRING OPTIONAL}
        //
        // Stores the response
        super.transitions[LdapStatesEnum.RESPONSE_NAME_STATE.ordinal()][LdapCodecConstants.EXTENDED_RESPONSE_VALUE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.RESPONSE_NAME_STATE,
                LdapStatesEnum.RESPONSE_VALUE_STATE,
                LdapCodecConstants.EXTENDED_RESPONSE_VALUE_TAG,
                new StoreExtendedResponseValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ResponseName to Controls
        // --------------------------------------------------------------------------------------------
        //         extendedRequest   EtendedRequest,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        // Init the controls
        super.transitions[LdapStatesEnum.RESPONSE_NAME_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.RESPONSE_NAME_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from diagnosticMessage ER to ResponseValue
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... ExtendedResponse ...
        // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
        //     COMPONENTS OF LDAPResult,
        //     ...
        //     responseValue  [11] OCTET STRING OPTIONAL}
        //
        // Stores the response
        super.transitions[LdapStatesEnum.DIAGNOSTIC_MESSAGE_ER_STATE.ordinal()][LdapCodecConstants.EXTENDED_RESPONSE_VALUE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.DIAGNOSTIC_MESSAGE_ER_STATE,
                LdapStatesEnum.RESPONSE_VALUE_STATE,
                LdapCodecConstants.EXTENDED_RESPONSE_VALUE_TAG,
                new StoreExtendedResponseValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ResponseValue to Controls
        // --------------------------------------------------------------------------------------------
        //         extendedRequest   EtendedRequest,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        // Init the controls
        super.transitions[LdapStatesEnum.RESPONSE_VALUE_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.RESPONSE_VALUE_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Message Id to IntermediateResponse Message
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... IntermediateResponse ...
        // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
        //
        // Creates the IntermediateResponse object
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.INTERMEDIATE_RESPONSE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.INTERMEDIATE_RESPONSE_STATE,
                LdapCodecConstants.INTERMEDIATE_RESPONSE_TAG,
                new InitIntermediateResponse(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from IntermediateResponse Message to ResponseName
        // --------------------------------------------------------------------------------------------
        // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
        //     responseName [0] LDAPOID OPTIONAL,
        //     ...
        //
        // Stores the name
        super.transitions[LdapStatesEnum.INTERMEDIATE_RESPONSE_STATE.ordinal()][LdapCodecConstants.INTERMEDIATE_RESPONSE_NAME_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INTERMEDIATE_RESPONSE_STATE,
                LdapStatesEnum.INTERMEDIATE_RESPONSE_NAME_STATE,
                LdapCodecConstants.INTERMEDIATE_RESPONSE_NAME_TAG,
                new StoreIntermediateResponseName(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from IntermediateResponse Message to ResponseValue (ResponseName is null)
        // --------------------------------------------------------------------------------------------
        // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
        //     ...
        //     responseValue [1] OCTET STRING OPTIONAL
        //     }
        //
        // Stores the value
        super.transitions[LdapStatesEnum.INTERMEDIATE_RESPONSE_STATE.ordinal()][LdapCodecConstants.INTERMEDIATE_RESPONSE_VALUE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INTERMEDIATE_RESPONSE_STATE,
                LdapStatesEnum.INTERMEDIATE_RESPONSE_VALUE_STATE,
                LdapCodecConstants.INTERMEDIATE_RESPONSE_VALUE_TAG,
                new StoreIntermediateResponseValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ResponseName to ResponseValue
        // --------------------------------------------------------------------------------------------
        // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
        //     ...
        //     responseValue  [1] OCTET STRING OPTIONAL }
        //
        // Stores the value
        super.transitions[LdapStatesEnum.INTERMEDIATE_RESPONSE_NAME_STATE.ordinal()][LdapCodecConstants.INTERMEDIATE_RESPONSE_VALUE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INTERMEDIATE_RESPONSE_NAME_STATE,
                LdapStatesEnum.INTERMEDIATE_RESPONSE_VALUE_STATE,
                LdapCodecConstants.INTERMEDIATE_RESPONSE_VALUE_TAG,
                new StoreIntermediateResponseValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ResponseName to Controls
        // --------------------------------------------------------------------------------------------
        //         intermediateResponse   IntermediateResponse,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        // Stores the value
        super.transitions[LdapStatesEnum.INTERMEDIATE_RESPONSE_NAME_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INTERMEDIATE_RESPONSE_NAME_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from ResponseValue to Controls
        // --------------------------------------------------------------------------------------------
        //         intermediateResponse   IntermediateResponse,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        // Stores the value
        super.transitions[LdapStatesEnum.INTERMEDIATE_RESPONSE_VALUE_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INTERMEDIATE_RESPONSE_VALUE_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // ============================================================================================
        // Transition from Controls to Control
        // ============================================================================================
        // ...
        // Controls ::= SEQUENCE OF Control
        //  ...
        //
        // Initialize the controls
        super.transitions[LdapStatesEnum.CONTROLS_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.CONTROLS_STATE,
                LdapStatesEnum.CONTROL_STATE,
                SEQUENCE,
                new CheckLengthNotNull(),
                FollowUp.OPTIONAL );

        // ============================================================================================
        // Transition from Control to ControlType
        // ============================================================================================
        // Control ::= SEQUENCE {
        //     ...
        //
        // Create a new Control object, and store it in the message Container
        super.transitions[LdapStatesEnum.CONTROL_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.CONTROL_STATE,
                LdapStatesEnum.CONTROL_TYPE_STATE,
                OCTET_STRING,
                new StoreControlName(),
                FollowUp.OPTIONAL );

        // ============================================================================================
        // Transition from ControlType to Control Criticality
        // ============================================================================================
        // Control ::= SEQUENCE {
        //     ...
        //     criticality BOOLEAN DEFAULT FALSE,
        //     ...
        //
        // Store the value in the control object created before
        super.transitions[LdapStatesEnum.CONTROL_TYPE_STATE.ordinal()][BOOLEAN.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.CONTROL_TYPE_STATE,
                LdapStatesEnum.CRITICALITY_STATE,
                OCTET_STRING,
                new StoreControlCriticality(),
                FollowUp.OPTIONAL );

        // ============================================================================================
        // Transition from Control Criticality to Control Value
        // ============================================================================================
        // Control ::= SEQUENCE {
        //     ...
        //     controlValue OCTET STRING OPTIONAL }
        //
        // Store the value in the control object created before
        super.transitions[LdapStatesEnum.CRITICALITY_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.CRITICALITY_STATE,
                LdapStatesEnum.CONTROL_VALUE_STATE,
                OCTET_STRING,
                new StoreControlValue(),
                FollowUp.OPTIONAL );

        // ============================================================================================
        // Transition from Control Type to Control Value
        // ============================================================================================
        // Control ::= SEQUENCE {
        //     ...
        //     controlValue OCTET STRING OPTIONAL }
        //
        // Store the value in the control object created before
        super.transitions[LdapStatesEnum.CONTROL_TYPE_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.CONTROL_TYPE_STATE,
                LdapStatesEnum.CONTROL_VALUE_STATE,
                OCTET_STRING,
                new StoreControlValue(),
                FollowUp.OPTIONAL );

        // ============================================================================================
        // Transition from Control Type to Control
        // ============================================================================================
        // Control ::= SEQUENCE {
        //     ...
        //     controlValue OCTET STRING OPTIONAL }
        //
        // Store the value in the control object created before
        super.transitions[LdapStatesEnum.CONTROL_TYPE_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.CONTROL_TYPE_STATE,
                LdapStatesEnum.CONTROL_STATE,
                SEQUENCE,
                new CheckLengthNotNull(),
                FollowUp.OPTIONAL );

        // ============================================================================================
        // Transition from Control Criticality to Control
        // ============================================================================================
        // Control ::= SEQUENCE {
        //     ...
        //     controlValue OCTET STRING OPTIONAL }
        //
        // Store the value in the control object created before
        super.transitions[LdapStatesEnum.CRITICALITY_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.CRITICALITY_STATE,
                LdapStatesEnum.CONTROL_STATE,
                SEQUENCE,
                new CheckLengthNotNull(),
                FollowUp.OPTIONAL );

        // ============================================================================================
        // Transition from Control Value to Control
        // ============================================================================================
        // Control ::= SEQUENCE {
        //     ...
        //     controlValue OCTET STRING OPTIONAL }
        //
        // Store the value in the control object created before
        super.transitions[LdapStatesEnum.CONTROL_VALUE_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.CONTROL_VALUE_STATE,
                LdapStatesEnum.CONTROL_STATE,
                SEQUENCE,
                new CheckLengthNotNull(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from message ID to SearchRequest Message
        // --------------------------------------------------------------------------------------------
        // LdapMessage ::= ... SearchRequest ...
        // SearchRequest ::= [APPLICATION 3] SEQUENCE { ...
        //
        // Initialize the searchRequest object
        super.transitions[LdapStatesEnum.MESSAGE_ID_STATE.ordinal()][LdapCodecConstants.SEARCH_REQUEST_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MESSAGE_ID_STATE,
                LdapStatesEnum.SEARCH_REQUEST_STATE,
                LdapCodecConstants.SEARCH_REQUEST_TAG,
                new InitSearchRequest(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from SearchRequest Message to BaseObject
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     baseObject LDAPDN,
        //     ...
        //
        // We have a value for the base object, we will store it in the message
        super.transitions[LdapStatesEnum.SEARCH_REQUEST_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.SEARCH_REQUEST_STATE,
                LdapStatesEnum.BASE_OBJECT_STATE,
                OCTET_STRING,
                new StoreSearchRequestBaseObject(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from BaseObject to Scope
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     scope ENUMERATED {
        //         baseObject   (0),
        //         singleLevel  (1),
        //         wholeSubtree (2) },
        //     ...
        //
        // We have a value for the scope, we will store it in the message
        super.transitions[LdapStatesEnum.BASE_OBJECT_STATE.ordinal()][ENUMERATED.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.BASE_OBJECT_STATE,
                LdapStatesEnum.SCOPE_STATE,
                ENUMERATED,
                new StoreSearchRequestScope(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Scope to DerefAlias
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     derefAliases ENUMERATED {
        //         neverDerefAliases   (0),
        //         derefInSearching    (1),
        //         derefFindingBaseObj (2),
        //         derefAlways         (3) },
        //     ...
        //
        // We have a value for the derefAliases, we will store it in the message
        super.transitions[LdapStatesEnum.SCOPE_STATE.ordinal()][ENUMERATED.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.SCOPE_STATE,
                LdapStatesEnum.DEREF_ALIAS_STATE,
                ENUMERATED,
                new StoreSearchRequestDerefAlias(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from DerefAlias to SizeLimit
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     sizeLimit INTEGER (0 .. maxInt),
        //     ...
        //
        // We have a value for the sizeLimit, we will store it in the message
        super.transitions[LdapStatesEnum.DEREF_ALIAS_STATE.ordinal()][INTEGER.getValue()] = new
            GrammarTransition(
                LdapStatesEnum.DEREF_ALIAS_STATE,
                LdapStatesEnum.SIZE_LIMIT_STATE,
                INTEGER,
                new StoreSearchRequestSizeLimit(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from SizeLimit to TimeLimit
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     timeLimit INTEGER (0 .. maxInt),
        //     ...
        //
        // We have a value for the timeLimit, we will store it in the message
        super.transitions[LdapStatesEnum.SIZE_LIMIT_STATE.ordinal()][INTEGER.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.SIZE_LIMIT_STATE,
                LdapStatesEnum.TIME_LIMIT_STATE,
                INTEGER,
                new StoreSearchRequestTimeLimit(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from TimeLimit to TypesOnly
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     typesOnly BOOLEAN,
        //     ...
        //
        // We have a value for the typesOnly, we will store it in the message.
        super.transitions[LdapStatesEnum.TIME_LIMIT_STATE.ordinal()][BOOLEAN.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.TIME_LIMIT_STATE,
                LdapStatesEnum.TYPES_ONLY_STATE,
                BOOLEAN,
                new StoreSearchRequestTypesOnly(),
                FollowUp.MANDATORY );

        //============================================================================================
        // Search Request And Filter
        // This is quite complicated, because we have a tree structure to build,
        // and we may have many elements on each node. For instance, considering the
        // search filter :
        // (& (| (a = b) (c = d)) (! (e = f)) (attr =* h))
        // We will have to create an And filter with three children :
        //  - an Or child,
        //  - a Not child
        //  - and a Present child.
        // The Or child will also have two children.
        //
        // We know when we have a children while decoding the PDU, because the length
        // of its parent has not yet reached its expected length.
        //
        // This search filter :
        // (&(|(objectclass=top)(ou=contacts))(!(objectclass=ttt))(objectclass=*top))
        // is encoded like this :
        //                              +----------------+---------------+
        //                              | ExpectedLength | CurrentLength |
        //+-----------------------------+----------------+---------------+
        //|A0 52                        | 82             | 0             | new level 1
        //|   A1 24                     | 82 36          | 0 0           | new level 2
        //|      A3 12                  | 82 36 18       | 0 0 0         | new level 3
        //|         04 0B 'objectclass' | 82 36 18       | 0 0 13        |
        //|         04 03 'top'         | 82 36 18       | 0 20 18       |
        //|                             |       ^               ^        |
        //|                             |       |               |        |
        //|                             |       +---------------+        |
        //+-----------------------------* end level 3 -------------------*
        //|      A3 0E                  | 82 36 14       | 0 0 0         | new level 3
        //|         04 02 'ou'          | 82 36 14       | 0 0 4         |
        //|         04 08 'contacts'    | 82 36 14       | 38 36 14      |
        //|                             |    ^  ^             ^  ^       |
        //|                             |    |  |             |  |       |
        //|                             |    |  +-------------|--+       |
        //|                             |    +----------------+          |
        //+-----------------------------* end level 3, end level 2 ------*
        //|   A2 14                     | 82 20          | 38 0          | new level 2
        //|      A3 12                  | 82 20 18       | 38 0 0        | new level 3
        //|         04 0B 'objectclass' | 82 20 18       | 38 0 13       |
        //|         04 03 'ttt'         | 82 20 18       | 60 20 18      |
        //|                             |    ^  ^             ^  ^       |
        //|                             |    |  |             |  |       |
        //|                             |    |  +-------------|--+       |
        //|                             |    +----------------+          |
        //+-----------------------------* end level 3, end level 2 ------*
        //|   A4 14                     | 82 20          | 60 0          | new level 2
        //|      04 0B 'objectclass'    | 82 20          | 60 13         |
        //|      30 05                  | 82 20          | 60 13         |
        //|         82 03 'top'         | 82 20          | 82 20         |
        //|                             | ^  ^             ^  ^          |
        //|                             | |  |             |  |          |
        //|                             | |  +-------------|--+          |
        //|                             | +----------------+             |
        //+-----------------------------* end level 2, end level 1 ------*
        //+-----------------------------+----------------+---------------+
        //
        // When the current length equals the expected length of the parent PDU,
        // then we are able to 'close' the parent : it has all its children. This
        // is propagated through all the tree, until either there are no more
        // parents, or the expected length of the parent is different from the
        // current length.

        // --------------------------------------------------------------------------------------------
        // Transition from TypesOnly to AND filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     and             [0] SET OF Filter,
        //     ...
        //
        // Init AND filter
        super.transitions[LdapStatesEnum.TYPES_ONLY_STATE.ordinal()][LdapCodecConstants.AND_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.TYPES_ONLY_STATE,
                LdapStatesEnum.AND_STATE,
                LdapCodecConstants.AND_FILTER_TAG,
                new InitAndFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from TypesOnly to OR filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     or              [1] SET OF Filter,
        //     ...
        //
        // Init OR filter
        super.transitions[LdapStatesEnum.TYPES_ONLY_STATE.ordinal()][LdapCodecConstants.OR_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.TYPES_ONLY_STATE,
                LdapStatesEnum.OR_STATE,
                LdapCodecConstants.OR_FILTER_TAG,
                new InitOrFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from TypesOnly to NOT filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     not             [2] SET OF Filter,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.TYPES_ONLY_STATE.ordinal()][LdapCodecConstants.NOT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.TYPES_ONLY_STATE,
                LdapStatesEnum.NOT_STATE,
                LdapCodecConstants.NOT_FILTER_TAG,
                new InitNotFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from TypesOnly to Equality Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch   [3] AttributeValueAssertion,
        //     ...
        //
        // Init Equality filter
        super.transitions[LdapStatesEnum.TYPES_ONLY_STATE.ordinal()][LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.TYPES_ONLY_STATE,
                LdapStatesEnum.EQUALITY_MATCH_STATE,
                LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG,
                new InitEqualityMatchFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from TypesOnly to Substrings filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     substrings     [4] SubstringFilter,
        //     ...
        //
        // Init Substrings filter
        super.transitions[LdapStatesEnum.TYPES_ONLY_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.TYPES_ONLY_STATE,
                LdapStatesEnum.SUBSTRINGS_FILTER_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_TAG,
                new InitSubstringsFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from TypesOnly to GreaterOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     greaterOrEqual  [5] AttributeValueAssertion,
        //     ...
        //
        // Init Greater Or Equal filter
        super.transitions[LdapStatesEnum.TYPES_ONLY_STATE.ordinal()][LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.TYPES_ONLY_STATE,
                LdapStatesEnum.GREATER_OR_EQUAL_STATE,
                LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG,
                new InitGreaterOrEqualFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from TypesOnly to LessOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     LessOrEqual    [6] AttributeValueAssertion,
        //     ...
        //
        // Init Less Or Equal filter
        super.transitions[LdapStatesEnum.TYPES_ONLY_STATE.ordinal()][LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.TYPES_ONLY_STATE,
                LdapStatesEnum.LESS_OR_EQUAL_STATE,
                LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG,
                new InitLessOrEqualFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from TypesOnly to Present filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     present        [7] AttributeDescription,
        //     ...
        //
        // Init Present Match filter
        super.transitions[LdapStatesEnum.TYPES_ONLY_STATE.ordinal()][LdapCodecConstants.PRESENT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.TYPES_ONLY_STATE,
                LdapStatesEnum.PRESENT_STATE,
                LdapCodecConstants.PRESENT_FILTER_TAG,
                new InitPresentFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from TypesOnly to Approx Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     approxMatch     [8] AttributeValueAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.TYPES_ONLY_STATE.ordinal()][LdapCodecConstants.APPROX_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.TYPES_ONLY_STATE,
                LdapStatesEnum.APPROX_MATCH_STATE,
                LdapCodecConstants.APPROX_MATCH_FILTER_TAG,
                new InitApproxMatchFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from TypesOnly to Extensible Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion,
        //     ...
        //
        // Init Extensible Match filter
        super.transitions[LdapStatesEnum.TYPES_ONLY_STATE.ordinal()][LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.TYPES_ONLY_STATE,
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG,
                new InitExtensibleMatchFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from AND to AND filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     and             [0] SET OF Filter,
        //     ...
        //
        // Init AND filter
        super.transitions[LdapStatesEnum.AND_STATE.ordinal()][LdapCodecConstants.AND_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.AND_STATE,
                LdapStatesEnum.AND_STATE,
                LdapCodecConstants.AND_FILTER_TAG,
                new InitAndFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from AND to OR filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     or              [1] SET OF Filter,
        //     ...
        //
        // Init OR filter
        super.transitions[LdapStatesEnum.AND_STATE.ordinal()][LdapCodecConstants.OR_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.AND_STATE,
                LdapStatesEnum.OR_STATE,
                LdapCodecConstants.OR_FILTER_TAG,
                new InitOrFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from AND to NOT filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     not             [2] SET OF Filter,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.AND_STATE.ordinal()][LdapCodecConstants.NOT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.AND_STATE,
                LdapStatesEnum.NOT_STATE,
                LdapCodecConstants.NOT_FILTER_TAG,
                new InitNotFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from AND to Equality Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch   [3] AttributeValueAssertion,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.AND_STATE.ordinal()][LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.AND_STATE,
                LdapStatesEnum.EQUALITY_MATCH_STATE,
                LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG,
                new InitEqualityMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from AND to Substrings filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     substrings     [4] SubstringFilter,
        //     ...
        //
        // Init Substrings filter
        super.transitions[LdapStatesEnum.AND_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.AND_STATE,
                LdapStatesEnum.SUBSTRINGS_FILTER_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_TAG,
                new InitSubstringsFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from AND to GreaterOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     greaterOrEqual  [5] AttributeValueAssertion,
        //     ...
        //
        // Init Greater Or Equal filter
        super.transitions[LdapStatesEnum.AND_STATE.ordinal()][LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.AND_STATE,
                LdapStatesEnum.GREATER_OR_EQUAL_STATE,
                LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG,
                new InitGreaterOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from AND to LessOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     LessOrEqual    [6] AttributeValueAssertion,
        //     ...
        //
        // Init Less Or Equal filter
        super.transitions[LdapStatesEnum.AND_STATE.ordinal()][LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.AND_STATE,
                LdapStatesEnum.LESS_OR_EQUAL_STATE,
                LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG,
                new InitLessOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from AND to Present filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     present        [7] AttributeDescription,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.AND_STATE.ordinal()][LdapCodecConstants.PRESENT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.AND_STATE,
                LdapStatesEnum.PRESENT_STATE,
                LdapCodecConstants.PRESENT_FILTER_TAG,
                new InitPresentFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from AND to Approx Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     approxMatch     [8] AttributeValueAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.AND_STATE.ordinal()][LdapCodecConstants.APPROX_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.AND_STATE,
                LdapStatesEnum.APPROX_MATCH_STATE,
                LdapCodecConstants.APPROX_MATCH_FILTER_TAG,
                new InitApproxMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from AND to Extensible Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.AND_STATE.ordinal()][LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.AND_STATE,
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG,
                new InitExtensibleMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from OR to AND filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     and             [0] SET OF Filter,
        //     ...
        //
        // Init AND filter
        super.transitions[LdapStatesEnum.OR_STATE.ordinal()][LdapCodecConstants.AND_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.OR_STATE,
                LdapStatesEnum.AND_STATE,
                LdapCodecConstants.AND_FILTER_TAG,
                new InitAndFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from OR to OR filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     or              [1] SET OF Filter,
        //     ...
        //
        // Init OR filter
        super.transitions[LdapStatesEnum.OR_STATE.ordinal()][LdapCodecConstants.OR_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.OR_STATE,
                LdapStatesEnum.OR_STATE,
                LdapCodecConstants.OR_FILTER_TAG,
                new InitOrFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from OR to NOT filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     not             [2] SET OF Filter,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.OR_STATE.ordinal()][LdapCodecConstants.NOT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.OR_STATE,
                LdapStatesEnum.NOT_STATE,
                LdapCodecConstants.NOT_FILTER_TAG,
                new InitNotFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from OR to Equality Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch   [3] AttributeValueAssertion,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.OR_STATE.ordinal()][LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.OR_STATE,
                LdapStatesEnum.EQUALITY_MATCH_STATE,
                LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG,
                new InitEqualityMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from OR to Substrings filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     substrings     [4] SubstringFilter,
        //     ...
        //
        // Init Substrings filter
        super.transitions[LdapStatesEnum.OR_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.OR_STATE,
                LdapStatesEnum.SUBSTRINGS_FILTER_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_TAG,
                new InitSubstringsFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from OR to GreaterOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     greaterOrEqual  [5] AttributeValueAssertion,
        //     ...
        //
        // Init Greater Or Equal filter
        super.transitions[LdapStatesEnum.OR_STATE.ordinal()][LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.OR_STATE,
                LdapStatesEnum.GREATER_OR_EQUAL_STATE,
                LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG,
                new InitGreaterOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from OR to LessOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     LessOrEqual    [6] AttributeValueAssertion,
        //     ...
        //
        // Init Less Or Equal filter
        super.transitions[LdapStatesEnum.OR_STATE.ordinal()][LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.OR_STATE,
                LdapStatesEnum.LESS_OR_EQUAL_STATE,
                LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG,
                new InitLessOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from OR to Present filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     present        [7] AttributeDescription,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.OR_STATE.ordinal()][LdapCodecConstants.PRESENT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.OR_STATE,
                LdapStatesEnum.PRESENT_STATE,
                LdapCodecConstants.PRESENT_FILTER_TAG,
                new InitPresentFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from OR to Approx Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     approxMatch     [8] AttributeValueAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.OR_STATE.ordinal()][LdapCodecConstants.APPROX_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.OR_STATE,
                LdapStatesEnum.APPROX_MATCH_STATE,
                LdapCodecConstants.APPROX_MATCH_FILTER_TAG,
                new InitApproxMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from OR to Extensible Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.OR_STATE.ordinal()][LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.OR_STATE,
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG,
                new InitExtensibleMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from NOT to AND filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     and             [0] SET OF Filter,
        //     ...
        //
        // Init AND filter
        super.transitions[LdapStatesEnum.NOT_STATE.ordinal()][LdapCodecConstants.AND_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NOT_STATE,
                LdapStatesEnum.AND_STATE,
                LdapCodecConstants.AND_FILTER_TAG,
                new InitAndFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from NOT to OR filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     or              [1] SET OF Filter,
        //     ...
        //
        // Init OR filter
        super.transitions[LdapStatesEnum.NOT_STATE.ordinal()][LdapCodecConstants.OR_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NOT_STATE,
                LdapStatesEnum.OR_STATE,
                LdapCodecConstants.OR_FILTER_TAG,
                new InitOrFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from NOT to NOT filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     not             [2] SET OF Filter,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.NOT_STATE.ordinal()][LdapCodecConstants.NOT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NOT_STATE,
                LdapStatesEnum.NOT_STATE,
                LdapCodecConstants.NOT_FILTER_TAG,
                new InitNotFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from NOT to Equality Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch   [3] AttributeValueAssertion,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.NOT_STATE.ordinal()][LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NOT_STATE,
                LdapStatesEnum.EQUALITY_MATCH_STATE,
                LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG,
                new InitEqualityMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from NOT to Substrings filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     substrings     [4] SubstringFilter,
        //     ...
        //
        // Init Substrings filter
        super.transitions[LdapStatesEnum.NOT_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NOT_STATE,
                LdapStatesEnum.SUBSTRINGS_FILTER_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_TAG,
                new InitSubstringsFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from NOT to GreaterOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     greaterOrEqual  [5] AttributeValueAssertion,
        //     ...
        //
        // Init Greater Or Equal filter
        super.transitions[LdapStatesEnum.NOT_STATE.ordinal()][LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NOT_STATE,
                LdapStatesEnum.GREATER_OR_EQUAL_STATE,
                LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG,
                new InitGreaterOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from NOT to LessOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     LessOrEqual    [6] AttributeValueAssertion,
        //     ...
        //
        // Init Less Or Equal filter
        super.transitions[LdapStatesEnum.NOT_STATE.ordinal()][LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NOT_STATE,
                LdapStatesEnum.LESS_OR_EQUAL_STATE,
                LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG,
                new InitLessOrEqualFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from NOT to Present filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     present        [7] AttributeDescription,
        //     ...
        //
        // Init present filter
        super.transitions[LdapStatesEnum.NOT_STATE.ordinal()][LdapCodecConstants.PRESENT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NOT_STATE,
                LdapStatesEnum.PRESENT_STATE,
                LdapCodecConstants.PRESENT_FILTER_TAG,
                new InitPresentFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from NOT to Approx Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     approxMatch     [8] AttributeValueAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.NOT_STATE.ordinal()][LdapCodecConstants.APPROX_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NOT_STATE,
                LdapStatesEnum.APPROX_MATCH_STATE,
                LdapCodecConstants.APPROX_MATCH_FILTER_TAG,
                new InitApproxMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from NOT to Extensible Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion,
        //     ...
        //
        // Init extensible match filter
        super.transitions[LdapStatesEnum.NOT_STATE.ordinal()][LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.NOT_STATE,
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG,
                new InitExtensibleMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Equality match filter to Attribute Value Assertion's AttributeDesc
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch  [3] AttributeValueAssertion,
        //     ...
        //
        // AttributeValueAssertion ::= SEQUENCE {
        //    attributeDesc   AttributeDescription,
        //     ...
        //
        // Init Attribute Desc filter
        super.transitions[LdapStatesEnum.EQUALITY_MATCH_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.EQUALITY_MATCH_STATE,
                LdapStatesEnum.ATTRIBUTE_DESC_FILTER_STATE,
                OCTET_STRING,
                new InitAttributeDescFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Attribute Desc Filter to Assertion Value Filter
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch  [3] AttributeValueAssertion,
        //     ...
        //
        // AttributeValueAssertion ::= SEQUENCE {
        //     ...
        //     assertionValue   AssertionValue }
        //
        // Init Assertion Value filter
        super.transitions[LdapStatesEnum.ATTRIBUTE_DESC_FILTER_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ATTRIBUTE_DESC_FILTER_STATE,
                LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE,
                OCTET_STRING,
                new InitAssertionValueFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Assertion Value Filter to AND filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     and             [0] SET OF Filter,
        //     ...
        //
        // Init AND filter
        super.transitions[LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE.ordinal()][LdapCodecConstants.AND_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE,
                LdapStatesEnum.AND_STATE,
                LdapCodecConstants.AND_FILTER_TAG,
                new InitAndFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Assertion Value Filter to OR filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     or              [1] SET OF Filter,
        //     ...
        //
        // Init OR filter
        super.transitions[LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE.ordinal()][LdapCodecConstants.OR_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE,
                LdapStatesEnum.OR_STATE,
                LdapCodecConstants.OR_FILTER_TAG,
                new InitOrFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Assertion Value Filter to NOT filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     not             [2] SET OF Filter,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE.ordinal()][LdapCodecConstants.NOT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE,
                LdapStatesEnum.NOT_STATE,
                LdapCodecConstants.NOT_FILTER_TAG,
                new InitNotFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Assertion Value Filter to Equality Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch   [3] AttributeValueAssertion,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE.ordinal()][LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE,
                LdapStatesEnum.EQUALITY_MATCH_STATE,
                LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG,
                new InitEqualityMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Assertion Value Filter to Substrings filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     substrings     [4] SubstringFilter,
        //     ...
        //
        // Init Substrings filter
        super.transitions[LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE,
                LdapStatesEnum.SUBSTRINGS_FILTER_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_TAG,
                new InitSubstringsFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Assertion Value Filter to GreaterOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     greaterOrEqual  [5] AttributeValueAssertion,
        //     ...
        //
        // Init Greater Or Equal filter
        super.transitions[LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE.ordinal()][LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE,
                LdapStatesEnum.GREATER_OR_EQUAL_STATE,
                LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG,
                new InitGreaterOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Assertion Value Filter to LessOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     LessOrEqual    [6] AttributeValueAssertion,
        //     ...
        //
        // Init Less Or Equal filter
        super.transitions[LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE.ordinal()][LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE,
                LdapStatesEnum.LESS_OR_EQUAL_STATE,
                LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG,
                new InitLessOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Assertion Value Filter to Present filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     present        [7] AttributeDescription,
        //     ...
        //
        // Init present filter
        super.transitions[LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE.ordinal()][LdapCodecConstants.PRESENT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE,
                LdapStatesEnum.PRESENT_STATE,
                LdapCodecConstants.PRESENT_FILTER_TAG,
                new InitPresentFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from Assertion Value Filter to Approx Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     approxMatch     [8] AttributeValueAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE.ordinal()][LdapCodecConstants.APPROX_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE,
                LdapStatesEnum.APPROX_MATCH_STATE,
                LdapCodecConstants.APPROX_MATCH_FILTER_TAG,
                new InitApproxMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Assertion Value Filter to Extensible Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion,
        //     ...
        //
        // Init Assertion Value Filter filter
        super.transitions[LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE.ordinal()][LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE,
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG,
                new InitExtensibleMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Assertion Value Filter to Attribute Description List
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter      Filter,
        //     attributes  AttributeSelection }
        //
        // AttributeSelection ::= SEQUENCE OF selector LDAPSTRING
        //
        // Init attribute description list
        super.transitions[LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ASSERTION_VALUE_FILTER_STATE,
                LdapStatesEnum.ATTRIBUTE_SELECTION_STATE,
                SEQUENCE,
                new InitSearchRequestAttributeDescList(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Attribute Description List to Controls
        // --------------------------------------------------------------------------------------------
        //         searchRequest   SearchRequest,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        //
        // Empty attribute description list, with controls
        super.transitions[LdapStatesEnum.ATTRIBUTE_SELECTION_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ATTRIBUTE_SELECTION_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Attribute Selection to selector
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter      Filter,
        //     attributes  AttributeSelection }
        //
        // AttributeSelection ::= SEQUENCE OF selector LDAPSTRING
        //
        // Store attribute description
        super.transitions[LdapStatesEnum.ATTRIBUTE_SELECTION_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ATTRIBUTE_SELECTION_STATE,
                LdapStatesEnum.SELECTOR_STATE,
                OCTET_STRING,
                new StoreSearchRequestAttributeDesc(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from selector to selector
        // --------------------------------------------------------------------------------------------
        // AttributeSelection ::= SEQUENCE OF selector LDAPSTRING
        //
        // Store attribute description
        super.transitions[LdapStatesEnum.SELECTOR_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.SELECTOR_STATE,
                LdapStatesEnum.SELECTOR_STATE,
                OCTET_STRING,
                new StoreSearchRequestAttributeDesc(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from selector to controls
        // --------------------------------------------------------------------------------------------
        //         searchRequest   SearchRequest,
        //         ... },
        //     controls       [0] Controls OPTIONAL }
        super.transitions[LdapStatesEnum.SELECTOR_STATE.ordinal()][LdapCodecConstants.CONTROLS_TAG] =
            new GrammarTransition(
                LdapStatesEnum.SELECTOR_STATE,
                LdapStatesEnum.CONTROLS_STATE,
                LdapCodecConstants.CONTROLS_TAG,
                new InitControls(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Greater Or Equal to Attribute Desc Filter
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     greaterOrEqual  [5] AttributeValueAssertion,
        //     ...
        //
        // AttributeValueAssertion ::= SEQUENCE {
        //     attributeDesc   AttributeDescription,
        //     ...
        //
        // Init Attribute Desc filter
        super.transitions[LdapStatesEnum.GREATER_OR_EQUAL_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.GREATER_OR_EQUAL_STATE,
                LdapStatesEnum.ATTRIBUTE_DESC_FILTER_STATE,
                OCTET_STRING,
                new InitAttributeDescFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Less Or Equal to Attribute Desc Filter
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     lessOrEqual  [6] AttributeValueAssertion,
        //     ...
        //
        // AttributeValueAssertion ::= SEQUENCE {
        //    attributeDesc   AttributeDescription,
        //     ...
        //
        // Init Attribute Desc filter
        super.transitions[LdapStatesEnum.LESS_OR_EQUAL_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.LESS_OR_EQUAL_STATE,
                LdapStatesEnum.ATTRIBUTE_DESC_FILTER_STATE,
                OCTET_STRING,
                new InitAttributeDescFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Substrings to typeSubstring
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     substrings  [4] SubstringFilter,
        //     ...
        //
        // SubstringFilter ::= SEQUENCE {
        //     type   AttributeDescription,
        //     ...
        //
        // Init substring type
        super.transitions[LdapStatesEnum.SUBSTRINGS_FILTER_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.SUBSTRINGS_FILTER_STATE,
                LdapStatesEnum.TYPE_SUBSTRING_STATE,
                OCTET_STRING,
                new StoreSubstringFilterType(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from typeSubstring to substrings
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     substrings  [4] SubstringFilter,
        //     ...
        //
        // SubstringFilter ::= SEQUENCE {
        //     ...
        //     substrings SEQUENCE OF CHOICE {
        //     ...
        //
        // Init substring type
        super.transitions[LdapStatesEnum.TYPE_SUBSTRING_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.TYPE_SUBSTRING_STATE,
                LdapStatesEnum.SUBSTRINGS_STATE,
                SEQUENCE,
                new CheckNotNullLength<LdapMessageContainer<SearchRequest>>(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from substrings to Initial
        // --------------------------------------------------------------------------------------------
        // SubstringFilter ::= SEQUENCE {
        //     ...
        //     substrings SEQUENCE OF CHOICE {
        //         initial  [0] LDAPSTRING,
        //         ...
        //
        // Store initial value
        super.transitions[LdapStatesEnum.SUBSTRINGS_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_INITIAL_TAG] =
            new GrammarTransition(
                LdapStatesEnum.SUBSTRINGS_STATE,
                LdapStatesEnum.INITIAL_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_INITIAL_TAG,
                new StoreInitial(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from substrings to any
        // --------------------------------------------------------------------------------------------
        // SubstringFilter ::= SEQUENCE {
        //     ...
        //     substrings SEQUENCE OF CHOICE {
        //         ...
        //         any  [1] LDAPSTRING,
        //         ...
        //
        // Store substring any type
        super.transitions[LdapStatesEnum.SUBSTRINGS_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_ANY_TAG] =
            new GrammarTransition(
                LdapStatesEnum.SUBSTRINGS_STATE,
                LdapStatesEnum.ANY_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_ANY_TAG,
                new StoreAny(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from substrings to final
        // --------------------------------------------------------------------------------------------
        // SubstringFilter ::= SEQUENCE {
        //     ...
        //     substrings SEQUENCE OF CHOICE {
        //         ...
        //         final  [2] LDAPSTRING }
        //
        // Store substring final type
        super.transitions[LdapStatesEnum.SUBSTRINGS_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_FINAL_TAG] =
            new GrammarTransition(
                LdapStatesEnum.SUBSTRINGS_STATE,
                LdapStatesEnum.FINAL_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_FINAL_TAG,
                new StoreFinal(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to any
        // --------------------------------------------------------------------------------------------
        // SubstringFilter ::= SEQUENCE {
        //     ...
        //     substrings SEQUENCE OF CHOICE {
        //         ...
        //         any  [1] LDAPSTRING,
        //         ...
        //
        // Store substring any type
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_ANY_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.ANY_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_ANY_TAG,
                new StoreAny(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to final
        // --------------------------------------------------------------------------------------------
        // SubstringFilter ::= SEQUENCE {
        //     ...
        //     substrings SEQUENCE OF CHOICE {
        //         ...
        //         final  [2] LDAPSTRING }
        //
        // Store substring final type
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_FINAL_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.FINAL_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_FINAL_TAG,
                new StoreFinal(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to Attribute Selection
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter      Filter,
        //     attributes      AttributeSelection }
        //
        // AttributeSelection ::= SEQUENCE OF selector OCTET STRING
        //
        // Init attribute description list
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.ATTRIBUTE_SELECTION_STATE,
                SEQUENCE,
                new InitSearchRequestAttributeDescList(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to AND filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     and             [0] SET OF Filter,
        //     ...
        //
        // Init AND filter
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][LdapCodecConstants.AND_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.AND_STATE,
                LdapCodecConstants.AND_FILTER_TAG,
                new InitAndFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to OR filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     or              [1] SET OF Filter,
        //     ...
        //
        // Init OR filter
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][LdapCodecConstants.OR_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.OR_STATE,
                LdapCodecConstants.OR_FILTER_TAG,
                new InitOrFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to NOT filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     not             [2] SET OF Filter,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][LdapCodecConstants.NOT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.NOT_STATE,
                LdapCodecConstants.NOT_FILTER_TAG,
                new InitNotFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to Equality Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch   [3] AttributeValueAssertion,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.EQUALITY_MATCH_STATE,
                LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG,
                new InitEqualityMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to Substrings filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     substrings     [4] SubstringFilter,
        //     ...
        //
        // Init Substrings filter
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.SUBSTRINGS_FILTER_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_TAG,
                new InitSubstringsFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to GreaterOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     greaterOrEqual  [5] AttributeValueAssertion,
        //     ...
        //
        // Init Greater Or Equal filter
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.GREATER_OR_EQUAL_STATE,
                LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG,
                new InitGreaterOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to LessOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     LessOrEqual    [6] AttributeValueAssertion,
        //     ...
        //
        // Init Less Or Equal filter
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.LESS_OR_EQUAL_STATE,
                LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG,
                new InitLessOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to Present filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     present        [7] AttributeDescription,
        //     ...
        //
        // Init present filter
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][LdapCodecConstants.PRESENT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.PRESENT_STATE,
                LdapCodecConstants.PRESENT_FILTER_TAG,
                new InitPresentFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to Approx Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     approxMatch     [8] AttributeValueAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][LdapCodecConstants.APPROX_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.APPROX_MATCH_STATE,
                LdapCodecConstants.APPROX_MATCH_FILTER_TAG,
                new InitApproxMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from initial to Extensible Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion,
        //     ...
        //
        // Init Assertion Value Filter filter
        super.transitions[LdapStatesEnum.INITIAL_STATE.ordinal()][LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.INITIAL_STATE,
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG,
                new InitExtensibleMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from any to final
        // --------------------------------------------------------------------------------------------
        // SubstringFilter ::= SEQUENCE {
        //     ...
        //     substrings SEQUENCE OF CHOICE {
        //         ...
        //         final  [2] LDAPSTRING }
        //
        // Store substring final type
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_FINAL_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.FINAL_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_FINAL_TAG,
                new StoreFinal(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from any to any
        // --------------------------------------------------------------------------------------------
        // SubstringFilter ::= SEQUENCE {
        //     ...
        //     substrings SEQUENCE OF CHOICE {
        //         ...
        //         any  [1] LDAPSTRING
        //         ...
        //
        // Store substring any type
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_ANY_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.ANY_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_ANY_TAG,
                new StoreAny(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from any to Attribute Description List
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter      Filter,
        //     attributes  AttributeDescriptionList }
        //
        // AttributeDescriptionList ::= SEQUENCE OF
        //     AttributeDescription
        //
        // Init attribute description list
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.ATTRIBUTE_SELECTION_STATE,
                SEQUENCE,
                new InitSearchRequestAttributeDescList(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from any to AND filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     and             [0] SET OF Filter,
        //     ...
        //
        // Init AND filter
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][LdapCodecConstants.AND_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.AND_STATE,
                LdapCodecConstants.AND_FILTER_TAG,
                new InitAndFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from any to OR filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     or              [1] SET OF Filter,
        //     ...
        //
        // Init OR filter
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][LdapCodecConstants.OR_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.OR_STATE,
                LdapCodecConstants.OR_FILTER_TAG,
                new InitOrFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from any to NOT filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     not             [2] SET OF Filter,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][LdapCodecConstants.NOT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.NOT_STATE,
                LdapCodecConstants.NOT_FILTER_TAG,
                new InitNotFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from any to Equality Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch   [3] AttributeValueAssertion,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.EQUALITY_MATCH_STATE,
                LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG,
                new InitEqualityMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from any to Substrings filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     substrings     [4] SubstringFilter,
        //     ...
        //
        // Init Substrings filter
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.SUBSTRINGS_FILTER_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_TAG,
                new InitSubstringsFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from any to GreaterOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     greaterOrEqual  [5] AttributeValueAssertion,
        //     ...
        //
        // Init Greater Or Equal filter
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.GREATER_OR_EQUAL_STATE,
                LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG,
                new InitGreaterOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from any to LessOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     LessOrEqual    [6] AttributeValueAssertion,
        //     ...
        //
        // Init Less Or Equal filter
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.LESS_OR_EQUAL_STATE,
                LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG,
                new InitLessOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from any to Present filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     present        [7] AttributeDescription,
        //     ...
        //
        // Init present filter
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][LdapCodecConstants.PRESENT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.PRESENT_STATE,
                LdapCodecConstants.PRESENT_FILTER_TAG,
                new InitPresentFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from any to Approx Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     approxMatch     [8] AttributeValueAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][LdapCodecConstants.APPROX_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.APPROX_MATCH_STATE,
                LdapCodecConstants.APPROX_MATCH_FILTER_TAG,
                new InitApproxMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from any to Extensible Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion,
        //     ...
        //
        // Init Assertion Value Filter filter
        super.transitions[LdapStatesEnum.ANY_STATE.ordinal()][LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.ANY_STATE,
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG,
                new InitExtensibleMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from final to Attribute Description List
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter      Filter,
        //     attributes  AttributeDescriptionList }
        //
        // AttributeDescriptionList ::= SEQUENCE OF
        //     AttributeDescription
        //
        // Init attribute description list
        super.transitions[LdapStatesEnum.FINAL_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.FINAL_STATE,
                LdapStatesEnum.ATTRIBUTE_SELECTION_STATE,
                SEQUENCE,
                new InitSearchRequestAttributeDescList(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from final to AND filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     and             [0] SET OF Filter,
        //     ...
        //
        // Init AND filter
        super.transitions[LdapStatesEnum.FINAL_STATE.ordinal()][LdapCodecConstants.AND_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.FINAL_STATE,
                LdapStatesEnum.AND_STATE,
                LdapCodecConstants.AND_FILTER_TAG,
                new InitAndFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from final to OR filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     or              [1] SET OF Filter,
        //     ...
        //
        // Init OR filter
        super.transitions[LdapStatesEnum.FINAL_STATE.ordinal()][LdapCodecConstants.OR_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.FINAL_STATE,
                LdapStatesEnum.OR_STATE,
                LdapCodecConstants.OR_FILTER_TAG,
                new InitOrFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from final to NOT filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     not             [2] SET OF Filter,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.FINAL_STATE.ordinal()][LdapCodecConstants.NOT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.FINAL_STATE,
                LdapStatesEnum.NOT_STATE,
                LdapCodecConstants.NOT_FILTER_TAG,
                new InitNotFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from final to Equality Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch   [3] AttributeValueAssertion,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.FINAL_STATE.ordinal()][LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.FINAL_STATE,
                LdapStatesEnum.EQUALITY_MATCH_STATE,
                LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG,
                new InitEqualityMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from final to Substrings filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     substrings     [4] SubstringFilter,
        //     ...
        //
        // Init Substrings filter
        super.transitions[LdapStatesEnum.FINAL_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.FINAL_STATE,
                LdapStatesEnum.SUBSTRINGS_FILTER_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_TAG,
                new InitSubstringsFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from final to GreaterOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     greaterOrEqual  [5] AttributeValueAssertion,
        //     ...
        //
        // Init Greater Or Equal filter
        super.transitions[LdapStatesEnum.FINAL_STATE.ordinal()][LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.FINAL_STATE,
                LdapStatesEnum.GREATER_OR_EQUAL_STATE,
                LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG,
                new InitGreaterOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from final to LessOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     LessOrEqual    [6] AttributeValueAssertion,
        //     ...
        //
        // Init Less Or Equal filter
        super.transitions[LdapStatesEnum.FINAL_STATE.ordinal()][LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.FINAL_STATE,
                LdapStatesEnum.LESS_OR_EQUAL_STATE,
                LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG,
                new InitLessOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from final to Present filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     present        [7] AttributeDescription,
        //     ...
        //
        // Init present filter
        super.transitions[LdapStatesEnum.FINAL_STATE.ordinal()][LdapCodecConstants.PRESENT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.FINAL_STATE,
                LdapStatesEnum.PRESENT_STATE,
                LdapCodecConstants.PRESENT_FILTER_TAG,
                new InitPresentFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from final to Approx Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     approxMatch     [8] AttributeValueAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.FINAL_STATE.ordinal()][LdapCodecConstants.APPROX_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.FINAL_STATE,
                LdapStatesEnum.APPROX_MATCH_STATE,
                LdapCodecConstants.APPROX_MATCH_FILTER_TAG,
                new InitApproxMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from final to Extensible Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion,
        //     ...
        //
        // Init Assertion Value Filter filter
        super.transitions[LdapStatesEnum.FINAL_STATE.ordinal()][LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.FINAL_STATE,
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG,
                new InitExtensibleMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Present Filter to AND filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     and             [0] SET OF Filter,
        //     ...
        //
        // Init AND filter
        super.transitions[LdapStatesEnum.PRESENT_STATE.ordinal()][LdapCodecConstants.AND_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.PRESENT_STATE,
                LdapStatesEnum.AND_STATE,
                LdapCodecConstants.AND_FILTER_TAG,
                new InitAndFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from Present Filter to OR filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     or              [1] SET OF Filter,
        //     ...
        //
        // Init OR filter
        super.transitions[LdapStatesEnum.PRESENT_STATE.ordinal()][LdapCodecConstants.OR_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.PRESENT_STATE,
                LdapStatesEnum.OR_STATE,
                LdapCodecConstants.OR_FILTER_TAG,
                new InitOrFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from Present Filter to NOT filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     not             [2] SET OF Filter,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.PRESENT_STATE.ordinal()][LdapCodecConstants.NOT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.PRESENT_STATE,
                LdapStatesEnum.NOT_STATE,
                LdapCodecConstants.NOT_FILTER_TAG,
                new InitNotFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from Present Filter to Equality Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch   [3] AttributeValueAssertion,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.PRESENT_STATE.ordinal()][LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.PRESENT_STATE,
                LdapStatesEnum.EQUALITY_MATCH_STATE,
                LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG,
                new InitEqualityMatchFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from Present Filter to Substrings filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     substrings     [4] SubstringFilter,
        //     ...
        //
        // Init Substrings filter
        super.transitions[LdapStatesEnum.PRESENT_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.PRESENT_STATE,
                LdapStatesEnum.SUBSTRINGS_FILTER_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_TAG,
                new InitSubstringsFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from Present Filter to GreaterOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     greaterOrEqual  [5] AttributeValueAssertion,
        //     ...
        //
        // Init Greater Or Equal filter
        super.transitions[LdapStatesEnum.PRESENT_STATE.ordinal()][LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.PRESENT_STATE,
                LdapStatesEnum.GREATER_OR_EQUAL_STATE,
                LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG,
                new InitGreaterOrEqualFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from Present Filter to LessOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     LessOrEqual    [6] AttributeValueAssertion,
        //     ...
        //
        // Init Less Or Equal filter
        super.transitions[LdapStatesEnum.PRESENT_STATE.ordinal()][LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.PRESENT_STATE,
                LdapStatesEnum.LESS_OR_EQUAL_STATE,
                LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG,
                new InitLessOrEqualFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from Present Filter to Present filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     present        [7] AttributeDescription,
        //     ...
        //
        // Init present filter
        super.transitions[LdapStatesEnum.PRESENT_STATE.ordinal()][LdapCodecConstants.PRESENT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.PRESENT_STATE,
                LdapStatesEnum.PRESENT_STATE,
                LdapCodecConstants.PRESENT_FILTER_TAG,
                new InitPresentFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from Present Filter to Approx Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     approxMatch     [8] AttributeValueAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.PRESENT_STATE.ordinal()][LdapCodecConstants.APPROX_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.PRESENT_STATE,
                LdapStatesEnum.APPROX_MATCH_STATE,
                LdapCodecConstants.APPROX_MATCH_FILTER_TAG,
                new InitApproxMatchFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from Present Filter to Extensible Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion,
        //     ...
        //
        // Init Assertion Value Filter filter
        super.transitions[LdapStatesEnum.PRESENT_STATE.ordinal()][LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.PRESENT_STATE,
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG,
                new InitExtensibleMatchFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from Present Filter to Attribute Description List
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter      Filter,
        //     attributes  AttributeDescriptionList }
        //
        // AttributeDescriptionList ::= SEQUENCE OF
        //     AttributeDescription
        //
        // Init attribute description list
        super.transitions[LdapStatesEnum.PRESENT_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.PRESENT_STATE,
                LdapStatesEnum.ATTRIBUTE_SELECTION_STATE,
                SEQUENCE,
                new InitSearchRequestAttributeDescList(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from Approx Match to Attribute Desc Filter
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     approxMatch  [8] AttributeValueAssertion,
        //     ...
        //
        // AttributeValueAssertion ::= SEQUENCE {
        //     attributeDesc   AttributeDescription,
        //     ...
        //
        // Init Attribute Desc filter
        super.transitions[LdapStatesEnum.APPROX_MATCH_STATE.ordinal()][OCTET_STRING.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.APPROX_MATCH_STATE,
                LdapStatesEnum.ATTRIBUTE_DESC_FILTER_STATE,
                OCTET_STRING,
                new InitAttributeDescFilter(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Extensible Match to MatchingRule
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion }
        //
        // MatchingRuleAssertion ::= SEQUENCE {
        //     matchingRule [1] MatchingRuleId OPTIONAL,
        //     ...
        //
        // Store the matching rule ID
        super.transitions[LdapStatesEnum.EXTENSIBLE_MATCH_STATE.ordinal()][LdapCodecConstants.MATCHING_RULE_ID_TAG] = new GrammarTransition(
            LdapStatesEnum.EXTENSIBLE_MATCH_STATE, 
            LdapStatesEnum.MRA_MATCHING_RULE_STATE,
            LdapCodecConstants.MATCHING_RULE_ID_TAG, 
            new StoreMatchingRuleId(),
            FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Extensible Match to type matching rule
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion }
        //
        // MatchingRuleAssertion ::= SEQUENCE {
        //     ...
        //     type [2] AttributeDescription OPTIONAL,
        //     ...
        //
        // Store the matching rule ID
        super.transitions[LdapStatesEnum.EXTENSIBLE_MATCH_STATE.ordinal()][LdapCodecConstants.MATCHING_RULE_TYPE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapStatesEnum.MRA_TYPE_STATE,
                LdapCodecConstants.MATCHING_RULE_TYPE_TAG,
                new StoreMatchingRuleType(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from Extensible Match to match value
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion }
        //
        // MatchingRuleAssertion ::= SEQUENCE {
        //     ...
        //     matchValue [3] AssertionValue,
        //     ...
        //
        // Store the match value
        super.transitions[LdapStatesEnum.EXTENSIBLE_MATCH_STATE.ordinal()][LdapCodecConstants.MATCH_VALUE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapCodecConstants.MATCH_VALUE_TAG,
                new StoreMatchValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from matching rule ID to matching rule Type
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion }
        //
        // MatchingRuleAssertion ::= SEQUENCE {
        //     matchingRule    [1] MatchingRuleId OPTIONAL,
        //     type            [2] AttributeDescription OPTIONAL,
        //     ...
        //
        // Store the matching rule ID
        super.transitions[LdapStatesEnum.MRA_MATCHING_RULE_STATE.ordinal()][LdapCodecConstants.MATCHING_RULE_TYPE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCHING_RULE_STATE,
                LdapStatesEnum.MRA_TYPE_STATE,
                LdapCodecConstants.MATCHING_RULE_TYPE_TAG,
                new StoreMatchingRuleType(),
                FollowUp.MANDATORY );

        // --------------------------------------------------------------------------------------------
        // Transition from matching rule type to matching rule value
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion }
        //
        // MatchingRuleAssertion ::= SEQUENCE {
        //     ...
        //     type            [2] AttributeDescription OPTIONAL,
        //     matchValue      [3] AssertionValue,
        //     ...
        //
        // Store the matching rule ID
        super.transitions[LdapStatesEnum.MRA_TYPE_STATE.ordinal()][LdapCodecConstants.MATCH_VALUE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_TYPE_STATE,
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapCodecConstants.MATCH_VALUE_TAG,
                new StoreMatchValue(),
                FollowUp.MANDATORY );
        
        // --------------------------------------------------------------------------------------------
        // Transition from matching rule to match value
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion }
        //
        // MatchingRuleAssertion ::= SEQUENCE {
        //     ...
        //     matchValue [3] AssertionValue,
        //     ...
        //
        // Store the matching value
        super.transitions[LdapStatesEnum.MRA_MATCHING_RULE_STATE.ordinal()][LdapCodecConstants.MATCH_VALUE_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCHING_RULE_STATE,
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapCodecConstants.MATCH_VALUE_TAG,
                new StoreMatchValue(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from match value to dnAttributes
        // --------------------------------------------------------------------------------------------
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion }
        //
        // MatchingRuleAssertion ::= SEQUENCE {
        //     ...
        //     dnAttributes [4] BOOLEAN DEFAULT FALSE }
        //
        // Store the dnAttributes flag
        super.transitions[LdapStatesEnum.MRA_MATCH_VALUE_STATE.ordinal()][LdapCodecConstants.DN_ATTRIBUTES_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE,
                LdapCodecConstants.DN_ATTRIBUTES_FILTER_TAG,
                new StoreMatchingRuleDnAttributes(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from match value to AND filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     and             [0] SET OF Filter,
        //     ...
        //
        // Init AND filter
        super.transitions[LdapStatesEnum.MRA_MATCH_VALUE_STATE.ordinal()][LdapCodecConstants.AND_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapStatesEnum.AND_STATE,
                LdapCodecConstants.AND_FILTER_TAG,
                new InitAndFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from match value to OR filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     or              [1] SET OF Filter,
        //     ...
        //
        // Init OR filter
        super.transitions[LdapStatesEnum.MRA_MATCH_VALUE_STATE.ordinal()][LdapCodecConstants.OR_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapStatesEnum.OR_STATE,
                LdapCodecConstants.OR_FILTER_TAG,
                new InitOrFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from match value to NOT filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     not             [2] SET OF Filter,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.MRA_MATCH_VALUE_STATE.ordinal()][LdapCodecConstants.NOT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapStatesEnum.NOT_STATE,
                LdapCodecConstants.NOT_FILTER_TAG,
                new InitNotFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from match value to Equality Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch   [3] AttributeValueAssertion,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.MRA_MATCH_VALUE_STATE.ordinal()][LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapStatesEnum.EQUALITY_MATCH_STATE,
                LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG,
                new InitEqualityMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from match value to Substrings filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     substrings     [4] SubstringFilter,
        //     ...
        //
        // Init Substrings filter
        super.transitions[LdapStatesEnum.MRA_MATCH_VALUE_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapStatesEnum.SUBSTRINGS_FILTER_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_TAG,
                new InitSubstringsFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from match value to GreaterOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     greaterOrEqual  [5] AttributeValueAssertion,
        //     ...
        //
        // Init Greater Or Equal filter
        super.transitions[LdapStatesEnum.MRA_MATCH_VALUE_STATE.ordinal()][LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapStatesEnum.GREATER_OR_EQUAL_STATE,
                LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG,
                new InitGreaterOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from match value to LessOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     LessOrEqual    [6] AttributeValueAssertion,
        //     ...
        //
        // Init Less Or Equal filter
        super.transitions[LdapStatesEnum.MRA_MATCH_VALUE_STATE.ordinal()][LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapStatesEnum.LESS_OR_EQUAL_STATE,
                LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG,
                new InitLessOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from match value to Present filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     present        [7] AttributeDescription,
        //     ...
        //
        // Init present filter
        super.transitions[LdapStatesEnum.MRA_MATCH_VALUE_STATE.ordinal()][LdapCodecConstants.PRESENT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapStatesEnum.PRESENT_STATE,
                LdapCodecConstants.PRESENT_FILTER_TAG,
                new InitPresentFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from match value to Approx Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     approxMatch     [8] AttributeValueAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.MRA_MATCH_VALUE_STATE.ordinal()][LdapCodecConstants.APPROX_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapStatesEnum.APPROX_MATCH_STATE,
                LdapCodecConstants.APPROX_MATCH_FILTER_TAG,
                new InitApproxMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from match value to Extensible Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion,
        //     ...
        //
        // Init Assertion Value Filter filter
        super.transitions[LdapStatesEnum.MRA_MATCH_VALUE_STATE.ordinal()][LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG,
                new InitExtensibleMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from match value to Attribute Selection
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter      Filter,
        //     attributes  AttributeSelection }
        //
        // AttributeDescriptionList ::= SEQUENCE OF selector LDAPSTRING
        //
        // Init attribute description list
        super.transitions[LdapStatesEnum.MRA_MATCH_VALUE_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.MRA_MATCH_VALUE_STATE,
                LdapStatesEnum.ATTRIBUTE_SELECTION_STATE,
                SEQUENCE,
                new InitSearchRequestAttributeDescList(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from dnAttributes to AND filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     and             [0] SET OF Filter,
        //     ...
        //
        // Init AND filter
        super.transitions[LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE.ordinal()][LdapCodecConstants.AND_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE,
                LdapStatesEnum.AND_STATE,
                LdapCodecConstants.AND_FILTER_TAG,
                new InitAndFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from dnAttributes to OR filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     or              [1] SET OF Filter,
        //     ...
        //
        // Init OR filter
        super.transitions[LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE.ordinal()][LdapCodecConstants.OR_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE,
                LdapStatesEnum.OR_STATE,
                LdapCodecConstants.OR_FILTER_TAG,
                new InitOrFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from dnAttributes to NOT filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     not             [2] SET OF Filter,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE.ordinal()][LdapCodecConstants.NOT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE,
                LdapStatesEnum.NOT_STATE,
                LdapCodecConstants.NOT_FILTER_TAG,
                new InitNotFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from dnAttributes to Equality Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     equalityMatch   [3] AttributeValueAssertion,
        //     ...
        //
        // Init NOT filter
        super.transitions[LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE.ordinal()][LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE,
                LdapStatesEnum.EQUALITY_MATCH_STATE,
                LdapCodecConstants.EQUALITY_MATCH_FILTER_TAG,
                new InitEqualityMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from dnAttributes to Substrings filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     substrings     [4] SubstringFilter,
        //     ...
        //
        // Init Substrings filter
        super.transitions[LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE.ordinal()][LdapCodecConstants.SUBSTRINGS_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE,
                LdapStatesEnum.SUBSTRINGS_FILTER_STATE,
                LdapCodecConstants.SUBSTRINGS_FILTER_TAG,
                new InitSubstringsFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from dnAttributes to GreaterOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     greaterOrEqual  [5] AttributeValueAssertion,
        //     ...
        //
        // Init Greater Or Equal filter
        super.transitions[LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE.ordinal()][LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE,
                LdapStatesEnum.GREATER_OR_EQUAL_STATE,
                LdapCodecConstants.GREATER_OR_EQUAL_FILTER_TAG,
                new InitGreaterOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from dnAttributes to LessOrEqual filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     LessOrEqual    [6] AttributeValueAssertion,
        //     ...
        //
        // Init Less Or Equal filter
        super.transitions[LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE.ordinal()][LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE,
                LdapStatesEnum.LESS_OR_EQUAL_STATE,
                LdapCodecConstants.LESS_OR_EQUAL_FILTER_TAG,
                new InitLessOrEqualFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from dnAttributes to Present filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     present        [7] AttributeDescription,
        //     ...
        //
        // Init present filter
        super.transitions[LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE.ordinal()][LdapCodecConstants.PRESENT_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE,
                LdapStatesEnum.PRESENT_STATE,
                LdapCodecConstants.PRESENT_FILTER_TAG,
                new InitPresentFilter(),
                FollowUp.OPTIONAL  );

        // --------------------------------------------------------------------------------------------
        // Transition from dnAttributes to Approx Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     approxMatch     [8] AttributeValueAssertion,
        //     ...
        //
        // Init Approx Match filter
        super.transitions[LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE.ordinal()][LdapCodecConstants.APPROX_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE,
                LdapStatesEnum.APPROX_MATCH_STATE,
                LdapCodecConstants.APPROX_MATCH_FILTER_TAG,
                new InitApproxMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from dnAttributes to Extensible Match filter
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter Filter,
        //     ...
        //
        // Filter ::= CHOICE {
        //     ...
        //     extensibleMatch  [9] MatchingRuleAssertion,
        //     ...
        //
        // Init Assertion Value Filter filter
        super.transitions[LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE.ordinal()][LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG] =
            new GrammarTransition(
                LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE,
                LdapStatesEnum.EXTENSIBLE_MATCH_STATE,
                LdapCodecConstants.EXTENSIBLE_MATCH_FILTER_TAG,
                new InitExtensibleMatchFilter(),
                FollowUp.OPTIONAL );

        // --------------------------------------------------------------------------------------------
        // Transition from dnAttributes to Attribute Description List
        // --------------------------------------------------------------------------------------------
        // SearchRequest ::= [APPLICATION 3] SEQUENCE {
        //     ...
        //     filter      Filter,
        //     attributes  AttributeDescriptionList }
        //
        // AttributeDescriptionList ::= SEQUENCE OF
        //     AttributeDescription
        //
        // Init attribute description list
        super.transitions[LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE.ordinal()][SEQUENCE.getValue()] =
            new GrammarTransition(
                LdapStatesEnum.MRA_DN_ATTRIBUTES_STATE,
                LdapStatesEnum.ATTRIBUTE_SELECTION_STATE,
                SEQUENCE,
                new InitSearchRequestAttributeDescList(),
                FollowUp.OPTIONAL );
    }


    /**
     * Get the instance of this grammar
     *
     * @return An instance on the LdapMessage Grammar
     */
    @SuppressWarnings("rawtypes")
    public static Grammar getInstance()
    {
        return instance;
    }
}
