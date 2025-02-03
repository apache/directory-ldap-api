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


import org.apache.directory.api.asn1.ber.grammar.States;


/**
 * This class store the Ldap grammar's constants. It is also used for debugging
 * purpose
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum LdapStatesEnum implements States
{
    /** The various states */
    /** AbandonRequest state */
    ABANDON_REQUEST_STATE,

    /** AddRequest state */
    ADD_REQUEST_STATE,

    /** AddResponse state */
    ADD_RESPONSE_STATE,
    
    /** And State */
    AND_STATE,
    
    /** Any State */
    ANY_STATE,

    /** ApproxMatch State */
    APPROX_MATCH_STATE,

    /** Assertion Value State */
    ASSERTION_VALUE_FILTER_STATE,

    /** Assertion Value Compare State */
    ASSERTION_VALUE_COMP_STATE,

    /** Attributes SearchRequest State */
    ATTRIBUTES_SR_STATE,

    /** Attributes State */
    ATTRIBUTES_STATE,

    /** Attribute Selection State */
    ATTRIBUTE_SELECTION_STATE,

    /** Attribute Description State */
    ATTRIBUTE_DESC_COMP_STATE,

    /** Attribute Description Filter State */
    ATTRIBUTE_DESC_FILTER_STATE,

    /** Attribute State */
    ATTRIBUTE_STATE,

    /** Attribute Value State */
    ATTRIBUTE_VALUE_STATE,

    /** AVA Compare State */
    AVA_COMP_STATE,

    /** Base Object State */
    BASE_OBJECT_STATE,
    
    /** BindRequest state */
    BIND_REQUEST_STATE,
    
    /** BindResponse state */
    BIND_RESPONSE_STATE,

    /** Changes State */
    CHANGES_STATE,

    /** Change State */
    CHANGE_STATE,

    /** CompareRequest state */
    COMPARE_REQUEST_STATE,
    
    /** CompareResponse state */
    COMPARE_RESPONSE_STATE,

    /** Controls State */
    CONTROLS_STATE,

    /** Control State */
    CONTROL_STATE,

    /** Control Type State */
    CONTROL_TYPE_STATE,

    /** Control Value State */
    CONTROL_VALUE_STATE,

    /** Credentials State */
    CREDENTIALS_STATE,

    /** Criticality State */
    CRITICALITY_STATE,

    /** Delete Old RDN State */
    DELETE_OLD_RDN_STATE,

    /** DelRequest state */
    DEL_REQUEST_STATE,
    
    /** DelResponse state */
    DEL_RESPONSE_STATE,

    /** Deref Alias State */
    DEREF_ALIAS_STATE,

    /** Diagnostic Message Bind Response State */
    DIAGNOSTIC_MESSAGE_BR_STATE,

    /** Diagnostic Message Extended Response State */
    DIAGNOSTIC_MESSAGE_ER_STATE,

    /** Diagnostic Message State */
    DIAGNOSTIC_MESSAGE_STATE,

    /** End State */
    END_STATE,

    /** Entry Compare State */
    ENTRY_COMP_STATE,

    /** Entry ModDN State */
    ENTRY_MOD_DN_STATE,

    /** Entry State */
    ENTRY_STATE,

    /** Equality Match State */
    EQUALITY_MATCH_STATE,

    /** ExtendedRequest state */
    EXTENDED_REQUEST_STATE,
    
    /** ExtendedResponse state */
    EXTENDED_RESPONSE_STATE,

    /** Extensible Match State */
    EXTENSIBLE_MATCH_STATE,

    /** Final State */
    FINAL_STATE,

    /** Freater or Equal State */
    GREATER_OR_EQUAL_STATE,

    /** Initial State */
    INITIAL_STATE,

    /** IntermediateResponse Name State */
    INTERMEDIATE_RESPONSE_NAME_STATE,

    /** IntermediateResponse  State */
    INTERMEDIATE_RESPONSE_STATE,

    /** IntermediateResponse Value State */
    INTERMEDIATE_RESPONSE_VALUE_STATE,

    /** Ldap Message State */
    LDAP_MESSAGE_STATE,

    /** Less or Equal State */
    LESS_OR_EQUAL_STATE,

    /** Matched DN BindRequest State */
    MATCHED_DN_BR_STATE,

    /** Matched DN ExtendedRequest State */
    MATCHED_DN_ER_STATE,

    /** Matched DN State */
    MATCHED_DN_STATE,

    /** Mechanism State */
    MECHANISM_STATE,

    /** Message ID State */
    MESSAGE_ID_STATE,

    /** Modification State */
    MODIFICATION_STATE,

    /** ModifyDnRequest state */
    MODIFY_DN_REQUEST_STATE,
    
    /** ModifyDnResponse state */
    MODIFY_DN_RESPONSE_STATE,

    /** ModifyRequest state */
    MODIFY_REQUEST_STATE,
    
    /** ModifyResponse state */
    MODIFY_RESPONSE_STATE,

    /** Matching Rule Assertion DN Attributes State */
    MRA_DN_ATTRIBUTES_STATE,

    /** Matching Rule Assertion  Matching Rule State */
    MRA_MATCHING_RULE_STATE,

    /** Matching Rule Assertion Type State */
    MRA_TYPE_STATE,

    /** Matching Rule Assertion Match Value State */
    MRA_MATCH_VALUE_STATE,

    /** Name State */
    NAME_STATE,

    /** New RDN State */
    NEW_RDN_STATE,

    /** New Superior State */
    NEW_SUPERIOR_STATE,

    /** Not State */
    NOT_STATE,

    /** Object NameState */
    OBJECT_NAME_STATE,

    /** Object State */
    OBJECT_STATE,

    /** Operation State */
    OPERATION_STATE,

    /** Or State */
    OR_STATE,

    /** Partial Attributes List State */
    PARTIAL_ATTRIBUTES_LIST_STATE,

    /** Present State */
    PRESENT_STATE,

    /** Reference State */
    REFERENCE_STATE,

    /** Referral Bind Response State */
    REFERRAL_BR_STATE,

    /** Referral Extended ResponseState */
    REFERRAL_ER_STATE,

    /** Referral State */
    REFERRAL_STATE,

    /** Request Name State */
    REQUEST_NAME_STATE,

    /** Request Value State */
    REQUEST_VALUE_STATE,

    /** Respobse Name State */
    RESPONSE_NAME_STATE,

    /** Response Value State */
    RESPONSE_VALUE_STATE,

    /** Result Code BindResponse State */
    RESULT_CODE_BR_STATE,

    /** Result Code ExtendedResponse State */
    RESULT_CODE_ER_STATE,

    /** Result Code State */
    RESULT_CODE_STATE,

    /** SASL State */
    SASL_STATE,

    /** Scope State */
    SCOPE_STATE,

    /** SearchRequest state */
    SEARCH_REQUEST_STATE,
    
    /** SearchResultDone state */
    SEARCH_RESULT_DONE_STATE,

    /** SearchResultEntry state */
    SEARCH_RESULT_ENTRY_STATE,

    /** SearchResultReference state */
    SEARCH_RESULT_REFERENCE_STATE,

    /** Selector State */
    SELECTOR_STATE,

    /** Sasl Credentials State */
    SERVER_SASL_CREDENTIALS_STATE,

    /** Simple State */
    SIMPLE_STATE,

    /** Size Limit State */
    SIZE_LIMIT_STATE,

    /** Starting State */
    START_STATE,

    /** Substrings State */
    SUBSTRINGS_STATE,

    /** Substrings Filter State */
    SUBSTRINGS_FILTER_STATE,

    /** State */
    TIME_LIMIT_STATE,

    /** TypesOnly State */
    TYPES_ONLY_STATE,

    /** Type Modification State */
    TYPE_MOD_STATE,

    /** Type SearchRequest State */
    TYPE_SR_STATE,

    /** Type State */
    TYPE_STATE,

    /** Typ Substring State */
    TYPE_SUBSTRING_STATE,

    /** UnbindRequest state */
    UNBIND_REQUEST_STATE,

    /** URI BindRequest State */
    URI_BR_STATE,

    /** URI_ER State */
    URI_ER_STATE,

    /** URI State */
    URI_STATE,

    /** Vals SearchRequest State */
    VALS_SR_STATE,

    /** Vals State */
    VALS_STATE,

    /** Values State */
    VALUES_STATE,

    /** Value State */
    VALUE_STATE,

    /** Value SearchRequest State */
    VALUE_SR_STATE,
    
    /** Version state */
    VERSION_STATE,
    
    // Keep it here it is used to create the grammar table, using its ordinal
    /** The last state */
    LAST_LDAP_STATE;

    /**
     * Get the grammar name
     *
     * @return The grammar name
     */
    public String getGrammarName()
    {
        return "LDAP_MESSAGE_GRAMMAR";
    }


    /**
     * Get the string representing the state
     *
     * @param state The state number
     * @return The String representing the state
     */
    public String getState( int state )
    {
        return ( state == END_STATE.ordinal() ) ? "LDAP_MESSAGE_END_STATE" : name();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isEndState()
    {
        return this == END_STATE;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapStatesEnum getStartState()
    {
        return START_STATE;
    }
}
