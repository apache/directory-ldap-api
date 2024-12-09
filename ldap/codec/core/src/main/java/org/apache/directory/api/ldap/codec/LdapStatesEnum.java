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
    /** The END_STATE */
    ABANDON_REQUEST_STATE,
    ADD_REQUEST_STATE,
    ADD_RESPONSE_STATE,
    AND_STATE,
    ANY_STATE,
    APPROX_MATCH_STATE,
    ASSERTION_VALUE_FILTER_STATE,
    ASSERTION_VALUE_COMP_STATE,
    ATTRIBUTES_SR_STATE,
    ATTRIBUTES_STATE,
    //ATTRIBUTE_DESCRIPTION_STATE,
    ATTRIBUTE_SELECTION_STATE,
    ATTRIBUTE_DESC_COMP_STATE,
    ATTRIBUTE_DESC_FILTER_STATE,
    ATTRIBUTE_STATE,
    ATTRIBUTE_VALUE_STATE,
    AVA_COMP_STATE,
    BASE_OBJECT_STATE,
    BIND_REQUEST_STATE,
    BIND_RESPONSE_STATE,
    CHANGES_STATE,
    CHANGE_STATE,
    COMPARE_REQUEST_STATE,
    COMPARE_RESPONSE_STATE,
    CONTROLS_STATE,
    CONTROL_STATE,
    CONTROL_TYPE_STATE,
    CONTROL_VALUE_STATE,
    CREDENTIALS_STATE,
    CRITICALITY_STATE,
    DELETE_OLD_RDN_STATE,
    DEL_REQUEST_STATE,
    DEL_RESPONSE_STATE,
    DEREF_ALIAS_STATE,
    DIAGNOSTIC_MESSAGE_BR_STATE,
    DIAGNOSTIC_MESSAGE_ER_STATE,
    DIAGNOSTIC_MESSAGE_STATE,
    END_STATE,
    ENTRY_COMP_STATE,
    ENTRY_MOD_DN_STATE,
    ENTRY_STATE,
    EQUALITY_MATCH_STATE,
    EXTENDED_REQUEST_STATE,
    EXTENDED_RESPONSE_STATE,
    EXTENSIBLE_MATCH_STATE,
    FINAL_STATE,
    GREATER_OR_EQUAL_STATE,
    INITIAL_STATE,
    INTERMEDIATE_RESPONSE_NAME_STATE,
    INTERMEDIATE_RESPONSE_STATE,
    INTERMEDIATE_RESPONSE_VALUE_STATE,
    LDAP_MESSAGE_STATE,
    LESS_OR_EQUAL_STATE,
    MATCHED_DN_BR_STATE,
    MATCHED_DN_ER_STATE,
    MATCHED_DN_STATE,
    MRA_DN_ATTRIBUTES_STATE,
    MRA_MATCHING_RULE_STATE,
    MRA_TYPE_STATE,
    MRA_MATCH_VALUE_STATE,
    MECHANISM_STATE,
    MESSAGE_ID_STATE,
    MODIFICATION_STATE,
    MODIFY_DN_REQUEST_STATE,
    MODIFY_DN_RESPONSE_STATE,
    MODIFY_REQUEST_STATE,
    MODIFY_RESPONSE_STATE,
    NAME_STATE,
    NEW_RDN_STATE,
    NEW_SUPERIOR_STATE,
    NOT_STATE,
    OBJECT_NAME_STATE,
    OBJECT_STATE,
    OPERATION_STATE,
    OR_STATE,
    PARTIAL_ATTRIBUTES_LIST_STATE,
    PRESENT_STATE,
    REFERENCE_STATE,
    REFERRAL_BR_STATE,
    REFERRAL_ER_STATE,
    REFERRAL_STATE,
    REQUEST_NAME_STATE,
    REQUEST_VALUE_STATE,
    RESPONSE_NAME_STATE,
    RESPONSE_VALUE_STATE,
    RESULT_CODE_BR_STATE,
    RESULT_CODE_ER_STATE,
    RESULT_CODE_STATE,
    SASL_STATE,
    SCOPE_STATE,
    SEARCH_REQUEST_STATE,
    SEARCH_RESULT_DONE_STATE,
    SEARCH_RESULT_ENTRY_STATE,
    SEARCH_RESULT_REFERENCE_STATE,
    SELECTOR_STATE,
    SERVER_SASL_CREDENTIALS_STATE,
    SIMPLE_STATE,
    SIZE_LIMIT_STATE,
    START_STATE,
    SUBSTRINGS_STATE,
    SUBSTRINGS_FILTER_STATE,
    TIME_LIMIT_STATE,
    TYPES_ONLY_STATE,
    TYPE_MOD_STATE,
    TYPE_SR_STATE,
    TYPE_STATE,
    TYPE_SUBSTRING_STATE,
    UNBIND_REQUEST_STATE,
    URI_BR_STATE,
    URI_ER_STATE,
    URI_STATE,
    VALS_SR_STATE,
    VALS_STATE,
    VALUES_STATE,
    VALUE_STATE,
    VALUE_SR_STATE,
    VERSION_STATE,
    
    // Keep it here it is used to create the grammar table, using its ordinal
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
