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

package org.apache.directory.api.ldap.extras.controls.ppolicy_impl;


import org.apache.directory.api.asn1.ber.grammar.States;


/**
 * various states used in {@link PasswordPolicyGrammar}.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum PasswordPolicyStates implements States
{
    /** Initial state */
    START_STATE,
    
    /** PasswordPolicyResponseValue ::= SEQUENCE  transition */
    PPOLICY_SEQ_STATE,
    
    /** warning [0] CHOICE transition */
    PPOLICY_WARNING_TAG_STATE,
    
    /** timeBeforeExpiration [0] INTEGER (0 .. maxInt) transition */
    PPOLICY_TIME_BEFORE_EXPIRATION_STATE,
    
    /** graceAuthNsRemaining [1] INTEGER (0 .. maxInt) } OPTIONAL transition */
    PPOLICY_GRACE_AUTHNS_REMAINING_STATE,
    
    /** error   [1] ENUMERATED transition */
    PPOLICY_ERROR_TAG_STATE,

    /** end state */
    END_STATE;


    /**
     * Get the grammar name
     * 
     * @return The grammar name
     */
    public String getGrammarName()
    {
        return "PASSWORD_POLICY_RESPONSE_CONTROL_GRAMMAR";
    }


    /**
     * Get the string representing the state
     * 
     * @param state The state number
     * @return The String representing the state
     */
    public String getState( int state )
    {
        return ( state == END_STATE.ordinal() ) ? "PASSWORD_POLICY_RESPONSE_CONTROL_GRAMMAR" : name();
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
    public PasswordPolicyStates getStartState()
    {
        return START_STATE;
    }
}
