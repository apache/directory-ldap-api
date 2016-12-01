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


import org.apache.directory.api.asn1.ber.grammar.States;


/**
 * Codec states for SortRequestControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum SortRequestStates implements States
{
    /** Initial state */
    START_STATE,

    /** SortKeyList ::= SEQUENCE OF transition */
    SEQUENCE_OF_SEQUENCE_STATE,
    
    /** SortKeyList ::= SEQUENCE OF SEQUENCE transition */
    SORT_KEY_SEQUENCE_STATE,

    /** attributeType   AttributeDescription transition */
    AT_DESC_STATE,

    /** orderingRule    [0] MatchingRuleId OPTIONAL transition */
    ORDER_RULE_STATE,

    /** reverseOrder    [1] BOOLEAN DEFAULT FALSE transition */
    REVERSE_ORDER_STATE,

    /** Final state */
    END_STATE;

    /**
     * Get the grammar name
     * 
     * @return The grammar name
     */
    public String getGrammarName()
    {
        return "SORT_REQUEST_GRAMMAR";
    }


    /**
     * Get the string representing the state
     * 
     * @param state The state number
     * @return The String representing the state
     */
    public String getState( int state )
    {
        return ( state == END_STATE.ordinal() ) ? "SORT_REQUEST_END_STATE" : name();
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
    public Enum<?> getStartState()
    {
        return START_STATE;
    }
}
