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
 * Enumeration of states encountered while decoding a SortResponseControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum SortResponseStates implements States
{
    /** Initialstate */ 
    START_STATE,

    /** SortResult ::= SEQUENCE transition */
    SEQUENCE_STATE,

    /** sortResult  ENUMERATED transition */
    RESULT_CODE_STATE,
    
    /** attributeType [0] AttributeDescription OPTIONAL transition */
    AT_DESC_STATE,

    /** Final state */
    END_STATE;

    /**
     * Get the grammar name
     * 
     * @return The grammar name
     */
    public String getGrammarName()
    {
        return "SORT_RESPONSE_GRAMMAR";
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


    @Override
    public boolean isEndState()
    {
        return this == END_STATE;
    }


    @Override
    public Enum<?> getStartState()
    {
        return START_STATE;
    }

}
