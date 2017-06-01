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

package org.apache.directory.api.ldap.extras.controls.vlv_impl;


import org.apache.directory.api.asn1.ber.grammar.States;


/**
 * This class store the VirtualListViewRequest grammar constants. It is also used for
 * debugging purposes.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum VirtualListViewRequestStates implements States
{
    /** Initial state */
    START_STATE,
    
    /** VirtualListViewRequest ::= SEQUENCE  transition */
    VLV_SEQUENCE_STATE,
    
    /** beforeCount    INTEGER (0..maxInt) transition */
    VLV_BEFORE_COUNT_STATE,
    
    /** afterCount     INTEGER (0..maxInt) transition */
    VLV_AFTER_COUNT_STATE,
    
    /** byOffset        [0] SEQUENCE transition */
    VLV_TARGET_BY_OFFSET_STATE,
    
    /** offset          INTEGER (1 .. maxInt) transition */
    VLV_OFFSET_STATE,
    
    /** contentCount    INTEGER (0 .. maxInt) transition */
    VLV_CONTENT_COUNT_STATE,
    
    /** contextID     OCTET STRING OPTIONAL transition */
    VLV_CONTEXT_ID_STATE,
    
    /** greaterThanOrEqual [1] AssertionValue  transition */
    VLV_ASSERTION_VALUE_STATE,
    
    /** Final state */
    END_STATE;

    /**
     * Get the grammar name
     * 
     * @return The grammar name
     */
    public String getGrammarName()
    {
        return "VLV_REQUEST_GRAMMAR";
    }


    /**
     * Get the string representing the state
     * 
     * @param state The state number
     * @return The String representing the state
     */
    public String getState( int state )
    {
        return ( state == END_STATE.ordinal() ) ? "VLV_REQUEST_END_STATE" : name();
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
