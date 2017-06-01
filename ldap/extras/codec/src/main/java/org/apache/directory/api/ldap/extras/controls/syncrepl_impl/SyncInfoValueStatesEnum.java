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
package org.apache.directory.api.ldap.extras.controls.syncrepl_impl;


import org.apache.directory.api.asn1.ber.grammar.States;


/**
 * This class store the SyncInfoValueControl's grammar constants. It is also used for
 * debugging purposes.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum SyncInfoValueStatesEnum implements States
{
    // ~ Static fields/initializers
    // -----------------------------------------------------------------

    /** The END_STATE */
    END_STATE,

    // =========================================================================
    // SyncRequestValue control grammar states
    // =========================================================================
    /** Initial state */
    START_STATE,

    /** NewCookie state */
    NEW_COOKIE_STATE,

    /** RefreshDelete state */
    REFRESH_DELETE_STATE,

    /** RefreshDelete cookie state */
    REFRESH_DELETE_COOKIE_STATE,

    /** RefreshDelete refreshDone state */
    REFRESH_DELETE_REFRESH_DONE_STATE,

    /** RefreshPresent state */
    REFRESH_PRESENT_STATE,

    /** RefreshPresent cookie state */
    REFRESH_PRESENT_COOKIE_STATE,

    /** RefreshPresent refreshDone state */
    REFRESH_PRESENT_REFRESH_DONE_STATE,

    /** SyncIdSet state */
    SYNC_ID_SET_STATE,

    /** SyncIdSet cookie state */
    SYNC_ID_SET_COOKIE_STATE,

    /** SyncIdSet refreshDone state */
    SYNC_ID_SET_REFRESH_DELETES_STATE,

    /** SyncIdSet SET OF UUIDs state */
    SYNC_ID_SET_SET_OF_UUIDS_STATE,

    /** SyncIdSet UUID state */
    SYNC_ID_SET_UUID_STATE,

    /** terminal state */
    LAST_SYNC_INFO_VALUE_STATE;

    /**
     * Get the grammar name
     * 
     * @return The grammar name
     */
    public String getGrammarName()
    {
        return "SYNC_INFO_VALUE_GRAMMAR";
    }


    /**
     * Get the string representing the state
     * 
     * @param state The state number
     * @return The String representing the state
     */
    public String getState( int state )
    {
        return ( state == END_STATE.ordinal() ) ? "SYNC_INFO_VALUE_END_STATE" : this.name();
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
    public SyncInfoValueStatesEnum getStartState()
    {
        return START_STATE;
    }
}
