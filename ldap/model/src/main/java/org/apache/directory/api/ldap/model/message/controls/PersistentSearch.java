/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.ldap.model.message.controls;


import org.apache.directory.api.ldap.model.message.Control;


/**
 * A persistence search object
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface PersistentSearch extends Control
{
    /** This control OID */
    String OID = "2.16.840.1.113730.3.4.3";

    /** Min and Max values for the possible combined change types */
    int CHANGE_TYPES_MIN = ChangeType.ADD.getValue();

    /** The maximum value for the possible combined changes type */
    int CHANGE_TYPES_MAX = ChangeType.ADD.getValue()
        | ChangeType.DELETE.getValue()
        | ChangeType.MODIFY.getValue()
        | ChangeType.MODDN.getValue();


    /**
     * Sets the ChangesOnly flag
     *   
     * @param changesOnly The ChangesOnly flag
     */
    void setChangesOnly( boolean changesOnly );


    /**
     * @return <TT>TRUE</TT> if the changesOnly flag is set
     */
    boolean isChangesOnly();


    /**
     * Sets the return entry changes flag
     * 
     * @param returnECs the return entry changes flag
     */
    void setReturnECs( boolean returnECs );


    /**
     * @return <TT>TRUE</TT> if the return entry changes flag is set
     */
    boolean isReturnECs();


    /**
     * Set the changeType value we want to get back ( a combinaison of Add, Delete,
     * Modify and ModifyDN)
     *  
     * @param changeTypes The changeType values (Add, Modify, Delete and ModifyDn)
     */
    void setChangeTypes( int changeTypes );


    /**
     * @return The changeTypes value
     */
    int getChangeTypes();


    /**
     * For each changeType, tells if the notification is enabled
     * 
     * @param changeType The ChnageType we are interested in
     * @return <T>TRUE<T> if the notification is set for this ChangeType
     */
    boolean isNotificationEnabled( ChangeType changeType );


    /**
     * Sets the notification for a given changeType 
     * @param changeType The chnageType we want some notification to be set
     */
    void enableNotification( ChangeType changeType );


    /**
     * Unsets the notification for a given changeType 
     * @param changeType The chnageType we want some notification to be unset
     */
    void disableNotification( ChangeType changeType );
}
