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


/**
 * An enumeration to store the tags used to encode and decode the syncInfoValue control.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum SyncInfoValueTags
{
    /** A new cookie */
    NEW_COOKIE_TAG(0x0080),
    
    /** Refresh delete phase */
    REFRESH_DELETE_TAG(0x00A1),
    
    /** Refresh present phase */
    REFRESH_PRESENT_TAG(0x00A2),
    
    /** Sync ID set */
    SYNC_ID_SET_TAG(0x00A3);

    /** Internal value for each tag */
    private int value;


    /**
     * Create the private instance
     * @param value The internal tag value
     */
    SyncInfoValueTags( int value )
    {
        this.value = value;
    }


    /**
     * @return The ASN.1 BER value for this tag.
     */
    public int getValue()
    {
        return value;
    }
}
