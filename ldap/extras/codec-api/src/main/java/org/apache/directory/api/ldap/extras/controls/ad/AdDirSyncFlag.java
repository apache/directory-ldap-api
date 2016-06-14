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
package org.apache.directory.api.ldap.extras.controls.ad;

/**
 * The flags used in the AdDirSync response.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum AdDirSyncFlag
{
    DEFAULT (0x0000),
    LDAP_DIRSYNC_OBJECT_SECURITY (0x0001),
    LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER (0x0800),
    LDAP_DIRSYNC_PUBLIC_DATA_ONLY (0x2000),
    LDAP_DIRSYNC_INCREMENTAL_VALUES (0x7FFFFFFF);

    /** The interned value */
    private int value;
    
    /** A private constructor that associates a value to each flag */
    private AdDirSyncFlag( int value )
    {
        this.value = value;
    }
    
    
    /**
     * @return The associated value of a given flag
     */
    public int getValue()
    {
        return value;
    }
    
    
    /**
     * Get back the flag associated with a given value
     * @param value The integer value
     * @return The associated flag
     */
    public static AdDirSyncFlag getFlag( int value )
    {
        switch ( value )
        {
            case 0x0000 : return DEFAULT;
            case 0x0001 : return LDAP_DIRSYNC_OBJECT_SECURITY;
            case 0x0800 : return LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER;
            case 0x2000 : return LDAP_DIRSYNC_PUBLIC_DATA_ONLY;
            case 0x7FFFFFFF : return LDAP_DIRSYNC_INCREMENTAL_VALUES;
            default : return null;
        }
    }
}
