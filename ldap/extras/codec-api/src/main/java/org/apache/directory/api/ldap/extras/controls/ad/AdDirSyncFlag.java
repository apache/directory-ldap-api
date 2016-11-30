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

import java.util.EnumSet;
import java.util.Set;

/**
 * The flags used in the AdDirSync response.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum AdDirSyncFlag
{
    /** The Object Security flag */
    LDAP_DIRSYNC_OBJECT_SECURITY( 0x0001, "Object Security" ),

    /** The Ancestors First Order flag */
    LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER( 0x0800, "Ancestors First Order" ),
    
    /** The Public Data Only flag */
    LDAP_DIRSYNC_PUBLIC_DATA_ONLY( 0x2000, "Public Data Only" ),
    
    /** The Incremental Values flag */
    LDAP_DIRSYNC_INCREMENTAL_VALUES( 0x80000000, "Incremental Values" );

    /** The int value */
    private int value;

    /** The string description **/
    private String description;

    /** A private constructor that associates a value and description to each flag */
    AdDirSyncFlag( int value, String description )
    {
        this.value = value;
        this.description = description;
    }


    /**
     * @return The associated value of a given flag
     */
    public int getValue()
    {
        return value;
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        return this.description;
    }


    /**
     * Get back the combination of flags associated with a given value
     * @param value The integer value
     * @return a set of all flags associated with the integer value
     */
    public static Set<AdDirSyncFlag> getFlags( int value )
    {
        EnumSet<AdDirSyncFlag> result = EnumSet.noneOf( AdDirSyncFlag.class );
        for ( AdDirSyncFlag flag : EnumSet.allOf( AdDirSyncFlag.class ) )
        {
            if ( ( flag.getValue() & value ) == flag.getValue() )
            {
                result.add( flag );
            }
        }
        return result;
    }

    /**
     * Get back the bitmask (as an integer) associated with the given flags
     * @param flags The AdDirSync flags
     * @return a bitmask in integer form associated with the set of flags
     */
    public static int getBitmask( Set<AdDirSyncFlag> flags )
    {
        int mask = 0;
        
        for ( AdDirSyncFlag flag : flags )
        {
            mask += flag.getValue();
        }
        
        return mask;
    }
}
