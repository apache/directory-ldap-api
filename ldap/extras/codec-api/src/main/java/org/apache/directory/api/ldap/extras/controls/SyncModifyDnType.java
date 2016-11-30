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

package org.apache.directory.api.ldap.extras.controls;


/**
 * The type of MODDN modification. One of MOVE, RENAME or MOVE_AND_RENAME
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum SyncModifyDnType
{
    /** A Move operation */
    MOVE(0),
    
    /** A Rename operation */
    RENAME(1),
    
    /** A Move and Rename operation */
    MOVE_AND_RENAME(2);

    /** Internal value for each tag */
    private int value;


    /**
     * Creates the value
     */
    SyncModifyDnType( int value )
    {
        this.value = value;
    }


    /**
     * @return The value associated with the current element.
     */
    public int getValue()
    {
        return value;
    }


    /**
     * Get the instance from it's interger value
     * @param value The value we are looking for 
     * @return The associated value
     */
    public static SyncModifyDnType getModifyDnType( int value )
    {
        switch ( value )
        {
            case 0:
                return MOVE;

            case 1:
                return RENAME;

            case 2:
                return MOVE_AND_RENAME;

            default:
                throw new IllegalArgumentException( "unknown modify dn operantion type " + value );
        }
    }
}
