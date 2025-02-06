/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.extras.controls.syncrepl.syncState;


import org.apache.directory.api.i18n.I18n;


/**
 * 
 * This class describes the four types of states part of the syncStateValue as described in rfc4533.
 * 
 *  state ENUMERATED {
 *            present (0),
 *            add (1),
 *            modify (2),
 *            delete (3),
 *            
 *            #includes the below ApacheDS specific values
 *            moddn(4),
 *   }
 *   
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum SyncStateTypeEnum
{
    /** The entry is present */
    PRESENT(0), 
    
    /** The entry has been added */
    ADD(1), 
    
    /** The entry has been modified */
    MODIFY(2), 
    
    /** The entry has been deleted */
    DELETE(3), 
    
    /** The entry has been renamed */
    MODDN(4);

    /** the internal value */
    private int value;


    /**
     * Private constructor so no other instances can be created other than the
     * public static constants in this class.
     * 
     * @param value the integer value of the enumeration.
     */
    SyncStateTypeEnum( int value )
    {
        this.value = value;
    }


    /**
     * Get the value
     * 
     * @return The value associated with the current element.
     */
    public int getValue()
    {
        return value;
    }


    /**
     * Get the {@link SyncStateTypeEnum} instance from an integer value.
     * 
     * @param value The value we want the enum element from
     * @return The enum element associated with this integer
     */
    public static SyncStateTypeEnum getSyncStateType( int value )
    {
        if ( value == PRESENT.value )
        {
            return PRESENT;
        }
        else if ( value == ADD.value )
        {
            return ADD;
        }
        else if ( value == MODIFY.value )
        {
            return MODIFY;
        }
        else if ( value == DELETE.value )
        {
            return DELETE;
        }
        else if ( value == MODDN.value )
        {
            return MODDN;
        }

        throw new IllegalArgumentException( I18n.err( I18n.ERR_9103_UNKNOWN_SYNC_STATE_TYPE, value ) );
    }

}
