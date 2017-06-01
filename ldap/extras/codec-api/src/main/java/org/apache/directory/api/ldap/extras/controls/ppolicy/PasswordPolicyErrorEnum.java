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

package org.apache.directory.api.ldap.extras.controls.ppolicy;


/**
 *  Constants representing PasswordPolicyErrors as stated in the <a href="http://tools.ietf.org/html/draft-behera-ldap-password-policy-10">draft</a>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum PasswordPolicyErrorEnum
{
    /** The password has expired */
    PASSWORD_EXPIRED(0),
    
    /** The account is locked */
    ACCOUNT_LOCKED(1),
    
    /** */
    CHANGE_AFTER_RESET(2),
    
    /** the password modification is not allowed */
    PASSWORD_MOD_NOT_ALLOWED(3),
    
    /** The ld password must be supplied */
    MUST_SUPPLY_OLD_PASSWORD(4),
    
    /** The password quality is not sufficient */
    INSUFFICIENT_PASSWORD_QUALITY(5),
    
    /** The password is too short */
    PASSWORD_TOO_SHORT(6),
    
    /** The password has been changed too recently to be used */
    PASSWORD_TOO_YOUNG(7),
    
    /** The password is in history */
    PASSWORD_IN_HISTORY(8);

    private int value;


    PasswordPolicyErrorEnum( int value )
    {
        this.value = value;
    }


    /**
     * Get the PasswordPolicyErrorEnum gien its numeric value
     * 
     * @param val The numeric value to retrieve
     * @return The associated PasswordPolicyErrorEnum
     */
    public static PasswordPolicyErrorEnum get( int val )
    {
        switch ( val )
        {
            case 0:
                return PASSWORD_EXPIRED;

            case 1:
                return ACCOUNT_LOCKED;

            case 2:
                return CHANGE_AFTER_RESET;

            case 3:
                return PASSWORD_MOD_NOT_ALLOWED;

            case 4:
                return MUST_SUPPLY_OLD_PASSWORD;

            case 5:
                return INSUFFICIENT_PASSWORD_QUALITY;

            case 6:
                return PASSWORD_TOO_SHORT;

            case 7:
                return PASSWORD_TOO_YOUNG;

            case 8:
                return PASSWORD_IN_HISTORY;

            default:

                throw new IllegalArgumentException( "unknown password policy error value " + val );
        }
    }


    /**
     * @return the PasswordPolicyError interned value
     */
    public int getValue()
    {
        return value;
    }
}
