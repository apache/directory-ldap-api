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

package org.apache.directory.api.ldap.extras.controls.vlv;


/**
 * Enumeration of the result codes of a Virtual List View response control as specified in draft-ietf-ldapext-ldapv3-vlv-09.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum VirtualListViewResultCode
{
    SUCCESS(0, "Success"),

    OPERATIONSERROR(1, "Server internal failure"),

    TIMELIMITEXCEEDED(3, "Timelimit exceeded"),

    ADMINLIMITEXCEEDED(11, "Admin limit exceeded"),

    INAPPROPRIATEMATCHING(18, "Unrecognized or inappropriate matching rule"),

    INSUFFICIENTACCESSRIGHTS(50, "Insufficient access rights"),

    UNWILLINGTOPERFORM(53, "Unwilling to perform"),

    SORTCONTROLMISSING(60, "Sort control missing"),

    OFFSETRANGEERROR(61, "Offset range error"),

    OTHER(80, "Other");

    private int val;
    private String desc;


    private VirtualListViewResultCode( int val, String desc )
    {
        this.val = val;
        this.desc = desc;
    }


    public int getVal()
    {
        return val;
    }


    /**
     * returns the enum value representing the given code.
     * 
     * @param code the result code
     * @return returns the corresponding ResultCode, throws IllegalArgumentException when there
     *         is no matching ResultCode exists for the given value.
     */
    public static VirtualListViewResultCode get( int code )
    {
        switch ( code )
        {
            case 0:
                return SUCCESS;

            case 1:
                return OPERATIONSERROR;

            case 3:
                return TIMELIMITEXCEEDED;

            case 11:
                return ADMINLIMITEXCEEDED;

            case 18:
                return INAPPROPRIATEMATCHING;

            case 50:
                return INSUFFICIENTACCESSRIGHTS;

            case 53:
                return UNWILLINGTOPERFORM;

            case 60:
                return SORTCONTROLMISSING;

            case 61:
                return OFFSETRANGEERROR;

            case 80:
                return OTHER;

            default:
                throw new IllegalArgumentException( "Unknown VLV response result code " + code );
        }
    }
}
