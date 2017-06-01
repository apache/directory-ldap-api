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
    /** A success */
    SUCCESS(0, "Success"),

    /** The operation failed dur to some internal error */
    OPERATIONSERROR(1, "Server internal failure"),

    /** teh time limit has been exceeded */
    TIMELIMITEXCEEDED(3, "Timelimit exceeded"),

    /** The admin limit has been exceeded */
    ADMINLIMITEXCEEDED(11, "Admin limit exceeded"),

    /** The matching rule is inappropriate */
    INAPPROPRIATEMATCHING(18, "Unrecognized or inappropriate matching rule"),

    /** The access right are insufficient */
    INSUFFICIENTACCESSRIGHTS(50, "Insufficient access rights"),

    /** Unwilling to perform the operation */
    UNWILLINGTOPERFORM(53, "Unwilling to perform"),

    /** No Sort Control provided */
    SORTCONTROLMISSING(60, "Sort control missing"),

    /** The offset is incorrect */
    OFFSETRANGEERROR(61, "Offset range error"),
    
    /** SS is missing */
    OPENLDAP_SSSMISSING(76, "SSS missing"), // OpenLDAP-specific error code
    
    /** The range is invalid */
    OPENLDAP_RANGEERRROR(77, "Range error"), // OpenLDAP-specific error code

    /** Another error */
    OTHER(80, "Other");

    /** The associated value */
    private int value;
    
    /** The associated description */
    private String desc;


    VirtualListViewResultCode( int value, String desc )
    {
        this.value = value;
        this.desc = desc;
    }


    /**
     * @return The associated integer value
     */
    public int getValue()
    {
        return value;
    }


    /**
     * @return The associated description
     */
    public String getDesc()
    {
        return desc;
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
                
            case 76:
                return OPENLDAP_SSSMISSING;

            case 77:
                return OPENLDAP_RANGEERRROR;

            case 80:
                return OTHER;

            default:
                throw new IllegalArgumentException( "Unknown VLV response result code " + code );
        }
    }
}
