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
package org.apache.directory.api.ldap.model.message.controls;

/**
 * Enumeration of the result codes of a SortResult defined in <a href="http://tools.ietf.org/html/rfc2891">RFC 2891</a>
 * for server side sort control.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum SortResultCode
{
    SUCCESS( 0, "Results are sorted"),
    
    OPERATIONSERROR( 1, "Server internal failure"),
    
    TIMELIMITEXCEEDED( 3, "Timelimit reached before sorting was completed"),
    
    STRONGAUTHREQUIRED( 8, "Refused to return sorted results via insecure protocol"),
    
    ADMINLIMITEXCEEDED( 11, "Too many matching entries for the server to sort"),
    
    NOSUCHATTRIBUTE( 16, "Unrecognized attribute type in sort key"),
    
    INAPPROPRIATEMATCHING( 18, "Unrecognized or inappropriate matching rule in sort key"),
    
    INSUFFICIENTACCESSRIGHTS( 50, "Refused to return sorted results to this client"),
    
    BUSY( 51, "Too busy to process"),
    
    UNWILLINGTOPERFORM( 53, "Unable to sort"),
    
    OTHER( 80, "Other");
    
    int val;
    String desc;
    
    SortResultCode( int val, String desc )
    {
        this.val = val;
        this.desc = desc;
    }

    /**
     * @return The internet value
     */
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
    public static SortResultCode get( int code )
    {
        switch ( code )
        {
            case 0:
                return SUCCESS;

            case 1:
                return OPERATIONSERROR;

            case 3:
                return TIMELIMITEXCEEDED;
                
            case 8:
                return STRONGAUTHREQUIRED;

            case 11:
                return ADMINLIMITEXCEEDED;
                
            case 16:
                return NOSUCHATTRIBUTE;
                
            case 18:
                return INAPPROPRIATEMATCHING;
                
            case 50:
                return INSUFFICIENTACCESSRIGHTS;
                
            case 51:
                return BUSY;
                
            case 53:
                return UNWILLINGTOPERFORM;
                
            case 80:
                return OTHER;

            default:
                throw new IllegalArgumentException( "Unknown sort response result code " + code );
        }
    }
}
