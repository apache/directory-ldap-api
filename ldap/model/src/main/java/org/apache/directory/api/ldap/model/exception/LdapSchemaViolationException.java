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
package org.apache.directory.api.ldap.model.exception;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;


/**
 * Makes a {@link LdapOperationException} unambiguous with respect to the result code
 * it corresponds to by associating an LDAP specific result code with it.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapSchemaViolationException extends LdapOperationException
{
    /** Declares the Serial Version Uid */
    static final long serialVersionUID = 1L;

    /**
     * Creates a new instance of LdapSchemaViolationException.
     *
     * @param resultCode the ResultCodeEnum for this exception
     * @param message The exception message
     */
    public LdapSchemaViolationException( ResultCodeEnum resultCode, String message )
    {
        super( message );
        checkResultCode( resultCode );
        this.resultCode = resultCode;
    }


    /**
     *
     * @param resultCode the ResultCodeEnum for this exception
     * @param message The exception message
     * @param cause The root cause for this exception
     */
    public LdapSchemaViolationException( ResultCodeEnum resultCode, String message, Throwable cause )
    {
        super( message, cause );
        checkResultCode( resultCode );
        this.resultCode = resultCode;
    }


    /**
     * Creates a new instance of LdapSchemaViolationException.
     * 
     * @param resultCode the ResultCodeEnum for this exception
     */
    public LdapSchemaViolationException( ResultCodeEnum resultCode )
    {
        super( null );
        checkResultCode( resultCode );
        this.resultCode = resultCode;
    }


    /**
     * Checks to make sure the resultCode value is right for this exception
     * type.
     * 
     * @param resultCode the code to check
     * @throws IllegalArgumentException
     *             if the result code is not one of
     *             {@link ResultCodeEnum#OBJECT_CLASS_VIOLATION},
     *             {@link ResultCodeEnum#NOT_ALLOWED_ON_RDN}.
     *             {@link org.apache.directory.api.ldap.model.message.ResultCodeEnum#OBJECT_CLASS_MODS_PROHIBITED}.
     */
    private void checkResultCode( ResultCodeEnum resultCode )
    {
        switch ( resultCode )
        {
            case OBJECT_CLASS_VIOLATION:
            case NOT_ALLOWED_ON_RDN:
            case OBJECT_CLASS_MODS_PROHIBITED:
            case INVALID_ATTRIBUTE_SYNTAX: // may happen during schema processing
                return;

            default:
                throw new IllegalArgumentException( I18n.err( I18n.ERR_13027_UNACCEPTABLE_RESULT_CODE, resultCode ) );
        }
    }
}
