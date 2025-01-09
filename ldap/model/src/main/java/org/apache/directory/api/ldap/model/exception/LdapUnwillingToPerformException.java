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
 * An LDAPException that extends the {@link LdapOperationException}
 * carrying with it the corresponding result codes for this condition.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapUnwillingToPerformException extends LdapOperationException
{
    /** Declares the Serial Version Uid */
    static final long serialVersionUID = 1L;

    /**
     * Creates a new instance of LdapUnwillingToPerformException, with
     * a default ResultCode to UNWILING_TO_PERFORM.
     */
    public LdapUnwillingToPerformException()
    {
        super( ResultCodeEnum.UNWILLING_TO_PERFORM, null );
    }


    /**
     * Creates a new instance of LdapUnwillingToPerformException.
     *
     * @param resultCode the ResultCodeEnum for this exception
     * @param message The exception message
     */
    public LdapUnwillingToPerformException( ResultCodeEnum resultCode, String message )
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
    public LdapUnwillingToPerformException( ResultCodeEnum resultCode, String message, Throwable cause )
    {
        super( message, cause );
        checkResultCode( resultCode );
        this.resultCode = resultCode;
    }


    /**
     * Creates a new instance of LdapUnwillingToPerformException.
     *
     * @param message The exception message
     */
    public LdapUnwillingToPerformException( String message )
    {
        super( ResultCodeEnum.UNWILLING_TO_PERFORM, message );
    }


    /**
     * Creates a new instance of LdapUnwillingToPerformException.
     *
     * @param resultCode the ResultCodeEnum for this exception
     */
    public LdapUnwillingToPerformException( ResultCodeEnum resultCode )
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
     *             {@link ResultCodeEnum#UNWILLING_TO_PERFORM},
     *             {@link ResultCodeEnum#UNAVAILABLE_CRITICAL_EXTENSION}.
     */
    private void checkResultCode( ResultCodeEnum resultCode )
    {
        switch ( resultCode )
        {
            case UNWILLING_TO_PERFORM:
            case UNAVAILABLE_CRITICAL_EXTENSION:
                return;

            default:
                throw new IllegalArgumentException( I18n.err( I18n.ERR_13027_UNACCEPTABLE_RESULT_CODE, resultCode ) );
        }
    }
}
