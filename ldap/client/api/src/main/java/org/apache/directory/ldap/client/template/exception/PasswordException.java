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
package org.apache.directory.ldap.client.template.exception;


import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyErrorEnum;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;


/**
 * Thrown when an attempt to bind or modify a userPassword fails when using
 * LdapConnectionTemplate.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordException extends Exception
{
    private static final long serialVersionUID = -1185823188085178776L;

    private LdapException ldapException;
    private ResultCodeEnum resultCode;
    private PasswordPolicyErrorEnum passwordPolicyError;


    /**
     * Creates a new PasswordException instance
     */
    public PasswordException()
    {
        super();
    }


    /**
     * If an LdapException was thrown causing this exception, that 
     * LdapException is returned.  Otherwise null is returned.
     *
     * @return The LdapException that was thrown, or null.
     */
    public LdapException getLdapException()
    {
        return ldapException;
    }


    /**
     * Returns the result code from the attempt to bind or modify the 
     * userPassword.
     *
     * @return The result code.
     */
    public ResultCodeEnum getResultCode()
    {
        return resultCode;
    }


    /**
     * Returns the password policy error code if present, otherwise null.
     *
     * @return The password policy error code or null.
     */
    public PasswordPolicyErrorEnum getPasswordPolicyError()
    {
        return passwordPolicyError;
    }


    /**
     * Sets the wrapped exception
     * 
     * @param ldapException The wrapped exception
     * @return The wrapping exception
     */
    public PasswordException setLdapException( LdapException ldapException )
    {
        this.ldapException = ldapException;
        
        return this;
    }


    /**
     * Set the Password Policy error
     * 
     * @param passwordPolicyError The Password Policy error
     * @return The wrapping exception
     */
    public PasswordException setPasswordPolicyError( PasswordPolicyErrorEnum passwordPolicyError )
    {
        this.passwordPolicyError = passwordPolicyError;
        
        return this;
    }


    /**
     * Sets the LDAP Result code
     * 
     * @param resultCode The LDAP error code
     * @return The wrapping exception
     */
    public PasswordException setResultCode( ResultCodeEnum resultCode )
    {
        this.resultCode = resultCode;
        
        return this;
    }
}
