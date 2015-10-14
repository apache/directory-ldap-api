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
 * The PasswordPolicy response. It contains information about the error if we
 * had one when injecting a bad password into the server.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public interface PasswordPolicyResponse
{
    /**
     * Returns the time before expiration.  Will return -1 if this warning 
     * was not present in the response.
     * 
     * @return The time before expiration of the password, or -1 if not set
     */
    int getTimeBeforeExpiration();


    /**
     * Set a date of expiration for the password.
     * 
     * @param timeBeforeExpiration The time before the password will expire
     */
    void setTimeBeforeExpiration( int timeBeforeExpiration );


    /**
     * Returns the number of possible attempts on the password before it's 
     * locked.  Will return -1 if this warning was not present in the 
     * response.
     * 
     * @return The number of possible attempts on the password before it's locked
     */
    int getGraceAuthNRemaining();


    /**
     * Sets the number of remaining wrong authentication for this password.
     * 
     * @param graceAuthNRemaining The number of remaining attempts
     */
    void setGraceAuthNRemaining( int graceAuthNRemaining );


    /**
     * Returns the password policy error.
     * 
     * @return The PasswordPolicyErrorEnum representing the error
     */
    PasswordPolicyErrorEnum getPasswordPolicyError();


    /**
     * Sets the PasswordPolicy error.
     * 
     * @param ppolicyError The PasswordPolicyErrorEnum representing the error
     */
    void setPasswordPolicyError( PasswordPolicyErrorEnum ppolicyError );
}