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

package org.apache.directory.api.ldap.model.password;


import org.apache.directory.api.ldap.model.constants.LdapSecurityConstants;


/**
 * A class to store all informations about an password.
 *
 * This includes:
 * <ul>
 * <li> the used algorithm</li>
 * <li> the salt if any</li>
 * <li> the password itself</li>
 * </ul>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordDetails
{
    private final LdapSecurityConstants algorithm;
    private final byte[] salt;
    private final byte[] password;


    /**
     * Creates a new PasswordDetails instance
     * 
     * @param algorithm The algorithm to use
     * @param salt The Salt to use
     * @param password The password
     */
    public PasswordDetails( LdapSecurityConstants algorithm, byte[] salt, byte[] password )
    {
        this.algorithm = algorithm;
        this.salt = salt;
        this.password = password;
    }


    /**
     * The hash algorithm used to hash the password, null for plain text passwords.
     * 
     * @return the hash algorithm used to hash the password, null for plain text passwords
     */
    public LdapSecurityConstants getAlgorithm()
    {
        return algorithm;
    }


    /**
     * The salt used to hash the password, null if no salt was used.
     * 
     * @return the salt used to hash the password, null if no salt was used
     */
    public byte[] getSalt()
    {
        return salt;
    }


    /**
     * The hashed or plain text password.
     * 
     * @return the hashed or plain text password
     */
    public byte[] getPassword()
    {
        return password;
    }

}
