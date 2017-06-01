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
 * A PasswordPolicyResponse.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class PasswordPolicyResponseImpl implements PasswordPolicyResponse
{
    /** time before expiration of the password */
    private int timeBeforeExpiration = -1;

    /** number of remaining grace authentications */
    private int graceAuthNRemaining = -1;

    /** number representing the password policy error */
    private PasswordPolicyErrorEnum ppolicyError;


    /**
     * {@inheritDoc}
     */
    @Override
    public int getTimeBeforeExpiration()
    {
        return timeBeforeExpiration;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTimeBeforeExpiration( int timeBeforeExpiration )
    {
        this.timeBeforeExpiration = timeBeforeExpiration;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getGraceAuthNRemaining()
    {
        return graceAuthNRemaining;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setGraceAuthNRemaining( int graceAuthNRemaining )
    {
        this.graceAuthNRemaining = graceAuthNRemaining;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PasswordPolicyErrorEnum getPasswordPolicyError()
    {
        return ppolicyError;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setPasswordPolicyError( PasswordPolicyErrorEnum ppolicyError )
    {
        this.ppolicyError = ppolicyError;
    }


    @Override
    public String toString()
    {
        return "PasswordPolicyResponse [timeBeforeExpiration=" + timeBeforeExpiration + ", graceAuthNRemaining="
            + graceAuthNRemaining + ", ppolicyError=" + ppolicyError + "]";
    }
}
