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

package org.apache.directory.ldap.client.template;


import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicy;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyErrorEnum;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyResponse;


/**
 * The default implementation of {@link PasswordWarning}.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
final class PasswordWarningImpl implements PasswordWarning
{
    private static final long serialVersionUID = -8952246313604352357L;

    private int timeBeforeExpiration = -1;
    private int graceAuthNsRemaining = -1;
    private boolean changeAfterReset = false;


    private PasswordWarningImpl()
    {
    }


    static PasswordWarning newWarning( PasswordPolicy policy )
    {
        PasswordPolicyResponse response = policy.getResponse();
        if ( response != null )
        {
            PasswordWarningImpl policyWarning = new PasswordWarningImpl();
            policyWarning.timeBeforeExpiration = response.getTimeBeforeExpiration();
            policyWarning.graceAuthNsRemaining = response.getGraceAuthNRemaining();
            policyWarning.changeAfterReset = response.getPasswordPolicyError() == PasswordPolicyErrorEnum.CHANGE_AFTER_RESET;

            if ( policyWarning.timeBeforeExpiration >= 0 || policyWarning.graceAuthNsRemaining >= 0
                || policyWarning.changeAfterReset )
            {
                // it actually is a warning!
                return policyWarning;
            }
        }
        return null;
    }


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
    public int getGraceAuthNsRemaining()
    {
        return graceAuthNsRemaining;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isChangeAfterReset()
    {
        return changeAfterReset;
    }
}