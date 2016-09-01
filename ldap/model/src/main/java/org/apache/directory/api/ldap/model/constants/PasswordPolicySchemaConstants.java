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

package org.apache.directory.api.ldap.model.constants;


/**
 * The PasswordPolicy schema ObjectClasses and AttributeTypes.
 * Final reference -&gt; class shouldn't be extended
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class PasswordPolicySchemaConstants
{
    /**
     *  Ensures no construction of this class, also ensures there is no need for final keyword above
     *  (Implicit super constructor is not visible for default constructor),
     *  but is still self documenting.
     */
    private PasswordPolicySchemaConstants()
    {
    }

    // ---- ObjectClasses -----------------------------------------------------
    // pwdPolicy
    public static final String PWD_POLICY_OC = "pwdPolicy";
    public static final String PWD_POLICY_OC_OID = "1.3.6.1.4.1.42.2.27.8.2.1";

    // ---- AttributeTypes ----------------------------------------------------
    // pwdAttribute
    public static final String PWD_ATTRIBUTE_AT = "pwdAttribute";
    public static final String PWD_ATTRIBUTE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.1";

    // pwdMinAge
    public static final String PWD_MIN_AGE_AT = "pwdMinAge";
    public static final String PWD_MIN_AGE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.2";

    // pwdMaxAge
    public static final String PWD_MAX_AGE_AT = "pwdMaxAge";
    public static final String PWD_MAX_AGE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.3";

    // pwdLockoutDuration
    public static final String PWD_LOCKOUT_DURATION_AT = "pwdLockoutDuration";
    public static final String PWD_LOCKOUT_DURATION_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.10";

    // pwdInHistory
    public static final String PWD_IN_HISTORY_AT = "pwdInHistory";
    public static final String PWD_IN_HISTORY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.4";

    // pwdCheckQuality
    public static final String PWD_CHECK_QUALITY_AT = "pwdCheckQuality";
    public static final String PWD_CHECK_QUALITY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.5";

    // pwdMinLength
    public static final String PWD_MIN_LENGTH_AT = "pwdMinLength";
    public static final String PWD_MIN_LENGTH_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.6;";

    // pwdExpireWarning
    public static final String PWD_EXPIRE_WARNING_AT = "pwdExpireWarning";
    public static final String PWD_EXPIRE_WARNING_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.7;";

    // pwdGraceAuthNLimit
    public static final String PWD_GRACE_AUTHN_LIMIT_AT = "pwdGraceAuthNLimit";
    public static final String PWD_GRACE_AUTHN_LIMIT_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.;";

    // pwdLockout
    public static final String PWD_LOCKOUT_AT = "pwdLockout";
    public static final String PWD_LOCKOUT_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.9";

    // pwdMaxFailure
    public static final String PWD_MAX_FAILURE_AT = "pwdMaxFailure";
    public static final String PWD_MAX_FAILURE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.11";

    // pwdFailureCountInterval
    public static final String PWD_FAILURE_COUNT_INTERVAL_AT = "pwdFailureCountInterval";
    public static final String PWD_FAILURE_COUNT_INTERVAL_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.12";

    // public static final String PWD_MUST_CHANGE_AT = 
    public static final String PWD_MUST_CHANGE_AT = "pwdMustChange";
    public static final String PWD_MUST_CHANGE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.13";

    // pwdAllowUserChange
    public static final String PWD_ALLOW_USER_CHANGE_AT = "pwdAllowUserChange";
    public static final String PWD_ALLOW_USER_CHANGE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.14";

    // pwdSafeModify
    public static final String PWD_SAFE_MODIFY_AT = "pwdSafeModify";
    public static final String PWD_SAFE_MODIFY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.15";

    // pwdChangedTime
    public static final String PWD_CHANGED_TIME_AT = "pwdChangedTime";
    public static final String PWD_CHANGED_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.16";

    // pwdAccountLockedTime
    public static final String PWD_ACCOUNT_LOCKED_TIME_AT = "pwdAccountLockedTime";
    public static final String PWD_ACCOUNT_LOCKED_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.17";

    // pwdFailureTime
    public static final String PWD_FAILURE_TIME_AT = "pwdFailureTime";
    public static final String PWD_FAILURE_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.19";

    // pwdHistory
    public static final String PWD_HISTORY_AT = "pwdHistory";
    public static final String PWD_HISTORY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.20";

    // pwdGraceUseTime
    public static final String PWD_GRACE_USE_TIME_AT = "pwdGraceUseTime";
    public static final String PWD_GRACE_USE_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.21";

    // pwdReset
    public static final String PWD_RESET_AT = "pwdReset";
    public static final String PWD_RESET_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.22";

    // pwdPolicySubentry
    public static final String PWD_POLICY_SUBENTRY_AT = "pwdPolicySubentry";
    public static final String PWD_POLICY_SUBENTRY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.23";

    // pwdMinDelay
    public static final String PWD_MIN_DELAY_AT = "pwdMinDelay";
    public static final String PWD_MIN_DELAY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.24";

    // pwdMaxDelay
    public static final String PWD_MAX_DELAY_AT = "pwdMaxDelay";
    public static final String PWD_MAX_DELAY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.25";

    // pwdMaxIdle
    public static final String PWD_MAX_IDLE_AT = "pwdMaxIdle";
    public static final String PWD_MAX_IDLE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.26";

    // pwdStartTime
    public static final String PWD_START_TIME_AT = "pwdStartTime";
    public static final String PWD_START_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.27";

    // pwdEndTime
    public static final String PWD_END_TIME_AT = "pwdEndTime";
    public static final String PWD_END_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.28";

    // pwdLastSuccess
    public static final String PWD_LAST_SUCCESS_AT = "pwdLastSuccess";
    public static final String PWD_LAST_SUCCESS_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.29";

    // pwdGraceExpire
    public static final String PWD_GRACE_EXPIRE_AT = "pwdGraceExpire";
    public static final String PWD_GRACE_EXPIRE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.30";

    // pwdMaxLength
    public static final String PWD_MAX_LENGTH_AT = "pwdMaxLength";
    public static final String PWD_MAX_LENGTH_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.31";
}
