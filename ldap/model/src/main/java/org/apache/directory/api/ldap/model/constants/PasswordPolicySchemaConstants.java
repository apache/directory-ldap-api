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
 * Final reference -> class shouldn't be extended
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
    public final static String PWD_POLICY_OC = "pwdPolicy";
    public final static String PWD_POLICY_OC_OID = "1.3.6.1.4.1.42.2.27.8.2.1";

    // ---- AttributeTypes ----------------------------------------------------
    // pwdAttribute
    public final static String PWD_ATTRIBUTE_AT = "pwdAttribute";
    public final static String PWD_ATTRIBUTE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.1";

    // pwdMinAge
    public final static String PWD_MIN_AGE_AT = "pwdMinAge";
    public final static String PWD_MIN_AGE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.2";

    // pwdMaxAge
    public final static String PWD_MAX_AGE_AT = "pwdMaxAge";
    public final static String PWD_MAX_AGE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.3";

    // pwdLockoutDuration
    public final static String PWD_LOCKOUT_DURATION_AT = "pwdLockoutDuration";
    public final static String PWD_LOCKOUT_DURATION_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.10";

    // pwdInHistory
    public final static String PWD_IN_HISTORY_AT = "pwdInHistory";
    public final static String PWD_IN_HISTORY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.4";

    // pwdCheckQuality
    public final static String PWD_CHECK_QUALITY_AT = "pwdCheckQuality";
    public final static String PWD_CHECK_QUALITY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.5";

    // pwdMinLength
    public final static String PWD_MIN_LENGTH_AT = "pwdMinLength";
    public final static String PWD_MIN_LENGTH_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.6;";

    // pwdExpireWarning
    public final static String PWD_EXPIRE_WARNING_AT = "pwdExpireWarning";
    public final static String PWD_EXPIRE_WARNING_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.7;";

    // pwdGraceAuthNLimit
    public final static String PWD_GRACE_AUTHN_LIMIT_AT = "pwdGraceAuthNLimit";
    public final static String PWD_GRACE_AUTHN_LIMIT_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.;";

    // pwdLockout
    public final static String PWD_LOCKOUT_AT = "pwdLockout";
    public final static String PWD_LOCKOUT_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.9";

    // pwdMaxFailure
    public final static String PWD_MAX_FAILURE_AT = "pwdMaxFailure";
    public final static String PWD_MAX_FAILURE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.11";

    // pwdFailureCountInterval
    public final static String PWD_FAILURE_COUNT_INTERVAL_AT = "pwdFailureCountInterval";
    public final static String PWD_FAILURE_COUNT_INTERVAL_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.12";

    // public final static String PWD_MUST_CHANGE_AT = 
    public final static String PWD_MUST_CHANGE_AT = "pwdMustChange";
    public final static String PWD_MUST_CHANGE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.13";

    // pwdAllowUserChange
    public final static String PWD_ALLOW_USER_CHANGE_AT = "pwdAllowUserChange";
    public final static String PWD_ALLOW_USER_CHANGE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.14";

    // pwdSafeModify
    public final static String PWD_SAFE_MODIFY_AT = "pwdSafeModify";
    public final static String PWD_SAFE_MODIFY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.15";

    // pwdChangedTime
    public final static String PWD_CHANGED_TIME_AT = "pwdChangedTime";
    public final static String PWD_CHANGED_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.16";

    // pwdAccountLockedTime
    public final static String PWD_ACCOUNT_LOCKED_TIME_AT = "pwdAccountLockedTime";
    public final static String PWD_ACCOUNT_LOCKED_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.17";

    // pwdFailureTime
    public final static String PWD_FAILURE_TIME_AT = "pwdFailureTime";
    public final static String PWD_FAILURE_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.19";

    // pwdHistory
    public final static String PWD_HISTORY_AT = "pwdHistory";
    public final static String PWD_HISTORY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.20";

    // pwdGraceUseTime
    public final static String PWD_GRACE_USE_TIME_AT = "pwdGraceUseTime";
    public final static String PWD_GRACE_USE_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.21";

    // pwdReset
    public final static String PWD_RESET_AT = "pwdReset";
    public final static String PWD_RESET_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.22";

    // pwdPolicySubentry
    public final static String PWD_POLICY_SUBENTRY_AT = "pwdPolicySubentry";
    public final static String PWD_POLICY_SUBENTRY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.23";

    // pwdMinDelay
    public final static String PWD_MIN_DELAY_AT = "pwdMinDelay";
    public final static String PWD_MIN_DELAY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.24";

    // pwdMaxDelay
    public final static String PWD_MAX_DELAY_AT = "pwdMaxDelay";
    public final static String PWD_MAX_DELAY_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.25";

    // pwdMaxIdle
    public final static String PWD_MAX_IDLE_AT = "pwdMaxIdle";
    public final static String PWD_MAX_IDLE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.26";

    // pwdStartTime
    public final static String PWD_START_TIME_AT = "pwdStartTime";
    public final static String PWD_START_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.27";

    // pwdEndTime
    public final static String PWD_END_TIME_AT = "pwdEndTime";
    public final static String PWD_END_TIME_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.28";

    // pwdLastSuccess
    public final static String PWD_LAST_SUCCESS_AT = "pwdLastSuccess";
    public final static String PWD_LAST_SUCCESS_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.29";

    // pwdGraceExpire
    public final static String PWD_GRACE_EXPIRE_AT = "pwdGraceExpire";
    public final static String PWD_GRACE_EXPIRE_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.30";

    // pwdMaxLength
    public final static String PWD_MAX_LENGTH_AT = "pwdMaxLength";
    public final static String PWD_MAX_LENGTH_AT_OID = "1.3.6.1.4.1.42.2.27.8.1.31";
}
