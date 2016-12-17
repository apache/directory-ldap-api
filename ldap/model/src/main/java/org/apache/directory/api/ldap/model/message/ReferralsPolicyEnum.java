/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * 
 */
package org.apache.directory.api.ldap.model.message;

/**
 * An enum describing the three possible actions for referrals :
 * <ul>
 * <li>Ignore : The referrals will be retruned as is (ie, the 'ref' attribute type will be present in the entry</li>
 * <li>Follow : The referral will be chased by the client</li>
 * <li>Throws : An LdapReferralException will be thrown</li>
 * </ul>
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 */
public enum ReferralsPolicyEnum
{
    /** Ignore referral */
    IGNORE,
    
    /** Floow referral */
    FOLLOW,
    
    /** Throw an exception */
    THROW
}
