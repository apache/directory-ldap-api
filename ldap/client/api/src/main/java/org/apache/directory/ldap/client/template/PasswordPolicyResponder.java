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


import org.apache.directory.ldap.client.template.exception.PasswordException;


/**
 * A class for translating the outcome of a {@link PasswordPolicyOperation}.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface PasswordPolicyResponder
{
    /**
     * Execute the <code>operation</code> and translate the outcome as follows:
     * 
     * <ul>
     * <li>SUCCESS: return null</li>
     * <li>WARNING: return {@link PasswordWarning}</li>
     * <li>FAILURE: throw {@link PasswordException}</li>
     * </ul>
     * 
     * @param operation An operation whose outcome implies password policy 
     * information
     * @return A <code>PasswordWarning</code> if warnings are present, or null 
     * if completely successful.
     * @throws PasswordException If the <code>operation</code> was a failure.
     */
    PasswordWarning process( PasswordPolicyOperation operation ) throws PasswordException;
}
