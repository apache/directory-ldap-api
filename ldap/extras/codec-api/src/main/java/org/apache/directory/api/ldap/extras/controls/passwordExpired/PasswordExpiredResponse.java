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
package org.apache.directory.api.ldap.extras.controls.passwordExpired;

import org.apache.directory.api.ldap.model.message.Control;

/**
 * The PasswordPolicy expired response control, as defined by 
 * https://docs.ldap.com/specs/draft-vchu-ldap-pwd-policy-00.txt
 * 
 * <pre>
 * controlType:  2.16.840.1.113730.3.4.5,
 *
 * controlValue: an octet string to indicate the time in seconds until
 *       the password expires.
 *
 * criticality:  false
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public interface PasswordExpiredResponse extends Control
{
    /** This control OID */
    String OID = "2.16.840.1.113730.3.4.4";

    
    /**
     * Returns the time in seconds before the password expires. Default to 0 
     * 
     * @return The time before expiration of the password
     */
    int getTimeBeforeExpiration();
}
