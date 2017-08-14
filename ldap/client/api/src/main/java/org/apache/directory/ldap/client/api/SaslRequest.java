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
package org.apache.directory.ldap.client.api;

import org.apache.directory.api.ldap.model.constants.SaslQoP;
import org.apache.directory.api.ldap.model.constants.SaslSecurityStrength;
import org.apache.directory.api.ldap.model.message.Control;

/**
 * Holds the data required to complete the SASL operation
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface SaslRequest
{
    /**
     * Gets the authorization ID.
     *
     * @return the authorization ID
     */
    String getAuthorizationId();

    
    /**
     * Gets the controls.
     *
     * @return the controls
     */
    Control[] getControls();

    
    /**
     * Gets the crendentials
     *
     * @return the credentials
     */
    byte[] getCredentials();


    /**
     * Gets the quality of protection.
     *
     * @return the quality of protection
     */
    SaslQoP getQualityOfProtection();
    
    
    /**
     * Gets realm name.
     *
     * @return the realm name
     */
    String getRealmName();


    /**
     * Gets the SASL mechanism.
     *
     * @return the SASL mechanism
     */
    String getSaslMechanism();


    /**
     * Gets the security strength.
     *
     * @return the security strength
     */
    SaslSecurityStrength getSecurityStrength();

    
    /**
     * Gets the username.
     *
     * @return the username
     */
    String getUsername();


    /**
     * Indicates if mutual authentication is required.
     *
     * @return the flag indicating if mutual authentication is required
     */
    boolean isMutualAuthentication();
}
