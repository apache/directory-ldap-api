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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import javax.net.ssl.TrustManager;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LdapConnectionConfigTest {

    @Test
    public void testNullTrustManagers() {
        LdapConnectionConfig config = new LdapConnectionConfig();

        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            config.setTrustManagers((TrustManager)null);
        });
    }
    
    @Test
    public void testNullTrustManagers2() {
        LdapConnectionConfig config = new LdapConnectionConfig();

        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            config.setTrustManagers(null);
        });
    }
    
    @Test
    public void testValidTrustManagers() {
        LdapConnectionConfig config = new LdapConnectionConfig();
        config.setTrustManagers(new NoVerificationTrustManager());
        assertNotNull(config.getTrustManagers());
    }
}

