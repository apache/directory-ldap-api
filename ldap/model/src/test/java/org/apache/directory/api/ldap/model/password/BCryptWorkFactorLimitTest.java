/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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


import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;


/**
 * Tests that the bcrypt work factor accepted from a (possibly attacker written)
 * stored credential is bounded at verification time.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class BCryptWorkFactorLimitTest
{
    @Test
    public void testExcessiveWorkFactorIsRejectedByHashPw()
    {
        // 2^30 rounds would take hours of CPU : must be refused, not computed
        assertThrows( IllegalArgumentException.class,
            () -> BCrypt.hashPw( "secret", "$2a$30$LH2xIb/TZmajuLJGDNuege" ) );
    }


    @Test
    public void testExcessiveWorkFactorIsRejectedAtCredentialComparison()
    {
        // A self-service password modify can store a '{CRYPT}$2a$30$...' blob :
        // a bind attempt against it must not pin a CPU for hours
        assertFalse( PasswordUtil.compareCredentials(
                Strings.getBytesUtf8( "secret" ),
                Strings.getBytesUtf8( "{CRYPT}$2a$30$LH2xIb/TZmajuLJGDNuegeeY.SCwkg6YAVLNXTh8n4Xfb1uwmLXg6" ) ) );
    }


    @Test
    public void testReasonableWorkFactorsStillVerify()
    {
        assertTrue( PasswordUtil.compareCredentials(
            Strings.getBytesUtf8( "secret" ),
            Strings.getBytesUtf8( "{CRYPT}$2a$06$LH2xIb/TZmajuLJGDNuegeeY.SCwkg6YAVLNXTh8n4Xfb1uwmLXg6" ) ) );
    }
}
