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

package org.apache.directory.api.ldap.model.password;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.apache.directory.api.util.Strings;
import org.junit.Test;

/**
 * A test for the PasswordUtil class.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordUtilTest
{

    @Test
    public void compareCredentialTest()
    {
        // Simple cases
        assertTrue( PasswordUtil.compareCredentials( null, null ) );
        assertTrue( PasswordUtil.compareCredentials( new byte[]{}, new byte[]{} ) );
        assertTrue( PasswordUtil.compareCredentials( new byte[]{ 0x01 }, new byte[]{ 0x01 } ) );
        
        // Simple failures
        assertFalse( PasswordUtil.compareCredentials( null, new byte[]{ 0x01 } ) );
        assertFalse( PasswordUtil.compareCredentials( new byte[]{ 0x01 }, null ) );
        assertFalse( PasswordUtil.compareCredentials( new byte[]{ 0x01 }, new byte[]{ 0x02 } ) );
        
        // With some different lengths
        assertFalse( PasswordUtil.compareCredentials( Strings.getBytesUtf8( "Password1" ), Strings.getBytesUtf8( "Password1 " ) ) );

        // With different passwords
        assertFalse( PasswordUtil.compareCredentials( Strings.getBytesUtf8( "Password1" ), Strings.getBytesUtf8( "password1" ) ) );

        // With same passwords
        assertTrue( PasswordUtil.compareCredentials( Strings.getBytesUtf8( "Password1" ), Strings.getBytesUtf8( "Password1" ) ) );
    }
}
