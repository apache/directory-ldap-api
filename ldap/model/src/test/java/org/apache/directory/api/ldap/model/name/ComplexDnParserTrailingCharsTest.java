/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.api.ldap.model.name;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Test that the complex DN parser consumes the whole input or fails: it must
 * not silently discard trailing bytes after the last parsed RDN, because the
 * Dn keeps the complete input as its user-provided name and a downstream
 * parser may read the never-validated tail differently.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class ComplexDnParserTrailingCharsTest
{
    @Test
    public void testTrailingGarbageAfterEscapedValueIsRejected()
    {
        // The LDAP hex escape '\2C' routes parsing to the complex parser; the
        // unescaped '<' ends the value early and ',uid=admin,ou=system' was
        // previously discarded while remaining in Dn.getName()
        assertThrows( LdapInvalidDnException.class,
            () -> new Dn( "uid=jsmith\\2C<,uid=admin,ou=system" ) );
    }


    @Test
    public void testIsValidRejectsTrailingGarbage()
    {
        assertFalse( Dn.isValid( "uid=jsmith\\2C<,uid=admin,ou=system" ) );
        assertFalse( Dn.isValid( "cn=a\\2Cb>trailing" ) );
    }


    @Test
    public void testValidComplexDnsStillParse() throws LdapException
    {
        assertTrue( Dn.isValid( "cn=a\\,b,dc=example,dc=com" ) );
        assertTrue( Dn.isValid( "cn=a\\2Cb,dc=example,dc=com" ) );
        assertTrue( Dn.isValid( "ou=x\\+y,dc=example,dc=com" ) );
    }
}