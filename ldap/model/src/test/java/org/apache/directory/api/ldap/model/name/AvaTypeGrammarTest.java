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


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that the programmatic Ava/Rdn composition API enforces the RFC 4514
 * attributeType grammar : a type containing structural DN characters must be
 * rejected, otherwise it injects DN structure when the composed DN is
 * serialized and re-parsed.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class AvaTypeGrammarTest
{
    /**
     * A type carrying DN structural characters must be rejected : previously
     * new Ava( "cn=admin,dc=example,dc=com+cn", "x" ).getEscaped() yielded
     * "cn=admin,dc=example,dc=com+cn=x", re-parsing as an injected DN.
     */
    @Test
    public void testStructuralCharactersInTypeAreRejected()
    {
        assertThrows( LdapInvalidDnException.class,
            () -> new Ava( "cn=", "x" ) );

        assertThrows( LdapInvalidDnException.class,
            () -> new Ava( "a:b", "x" ) );

        assertThrows( LdapInvalidDnException.class,
            () -> new Ava( "    ", "x" ) );

        assertThrows( LdapInvalidDnException.class,
            () -> new Ava( "-ab", "x" ) );
    }


    /**
     * Valid descr and numericoid types must still be accepted.
     */
    @Test
    public void testValidTypesAreAccepted() throws LdapInvalidDnException
    {
        assertEquals( "cn=x", new Ava( "cn", "x" ).getEscaped() );
        assertEquals( "cn-2_b=x", new Ava( "cn-2_b", "x" ).getEscaped() );
        assertEquals( "2.5.4.3=x", new Ava( "2.5.4.3", "x" ).getEscaped() );
        assertEquals( "oid.2.5.4.3=x", new Ava( "oid.2.5.4.3", "x" ).getEscaped() );
    }


    /**
     * Values keep being escaped, not rejected : the fix must not change the
     * value handling.
     */
    @Test
    public void testValuesAreStillEscaped() throws LdapInvalidDnException
    {
        assertEquals( "cn=x\\,y", new Ava( "cn", "x,y" ).getEscaped() );
    }
}
