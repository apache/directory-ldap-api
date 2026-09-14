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

package org.apache.directory.api.ldap.sp;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.InvalidClassException;
import java.util.ArrayList;

import org.apache.commons.lang3.SerializationUtils;
import org.junit.jupiter.api.Test;


/**
 * Tests for the restricted deserialization of stored procedure results: the extended
 * response value is entirely controlled by the LDAP server, so it must never reach an
 * unrestricted ObjectInputStream (CWE-502).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class JavaStoredProcUtilsTest
{
    @Test
    public void testDeserializeResponseAcceptsSimpleValues() throws Exception
    {
        byte[] payload = SerializationUtils.serialize( "hello" );
        assertEquals( "hello", JavaStoredProcUtils.deserializeResponse( payload ) );

        byte[] intPayload = SerializationUtils.serialize( Integer.valueOf( 42 ) );
        assertEquals( Integer.valueOf( 42 ), JavaStoredProcUtils.deserializeResponse( intPayload ) );

        ArrayList<String> list = new ArrayList<>();
        list.add( "a" );
        list.add( "b" );
        byte[] listPayload = SerializationUtils.serialize( list );
        assertEquals( list, JavaStoredProcUtils.deserializeResponse( listPayload ) );
    }


    @Test
    public void testDeserializeResponseRejectsNonAllowlistedClasses()
    {
        // Any class outside the allowlist must be rejected before it is loaded or
        // instantiated: a malicious server controls these bytes entirely, and gadget
        // chain side effects run during readObject
        byte[] payload = SerializationUtils.serialize( new File( "/tmp" ) );

        assertThrows( InvalidClassException.class, () ->
        {
            JavaStoredProcUtils.deserializeResponse( payload );
        } );
    }
}
