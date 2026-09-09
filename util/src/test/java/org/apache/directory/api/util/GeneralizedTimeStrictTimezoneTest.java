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
package org.apache.directory.api.util;


import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.text.ParseException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that GeneralizedTime rejects any time zone token other than 'Z',
 * '+HH[MM]' or '-HH[MM]'. Before this was enforced, a value containing a
 * fraction could carry unlimited trailing garbage ("20250101120000.5whatever")
 * and still parse successfully as GMT, creating a parsing differential with
 * strict RFC 4517 implementations.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class GeneralizedTimeStrictTimezoneTest
{
    /**
     * Trailing garbage after a fraction of a second must be rejected.
     */
    @Test
    public void testFractionOfSecondTrailingGarbageRejected()
    {
        assertThrows( ParseException.class, () -> new GeneralizedTime( "20250101120000.5X" ) );
        assertThrows( ParseException.class, () -> new GeneralizedTime( "20991231235959.9UNTIL-FOREVER" ) );
    }


    /**
     * Trailing garbage after a fraction of a minute must be rejected.
     */
    @Test
    public void testFractionOfMinuteTrailingGarbageRejected()
    {
        assertThrows( ParseException.class, () -> new GeneralizedTime( "202501011200.5garbage" ) );
    }


    /**
     * Trailing garbage after a fraction of an hour must be rejected.
     */
    @Test
    public void testFractionOfHourTrailingGarbageRejected()
    {
        assertThrows( ParseException.class, () -> new GeneralizedTime( "2025010112.5garbage" ) );
    }


    /**
     * Valid time zone tokens after a fraction must still be accepted.
     */
    @Test
    public void testValidTimezoneAfterFractionStillAccepted() throws ParseException
    {
        assertNotNull( new GeneralizedTime( "20250101120000.5Z" ) );
        assertNotNull( new GeneralizedTime( "20250101120000.5+0100" ) );
        assertNotNull( new GeneralizedTime( "20250101120000.5-05" ) );
        assertNotNull( new GeneralizedTime( "202501011200.5Z" ) );
        assertNotNull( new GeneralizedTime( "2025010112.5Z" ) );
    }
}
