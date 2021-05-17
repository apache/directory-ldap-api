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

package org.apache.directory.api.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.text.ParseException;
import java.util.Date;

import org.junit.jupiter.api.Test;

/**
 * A class to test DateUtils
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DateUtilTest
{
    @Test
    public void testGetGeneralizedTimeWithDefaultTimeProvider() throws ParseException
    {
        long t1 = System.currentTimeMillis();
        String gt = DateUtils.getGeneralizedTime( TimeProvider.DEFAULT );
        long now = new GeneralizedTime( gt ).getTime();
        long t2 = System.currentTimeMillis();
        assertTrue( t1 <= now );
        assertTrue( now <= t2 );
    }


    @Test
    public void testGetGeneralizedTimeWithMockTimeProvider() throws ParseException
    {
        MockTimeProvider mockTimeProvider = new MockTimeProvider();
        mockTimeProvider.setTimeInMillis( 1234567890L );

        String gt = DateUtils.getGeneralizedTime( mockTimeProvider );
        long t1 = new GeneralizedTime( gt ).getTime();
        assertEquals( 1234567890L, t1 );
    }


    @Test
    public void testGetDate()
    {
        Date date = DateUtils.getDate( "19700101000000.000Z" );
        assertEquals( 0, date.getTime() );
    }

    @Test
    public void testInfinite()
    {
        try
        {
            DateUtils.getDate( "9223372036854775807" );
        }
        catch ( RuntimeException pe )
        {
            fail();
        }
    }
}
