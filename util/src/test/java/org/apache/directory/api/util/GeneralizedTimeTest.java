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

import static org.apache.directory.api.util.TimeZones.GMT;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.TimeZone;

import org.apache.directory.api.util.GeneralizedTime.Format;
import org.apache.directory.api.util.GeneralizedTime.TimeZoneFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Tests the DateUtils class methods.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class GeneralizedTimeTest
{
    private static final Logger LOG = LoggerFactory.getLogger( GeneralizedTimeTest.class );


    // Test all valid variants:
    // Time: min + sec / min + no sec / no min + no sec 
    // Fraction: no fraction, dot, comma
    // Timezone: Z / +HH / +HHmm / -HH / -HHmm

    /**
     * Tests yyyyMMddHHmmssZ.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinSecZulu() throws ParseException
    {
        String gt = "20080102121314Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmmss+04.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinSecPlusHour() throws ParseException
    {
        String gt = "20080102121314+04";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmmss-1030.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinSecMinusHourMin() throws ParseException
    {
        String gt = "20080102121314-1030";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmmss.SSSZ.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinSecDotFractionZulu() throws ParseException
    {
        String gt = "20080102121314.987Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmmss.SSS+0100.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinSecDotFractionPlusHour() throws ParseException
    {
        String gt = "20080102121314.987+0100";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmmss.SSS-1030.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinSecDotFractionMinusHourMin() throws ParseException
    {
        String gt = "20080102121314.987-1030";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmmss,SSSZ.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinSecCommaFractionZulu() throws ParseException
    {
        String gt = "20080102121314,987Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmmss,SSS+0100.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinSecCommaFractionPlusHour() throws ParseException
    {
        String gt = "20080102121314,987+0100";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmmss,SSS-1030.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinSecCommaFractionMinusHourMin() throws ParseException
    {
        String gt = "20080102121314,987-1030";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmmZ.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinZulu() throws ParseException
    {
        String gt = "200801021213Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmm+HH.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinPlusHour() throws ParseException
    {
        String gt = "200801021213+04";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmm-HHmm.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinMinusHourMin() throws ParseException
    {
        String gt = "200801021213-1030";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmm.SSSZ.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinDotFractionZulu() throws ParseException
    {
        String gt = "200801021213.987Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmm.SSS+0100.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinDotFractionPlusHour() throws ParseException
    {
        String gt = "200801021213.987+0100";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmm.SSS-1030.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinDotFractionMinusHourMin() throws ParseException
    {
        String gt = "200801021213.987-1030";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmm,SSSZ.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinCommaFractionZulu() throws ParseException
    {
        String gt = "200801021213,987Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmm,SSS+0100.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinCommaFractionPlusHour() throws ParseException
    {
        String gt = "200801021213,987+0100";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHmm,SSS-1030.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinCommaFractionMinusHourMin() throws ParseException
    {
        String gt = "200801021213,987-1030";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHHZ.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourZulu() throws ParseException
    {
        String gt = "2008010212Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHH+HH.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourPlusHour() throws ParseException
    {
        String gt = "2008010212+04";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHH-HHmm.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourMinusHourMin() throws ParseException
    {
        String gt = "2008010212-1030";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHH.SSSZ.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourDotFractionZulu() throws ParseException
    {
        String gt = "200801021213.987Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHH.SSS+0100.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourDotFractionPlusHour() throws ParseException
    {
        String gt = "2008010212.987+0100";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHH.SSS-1030.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourDotFractionMinusHourMin() throws ParseException
    {
        String gt = "2008010212.987-1030";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHH,SSSZ.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourCommaFractionZulu() throws ParseException
    {
        String gt = "2008010212,987Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHH,SSS+0100.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourCommaFractionPlusHour() throws ParseException
    {
        String gt = "2008010212,987+0100";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests yyyyMMddHH,SSS-1030.
     * @throws ParseException If the test fails
     */
    @Test
    public void testYearMonthDayHourCommaFractionMinusHourMin() throws ParseException
    {
        String gt = "2008010212,987-1030";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests fraction of a second.
     * @throws ParseException If the test fails
     */
    @Test
    public void testFractionOfSecond() throws ParseException
    {
        String gt = "20080102121314,987Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
        assertEquals( 987, generalizedTime.getCalendar().get( Calendar.MILLISECOND ) );
    }


    /**
     * Tests fraction of a minute.
     * @throws ParseException If the test fails
     */
    @Test
    public void testFractionOfMinute1() throws ParseException
    {
        String gt = "200801021213,5Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
        assertEquals( 30, generalizedTime.getCalendar().get( Calendar.SECOND ) );
        assertEquals( 0, generalizedTime.getCalendar().get( Calendar.MILLISECOND ) );
    }


    /**
     * Tests fraction of a minute.
     * @throws ParseException If the test fails
     */
    @Test
    public void testFractionOfMinute2() throws ParseException
    {
        String gt = "200801021213,125Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
        assertEquals( 7, generalizedTime.getCalendar().get( Calendar.SECOND ) );
        assertEquals( 500, generalizedTime.getCalendar().get( Calendar.MILLISECOND ) );
    }


    /**
     * Tests fraction of an hour.
     * @throws ParseException If the test fails
     */
    @Test
    public void testFractionOfHour1() throws ParseException
    {
        String gt = "2008010212,5Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
        assertEquals( 30, generalizedTime.getCalendar().get( Calendar.MINUTE ) );
        assertEquals( 0, generalizedTime.getCalendar().get( Calendar.SECOND ) );
        assertEquals( 0, generalizedTime.getCalendar().get( Calendar.MILLISECOND ) );
    }


    /**
     * Tests fraction of an hour.
     * @throws ParseException If the test fails
     */
    @Test
    public void testFractionOfHour2() throws ParseException
    {
        String gt = "2008010212,125Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
        assertEquals( 7, generalizedTime.getCalendar().get( Calendar.MINUTE ) );
        assertEquals( 30, generalizedTime.getCalendar().get( Calendar.SECOND ) );
        assertEquals( 0, generalizedTime.getCalendar().get( Calendar.MILLISECOND ) );
    }


    /**
     * Test formatting
     * @throws ParseException If the test fails
     */
    @Test
    public void testFormatting() throws ParseException
    {
        String gt = "20080102121314Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );

        result = generalizedTime.toGeneralizedTime( Format.YEAR_MONTH_DAY_HOUR_MIN, null, 0, TimeZoneFormat.Z );
        assertEquals( "200801021213Z", result );

        result = generalizedTime.toGeneralizedTime( Format.YEAR_MONTH_DAY_HOUR, null, 0, TimeZoneFormat.Z );
        assertEquals( "2008010212Z", result );

        result = generalizedTime.toGeneralizedTime( Format.YEAR_MONTH_DAY_HOUR_MIN, null, 0,
            TimeZoneFormat.DIFF_HOUR_MINUTE );
        assertEquals( "200801021213+0000", result );

        result = generalizedTime.toGeneralizedTime( Format.YEAR_MONTH_DAY_HOUR, null, 0,
            TimeZoneFormat.DIFF_HOUR_MINUTE );
        assertEquals( "2008010212+0000", result );
    }


    /**
     * Test adjustment of time while formatting. 
     * @throws ParseException If the test fails
     */
    @Test
    public void testAdjustWhileFormatting() throws ParseException
    {
        String gt = "20080102121314+0130";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );

        result = generalizedTime.toGeneralizedTime( Format.YEAR_MONTH_DAY_HOUR_MIN_SEC, null, 0, TimeZoneFormat.Z );
        assertEquals( "20080102104314Z", result );
    }


    /**
     * Testcases from GeneralizedTimeSyntaxCheckerTest#testCorrectCase().
     * @throws ParseException If the test fails
     */
    @Test
    public void testGeneralizedTimeSyntaxCheckerTestCorrectCase() throws ParseException
    {
        new GeneralizedTime( "20061205184527Z" );
        new GeneralizedTime( "20061205184527+0500" );
        new GeneralizedTime( "20061205184527-1234" );
        new GeneralizedTime( "20061205184527.123Z" );
        new GeneralizedTime( "20061205184527,123+0100" );
        new GeneralizedTime( "2006120519Z" );
    }


    /**
     * Testcases from GeneralizedTimeSyntaxCheckerTest#testErrorCase().
     */
    @Test
    public void testGeneralizedTimeSyntaxCheckerTestErrorCase()
    {
        try
        {
            new GeneralizedTime( "20060005184527Z" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        try
        {
            new GeneralizedTime( "20061305184527Z" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        try
        {
            new GeneralizedTime( "20062205184527Z" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        try
        {
            new GeneralizedTime( "20061200184527Z" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        try
        {
            new GeneralizedTime( "20061235184527Z" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        try
        {
            new GeneralizedTime( "20061205604527Z" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        try
        {
            new GeneralizedTime( "20061205186027Z" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        try
        {
            new GeneralizedTime( "20061205184561Z" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        try
        {
            new GeneralizedTime( "20061205184527Z+" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        try
        {
            new GeneralizedTime( "20061205184527+2400" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        try
        {
            new GeneralizedTime( "20061205184527+9900" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        try
        {
            new GeneralizedTime( "20061205184527+1260" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
        try
        {
            new GeneralizedTime( "20061205184527+1299" );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
    }


    /**
     * Tests leap second.
     * The GeneralizedTime class does not support leap seconds!
     * @throws ParseException If the test fails
     */
    @Test
    public void testLeapSecond() throws ParseException
    {
        String gt = "20051231235960Z";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
    }


    /**
     * Tests Feb 29 in a leap year.
     * @throws ParseException If the test fails
     */
    @Test
    public void testFebruary29inLeapYear() throws ParseException
    {
        String gt = "20080229000000Z";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests Feb 29 in a non-leap year.
     * @throws ParseException If the test fails
     */
    @Test
    public void testFebruary29inNonLeapYear() throws ParseException
    {
        String gt = "20070229000000Z";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
    }


    /**
     * Tests null.
     * @throws ParseException If the test fails
     */
    @Test
    public void testNull() throws ParseException
    {
        try
        {
            String gt = null;
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        try
        {
            Calendar calendar = null;
            new GeneralizedTime( calendar );
            fail( "Expected IllegalArgumentException" );
        }
        catch ( IllegalArgumentException iae )
        {
            // expected
        }

    }


    /**
     * Tests empty string.
     * @throws ParseException If the test fails
     */
    @Test
    public void testEmpty() throws ParseException
    {
        String gt = "";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
    }


    /**
     * Tests invalid cases.
     * @throws ParseException If the test fails
     */
    @Test
    public void testInvalid() throws ParseException
    {
        // too short year
        String gt = "200";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // non-digits in year
        gt = "2XX8";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // too short month
        gt = "20081";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // non-digits in month
        gt = "20081X";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // too short day
        gt = "2008122";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // non-digits in day
        gt = "2008122X";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // too short hour
        gt = "200812211";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // non-digits in hour
        gt = "20081221X1";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // too short minute
        gt = "20081221121";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // non-digits in minute
        gt = "20081221121X";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // too short second
        gt = "2008122112131";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // non-digits in minute
        gt = "2008122112131X";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // missing time zone
        gt = "2008010212";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // missing time zone
        gt = "200801021213";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // missing time zone
        gt = "20080102121314";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // no digit
        gt = "2008010212X";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // no digit
        gt = "200801021213X";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // no digit
        gt = "20080102121314X";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // missing time zone
        gt = "20080102121314,1";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // time zone is not last char
        gt = "20080102121314ZX";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // time zone is not last char
        gt = "20080102121314+0430X";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }

        // no fraction digit
        gt = "20080102121314,Z";
        try
        {
            new GeneralizedTime( gt );
            fail( "Expected ParseException" );
        }
        catch ( ParseException pe )
        {
            // expected
        }
    }


    /**
     * Tests constructor with calendar object.
     * @throws ParseException If the test fails
     */
    @Test
    public void testCalendar() throws ParseException
    {
        Calendar calendar = new GregorianCalendar( GMT, Locale.ROOT );
        calendar.set( Calendar.YEAR, 2008 );
        calendar.set( Calendar.MONTH, 0 );
        calendar.set( Calendar.DAY_OF_MONTH, 2 );
        calendar.set( Calendar.HOUR_OF_DAY, 12 );
        calendar.set( Calendar.MINUTE, 13 );
        calendar.set( Calendar.SECOND, 14 );
        calendar.set( Calendar.MILLISECOND, 222 );
        calendar.setTimeZone( TimeZone.getTimeZone( "GMT" ) );

        GeneralizedTime generalizedTime = new GeneralizedTime( calendar );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( "20080102121314.222Z", result );
    }


    /**
     * Tests a complete round trip.
     * @throws ParseException If the test fails
     */
    @Test
    public void testRoundTrip() throws ParseException
    {
        Calendar calendar = new GregorianCalendar( GMT, Locale.ROOT );
        calendar.setTimeInMillis( 123456789000L ); // default format is without millis

        // create form calendar
        GeneralizedTime generalizedTime1 = new GeneralizedTime( calendar );

        // get the string value
        String gt1 = generalizedTime1.toGeneralizedTime();
        Calendar calendar1 = generalizedTime1.getCalendar();

        // create from string value
        GeneralizedTime generalizedTime2 = new GeneralizedTime( gt1 );

        // get the calendar value 
        Calendar calendar2 = generalizedTime2.getCalendar();
        String gt2 = generalizedTime2.toGeneralizedTime();

        // assert that all are equal
        assertEquals( calendar, calendar1 );
        assertEquals( calendar, calendar2 );
        assertEquals( calendar1, calendar2 );
        assertEquals( gt1, gt2 );
        assertTrue( calendar.isLenient() );
        assertTrue( calendar1.isLenient() );
        assertTrue( calendar2.isLenient() );
    }


    /**
     * Tests the compareTo() method.
     * @throws ParseException If the test fails
     */
    @Test
    public void testCompareTo() throws ParseException
    {
        String gt1 = "20080102121313,999Z";
        GeneralizedTime generalizedTime1 = new GeneralizedTime( gt1 );

        String gt2 = "20080102121314Z";
        GeneralizedTime generalizedTime2 = new GeneralizedTime( gt2 );

        String gt3 = "20080102121314,001Z";
        GeneralizedTime generalizedTime3 = new GeneralizedTime( gt3 );

        assertTrue( generalizedTime1.compareTo( generalizedTime2 ) < 0 );
        assertTrue( generalizedTime1.compareTo( generalizedTime3 ) < 0 );
        assertTrue( generalizedTime2.compareTo( generalizedTime3 ) < 0 );

        assertTrue( generalizedTime2.compareTo( generalizedTime1 ) > 0 );
        assertTrue( generalizedTime3.compareTo( generalizedTime1 ) > 0 );
        assertTrue( generalizedTime3.compareTo( generalizedTime2 ) > 0 );

        assertTrue( generalizedTime1.compareTo( generalizedTime1 ) == 0 );
        assertTrue( generalizedTime2.compareTo( generalizedTime2 ) == 0 );
        assertTrue( generalizedTime3.compareTo( generalizedTime3 ) == 0 );
    }


    /**
     * Tests the equals() method.
     * @throws ParseException If the test fails
     */
    @Test
    public void testEquals() throws ParseException
    {
        String gt1 = "20080102121314Z";
        GeneralizedTime generalizedTime1 = new GeneralizedTime( gt1 );

        String gt2 = "20080102121314Z";
        GeneralizedTime generalizedTime2 = new GeneralizedTime( gt2 );

        String gt3 = "20080102121314,001Z";
        GeneralizedTime generalizedTime3 = new GeneralizedTime( gt3 );

        assertTrue( generalizedTime1.equals( generalizedTime2 ) );
        assertFalse( generalizedTime1.equals( generalizedTime3 ) );
        assertFalse( generalizedTime1.equals( null ) );
    }


    /**
     * Tests DIRSHARED-29 (GeneralizedTime.toString() generates wrong output 
     * when TimeZone has hours &lt; 10 and minutes &gt; 10).
     * @throws ParseException If the test fails
     */
    public void testDIRSHARED29() throws ParseException
    {
        String gt = "20090312123456+0130";
        GeneralizedTime generalizedTime = new GeneralizedTime( gt );
        String result = generalizedTime.toGeneralizedTime();
        assertEquals( gt, result );
    }


    /**
     * Tests to make sure the GeneralizedTime parser preserves the milliseconds 
     * component.
     * 
     * @see <a href="https://issues.apache.org/jira/browse/DIRSHARED-131">DIRSHARED-131</a>
     * @throws ParseException If the test fails
     */
    @Test
    public void testMillisecondsPreservation() throws ParseException
    {
        Date date = new Date();
        long originalTime = 0;
        long millisLost = 0;
        long trimmedMillis = 0;

        // Get the current date and time now, also with trimmed milliseconds

        while ( millisLost == 0 )
        {
            date = new Date();
            originalTime = date.getTime();
            trimmedMillis = originalTime / 1000;
            trimmedMillis = trimmedMillis * 1000;
            millisLost = originalTime - trimmedMillis;
        }

        LOG.info( "original time = {}", originalTime );
        LOG.info( "trimmed milliseconds = {}", trimmedMillis );
        LOG.info( "milliseconds lost = {}", millisLost );

        // Set time on new Calendar instance, and generate the GT string
        Calendar calendar = new GregorianCalendar( GMT, Locale.ROOT );
        calendar.setTime( date );
        GeneralizedTime gt = new GeneralizedTime( calendar );
        assertEquals( date.getTime(), calendar.getTime().getTime(), "calendar time must equal the date time" );
        String gtStr = gt.toGeneralizedTime();
        LOG.info( "generalized time string of original time = {}", gtStr );

        // Parse and regenerate calendar from gtStr
        GeneralizedTime recalculatedGt = new GeneralizedTime( gtStr );
        long recalculatedTime = recalculatedGt.getCalendar().getTime().getTime();
        LOG.info( "recalculated time = {}", recalculatedTime );
        LOG.info( "generalized time string of recalculated time = {}", recalculatedGt.toGeneralizedTime() );

        assertEquals( originalTime, recalculatedTime, "The time after round trip GeneralizedTime generation should stay the same" );
    }

    static DateFormat format = new SimpleDateFormat( "dd/MM/yyyy HH:mm:ss.SSSS z", Locale.ROOT );

    /**
     * 
     * @throws ParseException If the test fails
     */
    @Test
    public void fractionCloseToOne() throws ParseException
    {
        GeneralizedTime close = new GeneralizedTime( "20000101000000.9994Z" );
        
        assertThat( close.getDate(), is( equalTo( format.parse( "01/01/2000 00:00:00.999 GMT" ) ) ) );
        
        GeneralizedTime closer = new GeneralizedTime( "20000101000000.9995Z" );
        
        assertThat( closer.getDate(), is( equalTo( format.parse( "01/01/2000 00:00:00.999 GMT" ) ) ) );

        GeneralizedTime larger = new GeneralizedTime( "20000101000000.9Z" );
        
        assertThat( larger.getDate(), is( equalTo( format.parse( "01/01/2000 00:00:00.900 GMT" ) ) ) );
        
    }
}
