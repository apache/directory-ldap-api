/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
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


import java.text.ParseException;
import java.util.Date;

import org.apache.directory.api.i18n.I18n;


/**
 * Gets the generalized time using the "Z" form of the g-time-zone.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class DateUtils
{
    /**
     * Private constructor.
     */
    private DateUtils()
    {
    }


    /**
     * Return a Date instance from a String 
     *
     * @param zuluTime The String to convert
     * @return The Date instance
     */
    public static Date getDate( String zuluTime )
    {
        try
        {
            return GeneralizedTime.getDate( zuluTime );
        }
        catch ( Exception e )
        {
            throw new RuntimeException( e );
        }
    }


    /**
     * Gets the generalized time right now. {@link GeneralizedTime}
     * 
     * @return the generalizedTime right now
     */
    public static String getGeneralizedTime()
    {
        return new GeneralizedTime( new Date() ).toGeneralizedTime();
    }


    /**
     * 
     * @see #getGeneralizedTime()
     *
     * @param date the date to be converted to generalized time string
     * @return given date in the generalized time string format
     */
    public static String getGeneralizedTime( Date date )
    {
        return new GeneralizedTime( date ).toGeneralizedTime();
    }


    /**
     * 
     * @see #getGeneralizedTime()
     *
     * @param time the time value to be converted to generalized time string
     * @return given time in generalized time string format
     */
    public static String getGeneralizedTime( long time )
    {
        return getGeneralizedTime( new Date( time ) );
    }


    /**
     * Converts the 18-digit Active Directory timestamps, also named 'Windows NT time format' or 'Win32 FILETIME or SYSTEMTIME'.
     * These are used in Microsoft Active Directory for pwdLastSet, accountExpires, LastLogon, LastLogonTimestamp and LastPwdSet.
     * The timestamp is the number of 100-nanoseconds intervals (1 nanosecond = one billionth of a second) since Jan 1, 1601 UTC.
     * <p>
     *
     * @param intervalDate 18-digit number. Time in 100-nanoseconds intervals since 1.1.1601
     * @return The converted date
     * @throws ParseException If the given interval is not valid
     */
    public static Date convertIntervalDate( String intervalDate ) throws ParseException
    {
        if ( intervalDate == null )
        {
            throw new ParseException( I18n.err( I18n.ERR_04359 ), 0 );
        }
    
        long offset = 11644473600000L; // offset milliseconds from Jan 1, 1601 to Jan 1, 1970
         
        // convert 100-nanosecond intervals to milliseconds (10000 = 1 000 000ns / 100)
        long javaTime = Long.parseLong( intervalDate ) / 10000L - offset;
        
        return new Date( javaTime );
    }
}
