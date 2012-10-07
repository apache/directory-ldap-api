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
package org.apache.directory.shared.util;


import java.util.Calendar;
import java.util.Date;


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


    public static Date getDate( String zuluTime )
    {
        try
        {
            return GeneralizedTime.getDate( zuluTime );
        }
        catch( Exception e )
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
        return new GeneralizedTime( Calendar.getInstance() ).toGeneralizedTime();
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
        Calendar calendar = Calendar.getInstance();
        calendar.setTime( date );
        return new GeneralizedTime( calendar ).toGeneralizedTime();
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

}
