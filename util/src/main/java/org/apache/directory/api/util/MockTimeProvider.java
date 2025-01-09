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


/**
 * Implementation of {@link TimeProvider} that always returns a fixed time.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MockTimeProvider implements TimeProvider
{
    /** The time in millisecond */
    private long timeInMillis;


    /**
     * A MockTimeProvider constructor which sets the time to teh cirrent time
     */
    public MockTimeProvider()
    {
        this.timeInMillis = System.currentTimeMillis();
    }


    /**
     * Get the current time in millisecond
     * 
     * @return The current time 
     */
    public long currentIimeMillis()
    {
        return timeInMillis;
    }


    /**
     * Set the current time in millisecond
     * 
     * @param timeInMillis The current time 
     */
    public void setTimeInMillis( long timeInMillis )
    {
        this.timeInMillis = timeInMillis;
    }


    /**
     * Add some time to the current time
     * 
     * @param millis The time to add to the current time 
     */
    public void addMillis( long millis )
    {
        this.timeInMillis += millis;
    }


    /**
     * Substract some time to the current time
     * 
     * @param millis The time to substract from the current time 
     */
    public void substractMillis( long millis )
    {
        this.timeInMillis -= millis;
    }
}
