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


/**
 * Provides the current time, i.e. <code>System.currentTimeMillis()</code>. 
 * This abstraction is done to be able to switch the implementation for time dependent tests.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface TimeProvider
{
    /**
     * The default time provider that always returns the system time.
     */
    TimeProvider DEFAULT = new TimeProvider()
    {
        //@Override
        public long currentIimeMillis()
        {
            return System.currentTimeMillis();
        }
    };


    /**
     * Gets the current time in milliseconds sind 1970-01-01 UTC.
     * 
     * @return the current time in milliseconds sind 1970-01-01 UTC
     */
    long currentIimeMillis();

}
