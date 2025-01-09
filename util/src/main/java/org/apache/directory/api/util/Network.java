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


import java.net.InetAddress;


/**
 * Network utils.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class Network
{
    /** The loopback address (ie, ::1 or 127.0.0.1 */
    public static final InetAddress LOOPBACK = getLoopbackAddress();
    
    /** The loopback hostname */
    public static final String LOOPBACK_HOSTNAME = getLoopbackHostName();

    /**
     * Private constructor.
     */
    private Network()
    {
    }


    /**
     * Fetch the loopback host name
     * 
     * @return The loopback host name
     */
    private static String getLoopbackHostName()
    {
        InetAddress loopbackAddress = InetAddress.getLoopbackAddress();
        return loopbackAddress.getCanonicalHostName();
    }


    /**
     * Fetch the loopback address
     * 
     * @return The loopback address
     */
    private static InetAddress getLoopbackAddress()
    {
        return InetAddress.getLoopbackAddress();
    }


    /**
     * Construct a LDAP URL using the loopback address.
     * 
     * @param port The port
     * @return The Loopback URL
     */
    public static String ldapLoopbackUrl( int port )
    {
        return "ldap://" + LOOPBACK_HOSTNAME + ":" + port;
    }
}
