/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.api.ldap.model.url;

/**
 * The type of Host we may have . One of :
 * <ul>
 * <li>IPV4 : IPV4 host</li>
 * <li>IPV6 : IPV6 host</li>
 * <li>IPV_FUTURE : IP v Future host</li>
 * <li>REGULAR_NAME : A regular name</li>
 * <li></li>
 * </ul>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum HostTypeEnum
{
    /** IP V4 host */
    IPV4,
    
    /** IP V6 host */
    IPV6,
    
    /** IP V(future) host */
    IPV_FUTURE,
    
    /** Regular name host */
    REGULAR_NAME
}
