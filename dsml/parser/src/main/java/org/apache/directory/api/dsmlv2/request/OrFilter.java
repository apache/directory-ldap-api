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
package org.apache.directory.api.dsmlv2.request;


import java.util.List;


/**
 * Or Filter Object to store the Or filter.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class OrFilter extends ConnectorFilter
{
    /**
     * Default constructor
     */
    public OrFilter() 
    {
        super();
    }


    /**
     * Get the OrFilter
     * 
     * @return Returns the orFilter.
     */
    public List<Filter> getOrFilter()
    {
        return filterSet;
    }


    /**
     * Return a string compliant with RFC 2254 representing an OR filter
     * 
     * @return The OR filter string
     */
    @Override
    public String toString()
    {

        StringBuilder sb = new StringBuilder();

        sb.append( '|' ).append( super.toString() );

        return sb.toString();
    }
}
