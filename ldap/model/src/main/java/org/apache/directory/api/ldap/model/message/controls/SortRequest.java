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
package org.apache.directory.api.ldap.model.message.controls;


import java.util.List;

import org.apache.directory.api.ldap.model.message.Control;


/**
 * Implementation of Server Side Sort request control based on
 * the <a href="http://tools.ietf.org/html/rfc2891">RFC 2891</a><br><br>
 * 
 *       SortKeyList ::= SEQUENCE OF SEQUENCE {<br>
 *               attributeType   AttributeDescription,<br>
 *               orderingRule    [0] MatchingRuleId OPTIONAL,<br>
 *               reverseOrder    [1] BOOLEAN DEFAULT FALSE }<br>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface SortRequest extends Control
{
    /** the sort request control's OID */
    String OID = "1.2.840.113556.1.4.473";


    /**
     * sets the sort keys
     *  
     * @param sortKeys The list of keys to be sorted
     */
    void setSortKeys( List<SortKey> sortKeys );


    /**
     * @return the list of sort keys
     */
    List<SortKey> getSortKeys();


    /**
     * adds a sort key
     * 
     * @param sortKey The list of keys to be sorted
     */
    void addSortKey( SortKey sortKey );
}
