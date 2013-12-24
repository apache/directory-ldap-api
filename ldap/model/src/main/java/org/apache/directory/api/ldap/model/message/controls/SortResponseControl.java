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

import org.apache.directory.api.ldap.model.message.Control;

/**
 * 
 * <pre>SortResult ::= SEQUENCE {<br>
 *           sortResult  ENUMERATED {<br>
 *           success                   (0), -- results are sorted<br>
 *           operationsError           (1), -- server internal failure<br>
 *           timeLimitExceeded         (3), -- timelimit reached before sorting was completed<br>
 *           strongAuthRequired        (8), -- refused to return sorted results via insecure protocol<br>
 *           adminLimitExceeded       (11), -- too many matching entries for the server to sort<br>
 *           noSuchAttribute          (16), -- unrecognized attribute type in sort key<br>
 *           inappropriateMatching    (18), -- unrecognized or inappropriate matching rule in sort key<br>
 *           insufficientAccessRights (50), -- refused to return sorted results to this client<br>
 *           busy                     (51), -- too busy to process<br>
 *           unwillingToPerform       (53), -- unable to sort<br>
 *           other                    (80)<br>
 *           },<br>
 *       attributeType [0] AttributeDescription OPTIONAL }<br><pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface SortResponseControl extends Control
{
    /** the OID of the response control */
    String OID = "1.2.840.113556.1.4.474";
    
    /**
     * sets the sort result
     * 
     * @param result
     */
    void setSortResult( SortResultCode result );
    
    
    /**
     * @return the sort result
     */
    SortResultCode getSortResult();

    
    /**
     * sets the name of the first offending attribute
     *  
     * @param attributeName
     */
    // didn't name the method setAttribute*Type*
    // cause in our internal terminology AttributeType is a java type
    void setAttributeName( String attributeName );
    
    
    /**
     * @return the name of the first offending attribute
     */
    String getAttributeName();
}
