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
package org.apache.directory.ldap.client.template.exception;


import org.apache.directory.api.ldap.model.message.ResultResponse;


/**
 * An RuntimeException wrapper class that allows the user to choose to have
 * unsuccessful responses thrown as exceptions rather than checking the 
 * response itself for process flow.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapRequestUnsuccessfulException extends RuntimeException
{
    private static final long serialVersionUID = 1982294624076306127L;

    private final transient ResultResponse response;


    /**
     * Creates a new LdapRequestUnsuccessfulException instance
     * 
     * @param response The associated LDAP Response
     */
    public LdapRequestUnsuccessfulException( ResultResponse response )
    {
        super();
        this.response = response;
    }


    /**
     * @return the associate LDAP Response
     */
    public ResultResponse getResponse()
    {
        return response;
    }

}
