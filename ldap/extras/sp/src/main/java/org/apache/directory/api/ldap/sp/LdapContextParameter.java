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

package org.apache.directory.api.ldap.sp;


import java.io.Serializable;


/**
 * A class for representing the special SP parameter: $ldapContext.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapContextParameter implements Serializable
{
    /** Serial UUID */
    private static final long serialVersionUID = -8703671542595407603L;

    /** The parameter name */
    private String name;


    /**
     * Creates a new LdapContextParameter instance
     * 
     * @param name The parameter name
     */
    public LdapContextParameter( String name )
    {
        this.name = name;
    }


    /**
     * get the parameter's value
     * 
     * @return The parameter's name
     */
    public String getValue()
    {
        return name;
    }
}
