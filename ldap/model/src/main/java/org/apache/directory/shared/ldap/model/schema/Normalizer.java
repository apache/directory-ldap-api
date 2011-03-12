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
package org.apache.directory.shared.ldap.model.schema;


import org.apache.directory.shared.ldap.model.entry.Value;
import org.apache.directory.shared.ldap.model.exception.LdapException;


public interface Normalizer extends LoadableSchemaObject
{
    /**
     * Gets the normalized value.
     * 
     * @param value the value to normalize. It must *not* be null !
     * @return the normalized form for a value
     * @throws LdapException if an error results during normalization
     */
    Value<?> normalize( Value<?> value ) throws LdapException;


    /**
     * Gets the normalized value.
     * 
     * @param value the value to normalize. It must *not* be null !
     * @return the normalized form for a value
     * @throws LdapException if an error results during normalization
     */
    String normalize( String value ) throws LdapException;
    
    
    /**
     * {@inheritDoc}
     */
    Normalizer copy();
}