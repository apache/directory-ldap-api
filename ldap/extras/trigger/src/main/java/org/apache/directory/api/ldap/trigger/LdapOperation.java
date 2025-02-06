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

package org.apache.directory.api.ldap.trigger;


/**
 * An enumeration that represents change inducing LDAP operations.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum LdapOperation
{
    /** The Modify operation */
    MODIFY("Modify"),

    /** The Add operation */
    ADD("Add"),

    /** The Delete operation */
    DELETE("Delete"),

    /** The ModDN operation */
    MODIFYDN("ModifyDN"),

    /** The Rename operation */
    MODIFYDN_RENAME("ModifyDN.Rename"),

    /** The Export operation */
    MODIFYDN_EXPORT("ModifyDN.Export"),

    /** The Import operation */
    MODIFYDN_IMPORT("ModifyDN.Import");

    private final String name;


    /**
     * 
     * Creates a new instance of LdapOperation.
     *
     * @param name The operation name
     */
    LdapOperation( String name )
    {
        this.name = name;
    }


    /**
     * Get the Ldap Operation name
     * 
     * @return the name of this LDAP operation
     */
    public String getName()
    {
        return name;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return name;
    }
}
