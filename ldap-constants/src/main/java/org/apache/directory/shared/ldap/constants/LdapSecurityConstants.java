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
package org.apache.directory.shared.ldap.constants;


/**
 * An enum to store all the security constants used in the server
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum LdapSecurityConstants
{
    /** The SHA encryption method */
    HASH_METHOD_SHA("sha"),

    /** The Salted SHA encryption method */
    HASH_METHOD_SSHA("ssha"),

    /** The MD5 encryption method */
    HASH_METHOD_MD5("md5"),

    /** The Salter MD5 encryption method */
    HASH_METHOD_SMD5("smd5"),

    /** The crypt encryption method */
    HASH_METHOD_CRYPT("crypt"),

    /** The SHA-256 encryption method */
    HASH_METHOD_SHA256("sha-256");

    /** The associated name */
    private String name;


    /**
     * Creates a new instance of LdapSecurityConstants.
     * 
     * @param name the associated name
     */
    private LdapSecurityConstants( String name )
    {
        this.name = name;
    }


    /**
     * @return the name associated with the constant.
     */
    public String getName()
    {
        return name;
    }


    /**
     * Get the associated constant from a string
     *
     * @param name The algorithm's name
     * @return The associated constant
     */
    public static LdapSecurityConstants getAlgorithm( String name )
    {
        String algorithm = "";

        if ( name != null )
        {
            algorithm = name.toLowerCase();
        }

        if ( HASH_METHOD_SHA.getName().equalsIgnoreCase( algorithm ) )
        {
            return HASH_METHOD_SHA;
        }

        if ( HASH_METHOD_SSHA.getName().equalsIgnoreCase( algorithm ) )
        {
            return HASH_METHOD_SSHA;
        }

        if ( HASH_METHOD_MD5.getName().equalsIgnoreCase( algorithm ) )
        {
            return HASH_METHOD_MD5;
        }

        if ( HASH_METHOD_SMD5.getName().equalsIgnoreCase( algorithm ) )
        {
            return HASH_METHOD_SMD5;
        }

        if ( HASH_METHOD_CRYPT.getName().equalsIgnoreCase( algorithm ) )
        {
            return HASH_METHOD_CRYPT;
        }

        if ( HASH_METHOD_SHA256.getName().equalsIgnoreCase( algorithm ) )
        {
            return HASH_METHOD_SHA256;
        }

        return null;
    }
}
