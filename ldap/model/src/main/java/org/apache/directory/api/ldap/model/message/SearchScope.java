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
package org.apache.directory.api.ldap.model.message;


import org.apache.directory.api.i18n.I18n;


/**
 * A search scope enumerated type.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum SearchScope
{
    /** Base scope */
    OBJECT(0, "base"),
    
    /** One Level scope */
    ONELEVEL(1, "one"),
    
    /** Subtree scope */
    SUBTREE(2, "sub");

    /** 
     * The corresponding LDAP scope constant value as defined in 
     * RFC 4511
     */
    private final int scope;

    /**
     * The LDAP URL string value of either base, one or sub as defined in RFC
     * 2255.
     * 
     * @see <a href="http://www.faqs.org/rfcs/rfc2255.html">RFC 2255</a>
     */
    private final String ldapUrlValue;


    /**
     * Creates a new instance of SearchScope based on the respective 
     * scope constant.
     *
     * @param scope the scope constant
     * @param ldapUrlValue LDAP URL scope string value: base, one, or sub
     */
    SearchScope( int scope, String ldapUrlValue )
    {
        this.scope = scope;
        this.ldapUrlValue = ldapUrlValue;
    }


    /**
     * Gets the LDAP URL value for the scope: according to RFC 2255 this is 
     * either base, one, or sub.
     * 
     * @see <a href="http://www.faqs.org/rfcs/rfc2255.html">RFC 2255</a>
     * 
     * @return the LDAP URL value
     */
    public String getLdapUrlValue()
    {
        return ldapUrlValue;
    }


    /**
     * Gets the corresponding scope constant value as defined in 
     * RFC 4511.
     * 
     * @return the scope
     */
    public int getScope()
    {
        return scope;
    }


    /**
     * Gets the SearchScope enumerated type for the corresponding 
     * scope numeric value.
     *
     * @param scope the numeric value to get SearchScope for
     * @return the SearchScope enumerated type for the scope numeric value
     */
    public static SearchScope getSearchScope( int scope )
    {
        switch ( scope )
        {
            case 0:
                return OBJECT;

            case 1:
                return ONELEVEL;

            case 2:
                return SUBTREE;

            default:
                throw new IllegalArgumentException( I18n.err( I18n.ERR_04160, scope ) );
        }
    }


    /**
     * Gets the SearchScope associated with a scope String
     *
     * @param scope The scope we are looking for
     * @return the scope
     */
    public SearchScope getScope( String scope )
    {
        if ( "base".equalsIgnoreCase( scope ) )
        {
            return OBJECT;
        }
        else if ( "one".equalsIgnoreCase( scope ) )
        {
            return ONELEVEL;
        }
        else if ( "sub".equalsIgnoreCase( scope ) )
        {
            return SUBTREE;
        }
        else
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04161, scope ) );
        }
    }


    /**
     * Gets the SearchScope enumerated type for the corresponding 
     * scope value of either base, one or sub.
     *
     * @param scope the scope value to get SearchScope for
     * @return the SearchScope enumerated type for the LDAP URL scope value
     */
    public static int getSearchScope( String scope )
    {
        if ( "base".equalsIgnoreCase( scope ) )
        {
            return OBJECT.getScope();
        }
        else if ( "one".equalsIgnoreCase( scope ) )
        {
            return ONELEVEL.getScope();
        }
        else if ( "sub".equalsIgnoreCase( scope ) )
        {
            return SUBTREE.getScope();
        }
        else
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04161, scope ) );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return ldapUrlValue;
    }
}
