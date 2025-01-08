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
package org.apache.directory.api.ldap.aci;


import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;


/**
 * A flatten entity which is converted from an {@link ACIItem}. The tuples are
 * accepted by ACDF (Access Control Decision Function, 18.8, X.501)
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ACITuple
{
    /** The collection of {@link UserClass}es this tuple relates to **/
    private final Collection<UserClass> userClasses;

    /** The level of authentication required */
    private final AuthenticationLevel authenticationLevel;

    /** The collection of {@link ProtectedItem}s this tuple relates */
    private final Collection<ProtectedItem> protectedItems;

    /** The set of {@link MicroOperation}s this tuple relates */
    private final Set<MicroOperation> microOperations;

    /** Tells if this tuple grant some access */
    private final boolean grant;

    /** The precedence for this tuple */
    private final Integer precedence;


    /**
     * Creates a new instance.
     * 
     * @param userClasses the collection of {@link UserClass}es this tuple relates to
     * @param authenticationLevel the level of authentication required
     * @param protectedItems the collection of {@link ProtectedItem}s this tuple relates
     * @param microOperations the collection of {@link MicroOperation}s this tuple relates
     * @param grant <code>true</code> if and only if this tuple grants an access
     * @param precedence the precedence of this tuple (<code>0</code>-<code>255</code>)
     */
    public ACITuple(
        Collection<UserClass> userClasses,
        AuthenticationLevel authenticationLevel,
        Collection<ProtectedItem> protectedItems,
        Collection<MicroOperation> microOperations,
        boolean grant,
        Integer precedence )
    {
        if ( authenticationLevel == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_07003_NULL_AUTHENTICATION_LEVEL ) );
        }

        if ( precedence < 0 || precedence > 255 )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_07002_BAD_PRECENDENCE, precedence ) );
        }

        this.userClasses = Collections.unmodifiableCollection( new ArrayList<UserClass>( userClasses ) );
        this.authenticationLevel = authenticationLevel;
        this.protectedItems = Collections.unmodifiableCollection( new ArrayList<ProtectedItem>( protectedItems ) );
        this.microOperations = Collections.unmodifiableSet( new HashSet<MicroOperation>( microOperations ) );
        this.grant = grant;
        this.precedence = precedence;
    }


    /**
     * Gets the collection of {@link UserClass}es this tuple relates to.
     *
     * @return the collection of {@link UserClass}es
     */
    public Collection<UserClass> getUserClasses()
    {
        return userClasses;
    }


    /**
     * Gets the level of authentication required.
     *
     * @return the authentication level
     */
    public AuthenticationLevel getAuthenticationLevel()
    {
        return authenticationLevel;
    }


    /**
     * Gets the collection of {@link ProtectedItem}s this tuple relates.
     *
     * @return the collection of {@link ProtectedItem}s
     */
    public Collection<ProtectedItem> getProtectedItems()
    {
        return protectedItems;
    }


    /**
     * Gets the collection of {@link MicroOperation}s this tuple relates.
     *
     * @return the collection of {@link MicroOperation}s
     */
    public Collection<MicroOperation> getMicroOperations()
    {
        return microOperations;
    }


    /**
     * Gets <code>true</code> if and only if this tuple grants an access.
     *
     * @return <code>true</code> if and only if this tuple grants an access
     */
    public boolean isGrant()
    {
        return grant;
    }


    /**
     * Gets the precedence of this tuple (<code>0</code>-<code>255</code>).
     *
     * @return the precedence
     */
    public Integer getPrecedence()
    {
        return precedence;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return "ACITuple: userClasses=" + userClasses + ", " + "authenticationLevel=" + authenticationLevel + ", "
            + "protectedItems=" + protectedItems + ", " + ( grant ? "grants=" : "denials=" ) + microOperations + ", "
            + "precedence=" + precedence;
    }
}
