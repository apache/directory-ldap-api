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


/**
 * Represents permissions to be applied to all {@link ProtectedItem}s in
 * {@link ItemFirstACIItem}.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ItemPermission extends Permission
{
    /** The user classes. */
    private final Collection<UserClass> userClasses;


    /**
     * Creates a new instance
     * 
     * @param precedence the precedence of this permission (<code>-1</code> to use the
     *         default)
     * @param grantsAndDenials the collection of {@link GrantAndDenial}s
     * @param userClasses the collection of {@link UserClass}es
     */
    public ItemPermission( Integer precedence, Collection<GrantAndDenial> grantsAndDenials,
        Collection<UserClass> userClasses )
    {
        super( precedence, grantsAndDenials );

        this.userClasses = Collections.unmodifiableCollection( new ArrayList<UserClass>( userClasses ) );
    }


    /**
     * Gets the collection of {@link UserClass}es.
     *
     * @return the collection of {@link UserClass}es
     */
    public Collection<UserClass> getUserClasses()
    {
        return userClasses;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder buffer = new StringBuilder();

        buffer.append( "{ " );

        if ( getPrecedence() != null )
        {
            buffer.append( "precedence " );
            buffer.append( getPrecedence() );
            buffer.append( ", " );
        }

        buffer.append( "userClasses { " );

        boolean isFirst = true;

        for ( UserClass userClass : userClasses )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                buffer.append( ", " );
            }

            buffer.append( userClass.toString() );
        }

        buffer.append( " }, grantsAndDenials { " );

        isFirst = true;

        for ( GrantAndDenial grantAndDenial : getGrantsAndDenials() )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                buffer.append( ", " );
            }

            buffer.append( grantAndDenial.toString() );
        }

        buffer.append( " } }" );

        return buffer.toString();
    }
}
