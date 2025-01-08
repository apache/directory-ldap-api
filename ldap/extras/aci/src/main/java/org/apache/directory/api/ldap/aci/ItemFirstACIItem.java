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
import java.util.Set;

import org.apache.directory.api.ldap.model.constants.AuthenticationLevel;


/**
 * An {@link ACIItem} which specifies {@link ProtectedItem}s first and then
 * {@link UserClass}es each {@link ProtectedItem} will have. (18.4.2.4. X.501)
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ItemFirstACIItem extends ACIItem
{
    /** The list of protected items ( userClasses or userPermissions ) */
    private final Collection<ProtectedItem> protectedItems;

    /** The associated permissions */
    private final Collection<ItemPermission> itemPermissions;


    /**
     * Creates a new instance.
     * 
     * @param identificationTag the id string of this item
     * @param precedence the precedence of this item
     * @param authenticationLevel the level of authentication required to this item
     * @param protectedItems the collection of {@link ProtectedItem}s this item protects
     * @param itemPermissions the collection of {@link ItemPermission}s each <code>protectedItems</code> will have
     */
    public ItemFirstACIItem( String identificationTag, int precedence, AuthenticationLevel authenticationLevel,
        Collection<ProtectedItem> protectedItems, Collection<ItemPermission> itemPermissions )
    {
        super( identificationTag, precedence, authenticationLevel );

        this.protectedItems = Collections.unmodifiableCollection( new ArrayList<ProtectedItem>( protectedItems ) );
        this.itemPermissions = Collections.unmodifiableCollection( new ArrayList<ItemPermission>( itemPermissions ) );
    }


    /**
     * Gets the collection of {@link ProtectedItem}s.
     *
     * @return the collection of {@link ProtectedItem}s
     */
    public Collection<ProtectedItem> getProtectedItems()
    {
        return protectedItems;
    }


    /**
     * Gets the collection of {@link ItemPermission}s.
     *
     * @return the collection of {@link ItemPermission}s
     */
    public Collection<ItemPermission> getItemPermissions()
    {
        return itemPermissions;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder buf = new StringBuilder();

        buf.append( "{" );
        buf.append( super.toString() );

        // itemOrUserFirst
        buf.append( ", itemOrUserFirst itemFirst: { " );

        // protectedItems
        buf.append( "protectedItems { " );

        boolean isFirst = true;

        for ( ProtectedItem item : protectedItems )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                buf.append( ", " );
            }

            buf.append( item.toString() );
        }

        // itemPermissions
        buf.append( " }, itemPermissions { " );

        isFirst = true;

        for ( ItemPermission permission : itemPermissions )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                buf.append( ", " );
            }

            buf.append( permission.toString() );
        }

        buf.append( " } } }" );

        return buf.toString();
    }


    /**
     * Transform this protected Item and permissions to a set of Tuples
     * 
     * @return The list of created Tuples
     */
    @Override
    public Collection<ACITuple> toTuples()
    {
        Collection<ACITuple> tuples = new ArrayList<>();

        for ( ItemPermission itemPermission : itemPermissions )
        {
            Set<GrantAndDenial> grants = itemPermission.getGrants();
            Set<GrantAndDenial> denials = itemPermission.getDenials();
            int precedence = itemPermission.getPrecedence() != null
                ? itemPermission.getPrecedence()
                : this.getPrecedence();

            if ( !grants.isEmpty() )
            {
                tuples.add( new ACITuple( itemPermission.getUserClasses(), getAuthenticationLevel(), protectedItems,
                    toMicroOperations( grants ), true, precedence ) );
            }

            if ( !denials.isEmpty() )
            {
                tuples.add( new ACITuple( itemPermission.getUserClasses(), getAuthenticationLevel(), protectedItems,
                    toMicroOperations( denials ), false, precedence ) );
            }
        }

        return tuples;
    }
}
