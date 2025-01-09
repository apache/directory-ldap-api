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
package org.apache.directory.api.ldap.model.schema.comparators;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.SchemaManager;


/**
 * Compare two DNs
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DnComparator extends LdapComparator<Object>
{
    /** Declares the Serial Version Uid */
     private static final long serialVersionUID = 2L;

    /** A reference to the schema manager */
    private transient SchemaManager schemaManager;

    /**
     * Creates a new instance of DnComparator.
     * 
     * @param oid The Comparator's OID
     */
    public DnComparator( String oid )
    {
        super( oid );
    }


    /**
     * Compare two String DNs
     *  
     * @param dn1 The first DN
     * @param dn2 The second DN
     * 
     * @return -1 i the first DN is inferior to the second DN, 1 if the second DN is superior, 0 of they are equal
     */
    public int compare( String dn1, String dn2 )
    {
        if ( dn1 == null )
        {
            if ( dn2 == null )
            {
                return 0;
            }
            else
            {
                return -1;
            }
        }
        
        return dn1.compareTo( dn2 );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int compare( Object obj0, Object obj1 )
    {
        if ( ( obj0 instanceof String ) && ( obj1 instanceof String ) )
        {
            return compare( ( String ) obj0, ( String ) obj1 );
        }
        
        Dn dn0 = null;
        Dn dn1 = null;

        try
        {
            dn0 = getDn( obj0 );
            dn1 = getDn( obj1 );
        }
        catch ( LdapException e )
        {
            // -- what do we do here ?
            return -1;
        }

        int dn0Size = dn0.getRdns().size();
        int dn1Size = dn1.getRdns().size();
        
        // check the equality first, cause
        // when both DNs are equal checking isAncestorOf() returns true
        if ( dn0.equals( dn1 ) )
        {
            return 0;
        }
        else if ( dn0Size > dn1Size )
        {
            return -1;
        }
        else if ( dn1Size > dn0Size )
        {
            return 1;
        }

        for ( int i = dn0Size - 1; i >= 0; i-- )
        {
            int comp = dn0.getRdn( i ).compareTo( dn1.getRdn( i ) );
            
            if ( comp != 0 )
            {
                return comp;
            }
        }
        
        return 0;
    }


    private Dn getDn( Object obj ) throws LdapInvalidDnException
    {
        Dn dn;

        if ( obj instanceof Dn )
        {
            dn = ( Dn ) obj;

            dn = dn.isSchemaAware() ? dn : new Dn( schemaManager, dn );
        }
        else if ( obj instanceof String )
        {
            dn = new Dn( schemaManager, ( String ) obj );
        }
        else
        {
            throw new IllegalStateException( I18n.err( I18n.ERR_13720_CANNOT_HANDLE_DN_COMPARISONS, obj == null ? null : obj.getClass() ) );
        }

        return dn;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setSchemaManager( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
    }
}
