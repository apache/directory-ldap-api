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
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.SchemaManager;


/**
 * A comparator that sorts OIDs based on their numeric id value.  Needs a 
 * OidRegistry to properly do it's job.  Public method to set the oid 
 * registry will be used by the server after instantiation in deserialization.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class UniqueMemberComparator extends LdapComparator<String>
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 2L;

    /** A reference to the schema manager */
    private transient SchemaManager schemaManager;
    
    /** A DN comparator instance */
    private transient ParsedDnComparator dnComparator = new ParsedDnComparator( SchemaConstants.ENTRY_DN_AT_OID );

    /**
     * The IntegerComparator constructor. Its OID is the IntegerOrderingMatch matching
     * rule OID.
     * 
     * @param oid The Comparator's OID
     */
    public UniqueMemberComparator( String oid )
    {
        super( oid );
    }


    /**
     * {@inheritDoc}
     */
    public int compare( String dnstr1, String dnstr2 )
    {
        int dash1 = dnstr1.lastIndexOf( '#' );
        int dash2 = dnstr2.lastIndexOf( '#' );

        if ( ( dash1 == -1 ) && ( dash2 == -1 ) )
        {
            // no UID part
            try
            {
                Dn dn1 = getDn( dnstr1 );
                Dn dn2 = getDn( dnstr2 );

                return dnComparator.compare( dn1, dn2 );
            }
            catch ( LdapInvalidDnException ne )
            {
                return -1;
            }
        }
        else
        {
            // Now, check that we don't have another '#'
            if ( dnstr1.indexOf( '#' ) != dash1 )
            {
                // Yes, we have one : this is not allowed, it should have been
                // escaped.
                return -1;
            }

            if ( dnstr2.indexOf( '#' ) != dash1 )
            {
                // Yes, we have one : this is not allowed, it should have been
                // escaped.
                return 1;
            }

            Dn dn1;
            Dn dn2;

            // This is an UID if the '#' is immediatly
            // followed by a BitString, except if the '#' is
            // on the last position
            String uid1 = dnstr1.substring( dash1 + 1 );

            if ( dash1 > 0 )
            {
                try
                {
                    dn1 = new Dn( dnstr1.substring( 0, dash1 ) );
                }
                catch ( LdapException ne )
                {
                    return -1;
                }
            }
            else
            {
                return -1;
            }

            // This is an UID if the '#' is immediately
            // followed by a BitString, except if the '#' is
            // on the last position
            String uid2 = dnstr2.substring( dash2 + 1 );

            if ( dash2 > 0 )
            {
                try
                {
                    dn2 = new Dn( dnstr1.substring( 0, dash2 ) );
                }
                catch ( LdapException ne )
                {
                    return 1;
                }
            }
            else
            {
                return 1;
            }

            int dnResult = dnComparator.compare( dn1, dn2 );
            
            if ( dnResult == 0 )
            {
                return uid1.compareTo( uid2 );
            }

            return dnResult;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setSchemaManager( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
    }


    /**
     * Get the DN from the given object
     *
     * @param obj The object containing a DN (either as an instance of Dn or as a String)
     * @return A Dn instance
     * @throws LdapInvalidDnException If the Dn is invalid
     */
    public Dn getDn( Object obj ) throws LdapInvalidDnException
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
}
