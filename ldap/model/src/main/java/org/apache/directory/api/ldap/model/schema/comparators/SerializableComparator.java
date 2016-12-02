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
package org.apache.directory.api.ldap.model.schema.comparators;


import java.io.Serializable;
import java.util.Comparator;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.SchemaManager;


/**
 * A serializable wrapper around a Comparator which uses delayed initialization
 * of the underlying wrapped comparator which is JIT resolved from a static
 * global registry.
 * 
 * @param <E> The type of object to compare
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SerializableComparator<E> extends LdapComparator<E> implements Serializable
{
    /** The serial version UID */
    private static final long serialVersionUID = 2L;

    /** the OID of the matchingRule for this comparator */
    private String matchingRuleOid;

    /** the transient wrapped comparator */
    private transient Comparator<E> wrapped;

    /** A reference to the schema manager */
    private transient SchemaManager schemaManager;


    /**
     * Creates a new instance of SerializableComparator.
     *
     * @param matchingRuleOid The MatchingRule OID
     */
    public SerializableComparator( String matchingRuleOid )
    {
        super( matchingRuleOid );
        this.matchingRuleOid = matchingRuleOid;
    }


    // ------------------------------------------------------------------------
    // C O M P A R A T O R   I M P L E M E N T A T I O N S
    // ------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    @Override
    public int compare( E o1, E o2 )
    {
        if ( wrapped == null )
        {
            try
            {
                wrapped = ( Comparator<E> ) schemaManager.lookupComparatorRegistry( matchingRuleOid );
            }
            catch ( LdapException le )
            {
                throw new RuntimeException( I18n.err( I18n.ERR_04221, matchingRuleOid ), le );
            }
        }

        return wrapped.compare( o1, o2 );
    }


    /**
     * @param schemaManager the schemaManager to set
     */
    @SuppressWarnings("unchecked")
    @Override
    public void setSchemaManager( SchemaManager schemaManager )
    {
        if ( wrapped == null )
        {
            try
            {
                wrapped = ( Comparator<E> )
                    schemaManager.lookupComparatorRegistry( matchingRuleOid );
            }
            catch ( LdapException ne )
            {
                // Not found : get the default comparator
                wrapped = ( Comparator<E> )
                    new ComparableComparator<>( matchingRuleOid );
            }
        }

        ( ( LdapComparator<E> ) wrapped ).setSchemaManager( schemaManager );
        this.schemaManager = schemaManager;
    }
}
