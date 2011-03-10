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
package org.apache.directory.shared.ldap.model.schema.registries;


import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.schema.MutableSchemaObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Moving some utility methods here to clean up schema interfaces.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class RegistryUtils
{
    /** static class logger */
    private static final Logger LOG = LoggerFactory.getLogger( DefaultSchemaObjectRegistry.class );

    /** A speedup for debug */
    private static final boolean DEBUG = LOG.isDebugEnabled();


    /**
     * Modify all the SchemaObject using a schemaName when this name changes.
     *
     * @param originalSchemaName The original Schema name
     * @param newSchemaName The new Schema name
     * @throws LdapException if the schema object does not exist
     */
    public <T extends MutableSchemaObject> void renameSchema( SchemaObjectRegistry<T> registry, String originalSchemaName, 
        String newSchemaName ) throws LdapException
    {
        // Loop on all the SchemaObjects stored and remove those associated
        // with the give schemaName
        for ( T schemaObject : registry )
        {
            if ( originalSchemaName.equalsIgnoreCase( schemaObject.getSchemaName() ) )
            {
                schemaObject.setSchemaName( newSchemaName );

                if ( DEBUG )
                {
                    LOG.debug( "Renamed {} schemaName to {}", schemaObject, newSchemaName );
                }
            }
        }
    }
}
