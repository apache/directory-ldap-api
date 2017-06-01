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

package org.apache.directory.api.ldap.model.ldif.anonymizer;


import java.util.Map;
import java.util.Set;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.schema.SchemaManager;


/**
 * An interface for Anonymizers.
 * 
 * @param <K> The type of object that will be anonymized
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface Anonymizer<K>
{
    /**
     * Take an attribute and its value, anonymizing all of them.
     * 
     * @param valueMap The existing map of value to the associated anonymized counterpart
     * @param valueSet The existing set of anonymized counterpart
     * @param attribute The attribute to anonymize
     * @return The anonymized attribute
     */
    Attribute anonymize( Map<Value<K>, Value<K>> valueMap, Set<Value<K>> valueSet, Attribute attribute );
    
    
    /**
     * Inject a SchemaManager instance in this Anonymizer
     *
     * @param schemaManager The SchemaManager instance
     */
    void setSchemaManager( SchemaManager schemaManager );
    
    
    /**
     * Set the list of existing anonymizers
     *
     * @param attributeAnonymizers The list of existing anonymizers
     */
    void setAnonymizers( Map<String, Anonymizer<K>> attributeAnonymizers );
    
    
    /**
     * @return The latest String anonymized value map
     */
    Map<Integer, String> getLatestStringMap();
    
    
    /**
     * @param latestStringMap The latest String anonymized value map
     */
    void setLatestStringMap( Map<Integer, String> latestStringMap );
    
    
    /**
     * @return The latest byte[] anonymized value map
     */
    Map<Integer, byte[]> getLatestBytesMap();
    
    
    /**
     * @param latestBytesMap The latest byte[] anonymized value map
     */
    void setLatestBytesMap( Map<Integer, byte[]> latestBytesMap );
}
