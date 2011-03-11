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
package org.apache.directory.shared.ldap.model.schema;


/**
 * A mutable version of the LoadableSchemaObject.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface MutableLoadableSchemaObject extends LoadableSchemaObject
{
    /**
     * Stores some bytecode representing the compiled Java class for this
     * SchemaObject instance.
     * 
     * @param bytecode The bytecode to store
     */
    void setBytecode( String bytecode );


    /**
     * Set the Fully Qualified Class Name for this SchemaObject instance
     * class stored in the bytecode attribute
     * @param fqcn The Fully Qualified Class Name
     */
    void setFqcn( String fqcn );
}