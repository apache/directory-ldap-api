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
 * An immutable interface for SchemaObjects that are class loaded.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface LoadableSchemaObject extends SchemaObject
{
    /**
     * Gets the base64 encoded bytecode associated with this 
     * LoadableSchemaObject.
     * 
     * @return The based64 encoded bytecode of this LoadableSchemaObject 
     * instance
     */
    String getBytecode();


    /**
     * @return The chemaObject instance Fully Qualified Class Name
     */
    String getFqcn();


    /**
     * Test that the FQCN is equal to the instance's name. If the FQCN is
     * empty, fill it with the instance's name
     *
     * @return true if the FQCN is correctly set
     */
    boolean isValid();
}