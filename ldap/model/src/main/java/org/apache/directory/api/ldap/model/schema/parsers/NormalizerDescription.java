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

package org.apache.directory.api.ldap.model.schema.parsers;


import org.apache.directory.api.ldap.model.schema.LoadableSchemaObject;
import org.apache.directory.api.ldap.model.schema.SchemaObjectType;


/**
 * An ApacheDS specific schema description for a Normalizer.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class NormalizerDescription extends LoadableSchemaObject
{
    /** Declares the Serial Version Uid */
    public static final long serialVersionUID = 1L;

    /**
     * Default constructor for a NormalizerDecription
     * @param oid The SyntaxChecker OID
     */
    public NormalizerDescription( String oid )
    {
        super( SchemaObjectType.NORMALIZER, oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return "SyntaxChecker description : " + getDescription();
    }
}
