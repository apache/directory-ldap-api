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
package org.apache.directory.api.ldap.model.schema.syntaxCheckers;


import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;


/**
 * A SyntaxChecker which verifies that a value is a supplier and consumer according to RFC 2252.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class SupplierAndConsumerSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of SupplierAndConsumerSyntaxChecker
     */
    public static final SupplierAndConsumerSyntaxChecker INSTANCE = 
        new SupplierAndConsumerSyntaxChecker( SchemaConstants.SUPPLIER_AND_CONSUMER_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<SupplierAndConsumerSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.SUPPLIER_AND_CONSUMER_SYNTAX );
        }
        
        
        /**
         * Create a new instance of SupplierAndConsumerSyntaxChecker
         * @return A new instance of SupplierAndConsumerSyntaxChecker
         */
        @Override
        public SupplierAndConsumerSyntaxChecker build()
        {
            return new SupplierAndConsumerSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates an instance of SupplierAndConsumerSyntaxChecker
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private SupplierAndConsumerSyntaxChecker( String oid )
    {
        super( oid );
    }

    
    /**
     * @return An instance of the Builder for this class
     */
    public static Builder builder()
    {
        return new Builder();
    }
}
