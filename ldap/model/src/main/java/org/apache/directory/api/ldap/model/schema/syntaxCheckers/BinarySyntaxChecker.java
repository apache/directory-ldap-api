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
 * A binary value (universal value acceptor) syntax checker.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class BinarySyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of BinarySyntaxChecker
     */
    public static final BinarySyntaxChecker INSTANCE = new BinarySyntaxChecker( SchemaConstants.BINARY_SYNTAX );

    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<BinarySyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.ACCESS_POINT_SYNTAX );
        }
        
        
        /**
         * Create a new instance of BinarySyntaxChecker
         * @return A new instance of BinarySyntaxChecker
         */
        @Override
        public BinarySyntaxChecker build()
        {
            return new BinarySyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of the child class
     * @param oid The child's OID
     */
    private BinarySyntaxChecker( String oid )
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
