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
 * A SyntaxChecker which verifies that a value is a PresentationAddressSyntax.
 * <p>
 * This syntax is defined in RFC 1278, but it has not been implemented.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class PresentationAddressSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of PresentationAddressSyntaxChecker
     */
    public static final PresentationAddressSyntaxChecker INSTANCE = 
        new PresentationAddressSyntaxChecker( SchemaConstants.PRESENTATION_ADDRESS_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<PresentationAddressSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.PRESENTATION_ADDRESS_SYNTAX );
        }
        
        
        /**
         * Create a new instance of PresentationAddressSyntaxChecker
         * @return A new instance of PresentationAddressSyntaxChecker
         */
        @Override
        public PresentationAddressSyntaxChecker build()
        {
            return new PresentationAddressSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates an instance of PresentationAddressSyntaxChecker
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private PresentationAddressSyntaxChecker( String oid )
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
