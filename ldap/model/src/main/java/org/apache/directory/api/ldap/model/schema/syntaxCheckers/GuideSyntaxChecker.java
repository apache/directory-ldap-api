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
 * A SyntaxChecker which verifies that a value is a Guide according to RFC 4517.
 * <p>
 * Implemented as binary right now ...
 *  
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class GuideSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of GuideSyntaxChecker
     */
    public static final GuideSyntaxChecker INSTANCE = new GuideSyntaxChecker( SchemaConstants.GUIDE_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final  class Builder extends SCBuilder<GuideSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.GUIDE_SYNTAX );
        }
        
        
        /**
         * Create a new instance of GuideSyntaxChecker
         * @return A new instance of GuideSyntaxChecker
         */
        @Override
        public GuideSyntaxChecker build()
        {
            return new GuideSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of GuideSyntaxChecker
     */
    private GuideSyntaxChecker( String oid )
    {
        super( oid );
    }

    
    /**
     * @return An instance of the Builder for this class
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    public static Builder builder()
    {
        return new Builder();
    }
}
