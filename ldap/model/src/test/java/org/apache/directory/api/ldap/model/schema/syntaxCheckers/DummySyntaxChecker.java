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
 * A Dummy SyntaxChecker used for tests
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public class DummySyntaxChecker extends SyntaxChecker
{
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<DummySyntaxChecker>
    {

        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.OCTET_STRING_SYNTAX );
        }


        /**
         * Create a new instance of DummySyntaxChecker
         * @return A new instance of DummySyntaxChecker
         */
        @Override
        public DummySyntaxChecker build()
        {
            return new DummySyntaxChecker( oid );
        }
    }


    /**
     * @return An instance of the Builder for this class
     */
    public static Builder builder()
    {
        return new Builder();
    }


    /**
     * Creates a new instance of DummySyntaxChecker, with a specific OID
     * 
     * @param oid The Syntax's OID 
     */
    private DummySyntaxChecker( String oid )
    {
        super( oid );
    }


    /**
     * {@inheritDoc}
     */
    public boolean isValidSyntax( Object value )
    {
        // Always true.
        return true;
    }
}
