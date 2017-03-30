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
 * A SyntaxChecker which verifies that a value is a 
 * MasterAndShadowAccessPoint.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class MasterAndShadowAccessPointSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of MasterAndShadowAccessPointSyntaxChecker
     */
    public static final MasterAndShadowAccessPointSyntaxChecker INSTANCE = 
        new MasterAndShadowAccessPointSyntaxChecker( SchemaConstants.MASTER_AND_SHADOW_ACCESS_POINTS_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<MasterAndShadowAccessPointSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.MASTER_AND_SHADOW_ACCESS_POINTS_SYNTAX );
        }
        
        
        /**
         * Create a new instance of MasterAndShadowAccessPointSyntaxChecker
         * @return A new instance of MasterAndShadowAccessPointSyntaxChecker
         */
        @Override
        public MasterAndShadowAccessPointSyntaxChecker build()
        {
            return new MasterAndShadowAccessPointSyntaxChecker( oid );
        }
    }

    
    /**
     * Create a new instance of MasterAndShadowAccessPointSyntaxChecker
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private MasterAndShadowAccessPointSyntaxChecker( String oid )
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
