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


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A SyntaxChecker which verifies that a value is a SupportedAlgorithm according to RFC 2252.
 * <p>
 * It has been removed in RFC 4517
 *  
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public class SupportedAlgorithmSyntaxChecker extends BinarySyntaxChecker
{
    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( SupportedAlgorithmSyntaxChecker.class );
    
    /**
     * A static instance of SupportedAlgorithmSyntaxChecker
     */
    public static final SupportedAlgorithmSyntaxChecker INSTANCE = new SupportedAlgorithmSyntaxChecker();

    
    /**
     * Creates a new instance of SupportedAlgorithmSyntaxChecker.
     */
    public SupportedAlgorithmSyntaxChecker()
    {
        super( SchemaConstants.SUPPORTED_ALGORITHM_SYNTAX );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isValidSyntax( Object value )
    {
        LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
        return true;
    }
}
