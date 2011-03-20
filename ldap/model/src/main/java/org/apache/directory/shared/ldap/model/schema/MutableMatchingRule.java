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
 * 
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface MutableMatchingRule extends MutableSchemaObject, MatchingRule
{
    /**
     * Sets the Syntax's OID
     *
     * @param oid The Syntax's OID
     */
    void setSyntaxOid( String oid );


    /**
     * Sets the Syntax
     *
     * @param ldapSyntax The Syntax
     */
    void setSyntax( MutableLdapSyntax ldapSyntax );
    
    
    /**
     * {@inheritDoc}
     */
    MutableLdapSyntax getSyntax();

    
    /**
     * Sets the LdapComparator
     *
     * @param ldapComparator The LdapComparator
     */
    void setLdapComparator( MutableLdapComparator<?> ldapComparator );

    
    /**
     * {@inheritDoc}
     */
    MutableLdapComparator<Object> getLdapComparator();

    
    /**
     * Sets the Normalizer
     *
     * @param normalizer The Normalizer
     */
    void setNormalizer( MutableNormalizer normalizer );

    
    /**
     * {@inheritDoc}
     */
    MutableNormalizer getNormalizer();
    

    /**
     * {@inheritDoc}
     */
    MatchingRule copy();
    
    
    /**
     * {@inheritDoc}
     */
    MutableMatchingRule copyMutable();
}