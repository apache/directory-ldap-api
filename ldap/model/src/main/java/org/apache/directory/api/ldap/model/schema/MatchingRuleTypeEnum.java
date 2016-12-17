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
package org.apache.directory.api.ldap.model.schema;

/**
 * This Enum is used to list the MatchingRules that will be subject to a PrepareString.
 * 
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum MatchingRuleTypeEnum
{
    // The EQUALITY matching rules
    /** Case Exact Match */
    CASE_EXACT_MATCH( "2.5.13.5" ),
    
    /** Case Exact IA5 Match */
    CASE_EXACT_IA5_MATCH( "1.3.6.1.4.1.1466.109.114.1" ),

    /** Case Ignore Match */
    CASE_IGNORE_IA5_MATCH( "1.3.6.1.4.1.1466.109.114.2" ),

    /** Case Ignore List Match */
    CASE_IGNORE_LIST_MATCH( "2.5.13.11" ),
    
    /** Case Ignore Match */
    CASE_IGNORE_MATCH( "2.5.13.2" ),
    
    /** DirectoryString First Component Match */
    DIRECTORY_STRING_FIRST_COMPONENT_MATCH( "2.5.13.31" ),
    
    /** Numeric String Match */
    NUMERIC_STRING_MATCH( "2.5.13.8" ),

    /** Telephone Number Match */
    TELEPHONE_NUMBER_MATCH( "2.5.13.20" ),
    
    /** Word Match */
    WORD_MATCH( "2.5.13.32" ),

    // The ORDERING matching rules
    /** Case Exact Ordering Match */
    CASE_EXACT_ORDERING_MATCH( "2.5.13.6" ),

    /** Case Ignore Ordering Match */
    CASE_IGNORE_ORDERING_MATCH( "2.5.13.3" ),

    /** Numeric String Ordering Match */
    NUMERIC_STRING_ORDERING_MATCH( "2.5.13.9" ),

    // The SUBSTRING matching rules
    /** Case Exact Substring Match */
    CASE_EXACT_SUBSTRINGS_MATCH( "2.5.13.7" ),
    
    /** Case Ignore IA5 Substring Match */
    CASE_IGNORE_IA5_SUBSTRINGS_MATCH( "1.3.6.1.4.1.1466.109.114.3" ),
    
    /** Case Ignore List Substring Match */
    CASE_IGNORE_LIST_SUBSTRINGS_MATCH( "2.5.13.12" ),
    
    /** CaseIgnore Substring Match */
    CASE_IGNORE_SUBSTRINGS_MATCH( "2.5.13.4" ),
    
    /** Numeric String Substring Match */
    NUMERIC_STRING_SUBSTRINGS_MATCH( "2.5.13.10" ),
    
    /** Telephone Number Substring Match */
    TELEPHONE_NUMBER_SUBSTRINGS_MATCH( "2.5.13.21" );

    /** The interned MR OID */
    private String oid;
    
    /**
     * Create an instance of MatchingRuleTypeEnum
     */
    MatchingRuleTypeEnum( String oid )
    {
        this.oid = oid;
    }
    
    
    /**
     * Get the MatchingRuleTypeEnum associated with an OID
     * 
     * @param oid The OID for which we want the MatchingRuleTypeEnum.
     * @return The MatchingRuleTypeEnum we found, or null.
     */
    public static MatchingRuleTypeEnum getMatchingRuleType( String oid )
    {
        if ( CASE_EXACT_MATCH.oid.equals( oid ) )
        {
            return CASE_EXACT_MATCH;
        }
        
        if ( CASE_EXACT_IA5_MATCH.oid.equals( oid ) )
        {
            return CASE_EXACT_IA5_MATCH;
        }
        
        if ( CASE_IGNORE_IA5_MATCH.oid.equals( oid ) )
        {
            return CASE_IGNORE_IA5_MATCH;
        }
        
        if ( CASE_IGNORE_LIST_MATCH.oid.equals( oid ) )
        {
            return CASE_IGNORE_LIST_MATCH;
        }
        
        if ( CASE_IGNORE_MATCH.oid.equals( oid ) )
        {
            return CASE_IGNORE_MATCH;
        }
        
        if ( DIRECTORY_STRING_FIRST_COMPONENT_MATCH.oid.equals( oid ) )
        {
            return DIRECTORY_STRING_FIRST_COMPONENT_MATCH;
        }
        
        if ( NUMERIC_STRING_MATCH.oid.equals( oid ) )
        {
            return NUMERIC_STRING_MATCH;
        }
        
        if ( TELEPHONE_NUMBER_MATCH.oid.equals( oid ) )
        {
            return TELEPHONE_NUMBER_MATCH;
        }
        
        if ( WORD_MATCH.oid.equals( oid ) )
        {
            return WORD_MATCH;
        }
        
        return null;
    }
}
