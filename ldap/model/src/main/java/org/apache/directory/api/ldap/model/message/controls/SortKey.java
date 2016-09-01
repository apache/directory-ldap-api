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
package org.apache.directory.api.ldap.model.message.controls;


/**
 * Datastructure to store the Attribute name, matching rule ID of the attribute<br>
 * and the sort order.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SortKey
{
    /**
     * The name/OID of AttributeType we want to use as a key for the sort
     */
    private String attributeTypeDesc;

    /**
     * The matching rule to use to order the result
     */
    private String matchingRuleId;

    /**
     * A flag to set to true to get the result in reverse order. Default to false
     */
    private boolean reverseOrder = false;


    /**
     * Create a new instance of a SortKey for a give AttributeType
     * 
     * @param attributeTypeDesc The AttributeType's name or OID to use
     */
    public SortKey( String attributeTypeDesc )
    {
        this( attributeTypeDesc, null );
    }


    /**
     * Create a new instance of a SortKey for a give AttributeType
     * 
     * @param attributeTypeDesc The AttributeType's name or OID to use
     * @param matchingRuleId The MatchingRule to use
     */
    public SortKey( String attributeTypeDesc, String matchingRuleId )
    {
        this( attributeTypeDesc, matchingRuleId, false );
    }


    /**
     * Create a new instance of a SortKey for a give AttributeType
     * 
     * @param attributeTypeDesc The AttributeType OID to use
     * @param matchingRuleId The MatchingRule to use
     * @param reverseOrder The reverseOrder flag
     */
    public SortKey( String attributeTypeDesc, String matchingRuleId, boolean reverseOrder )
    {
        this.attributeTypeDesc = attributeTypeDesc;
        this.matchingRuleId = matchingRuleId;
        this.reverseOrder = reverseOrder;
    }


    /**
     * @return the attributeType name or OID
     */
    public String getAttributeTypeDesc()
    {
        return attributeTypeDesc;
    }


    /**
     * @param attributeTypeDesc the attributeType to set
     */
    public void setAttributeTypeDesc( String attributeTypeDesc )
    {
        this.attributeTypeDesc = attributeTypeDesc;
    }


    /**
     * @return the matchingRuleId
     */
    public String getMatchingRuleId()
    {
        return matchingRuleId;
    }


    /**
     * @param matchingRuleId the matchingRuleId to set
     */
    public void setMatchingRuleId( String matchingRuleId )
    {
        this.matchingRuleId = matchingRuleId;
    }


    /**
     * @return the reverseOrder
     */
    public boolean isReverseOrder()
    {
        return reverseOrder;
    }


    /**
     * @param reverseOrder the reverseOrder to set
     */
    public void setReverseOrder( boolean reverseOrder )
    {
        this.reverseOrder = reverseOrder;
    }


    /**
     * @see String#toString()
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "SortKey : [" );

        sb.append( attributeTypeDesc );

        if ( matchingRuleId != null )
        {
            sb.append( ", " ).append( matchingRuleId );
        }

        if ( reverseOrder )
        {
            sb.append( ", reverse" );
        }

        sb.append( ']' );
        return sb.toString();
    }
}
