/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.ldap.client.api.search;


import org.apache.directory.api.ldap.model.filter.FilterEncoder;


/**
 * 
 * TODO AttributeValueAssertionFilter.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
/* No qualifier*/class AttributeValueAssertionFilter extends AbstractFilter
{
    private String attribute;
    private String value;
    private Operator operator;


    private AttributeValueAssertionFilter( String attribute, String value, Operator operator )
    {
        this.attribute = attribute;
        this.value = value;
        this.operator = operator;
    }


    public static AttributeValueAssertionFilter approximatelyEqual( String attribute, String value )
    {
        return new AttributeValueAssertionFilter( attribute, value, Operator.APPROXIMATELY_EQUAL );
    }


    public static AttributeValueAssertionFilter equal( String attribute, String value )
    {
        return new AttributeValueAssertionFilter( attribute, value, Operator.EQUAL );
    }


    public static AttributeValueAssertionFilter greaterThanOrEqual( String attribute, String value )
    {
        return new AttributeValueAssertionFilter( attribute, value, Operator.GREATER_THAN_OR_EQUAL );
    }


    public static AttributeValueAssertionFilter lessThanOrEqual( String attribute, String value )
    {
        return new AttributeValueAssertionFilter( attribute, value, Operator.LESS_THAN_OR_EQUAL );
    }


    @Override
    public StringBuilder build( StringBuilder builder )
    {
        return builder.append( "(" ).append( attribute )
            .append( operator.operator() )
            .append( FilterEncoder.encodeFilterValue( value ) ).append( ")" );
    }

    public static enum Operator
    {
        APPROXIMATELY_EQUAL("~="),
        EQUAL("="),
        GREATER_THAN_OR_EQUAL(">="),
        LESS_THAN_OR_EQUAL("<=");

        private String operator;


        private Operator( String operator )
        {
            this.operator = operator;
        }


        public String operator()
        {
            return operator;
        }
    }
}