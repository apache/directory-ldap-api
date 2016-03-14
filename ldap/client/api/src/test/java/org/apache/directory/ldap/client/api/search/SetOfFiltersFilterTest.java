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


import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Test;


/**
 * 
 * TODO SetOfFiltersFilterTest.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SetOfFiltersFilterTest
{
    private String expected( FilterOperator operator, Filter... filters )
    {
        StringBuilder builder = new StringBuilder( "(" )
            .append( operator.operator() );

        for ( Filter filter : filters )
        {
            filter.build( builder );
        }

        return builder.append( ")" ).toString();
    }


    @Test
    public void testAnd()
    {
        AttributeDescriptionFilter attributeFilter = AttributeDescriptionFilter.present( "objectClass" );
        AttributeValueAssertionFilter attributeValueAssertionFilter =
            AttributeValueAssertionFilter.equal( "objectClass", "person" );
        String expected = expected( FilterOperator.AND, attributeFilter, attributeValueAssertionFilter );

        assertEquals( expected,
            SetOfFiltersFilter.and( attributeFilter, attributeValueAssertionFilter )
                .build().toString() );

        assertEquals( expected,
            SetOfFiltersFilter.and()
                .add( attributeFilter )
                .add( attributeValueAssertionFilter )
                .build().toString() );

        assertEquals( expected,
            SetOfFiltersFilter.and()
                .addAll( attributeFilter, attributeValueAssertionFilter )
                .build().toString() );

        assertEquals( expected,
            SetOfFiltersFilter.and()
                .addAll( Arrays.asList( ( Filter ) attributeFilter, ( Filter ) attributeValueAssertionFilter ) )
                .build().toString() );
    }


    @Test
    public void testOr()
    {
        AttributeDescriptionFilter attributeFilter = AttributeDescriptionFilter.present( "objectClass" );
        AttributeValueAssertionFilter attributeValueAssertionFilter =
            AttributeValueAssertionFilter.equal( "objectClass", "person" );
        String expected = expected( FilterOperator.OR, attributeFilter, attributeValueAssertionFilter );

        assertEquals( expected,
            SetOfFiltersFilter.or( attributeFilter, attributeValueAssertionFilter )
                .build().toString() );

        assertEquals( expected,
            SetOfFiltersFilter.or()
                .add( attributeFilter )
                .add( attributeValueAssertionFilter )
                .build().toString() );

        assertEquals( expected,
            SetOfFiltersFilter.or()
                .addAll( attributeFilter, attributeValueAssertionFilter )
                .build().toString() );

        assertEquals( expected,
            SetOfFiltersFilter.or()
                .addAll( Arrays.asList( ( Filter ) attributeFilter, ( Filter ) attributeValueAssertionFilter ) )
                .build().toString() );
    }
}
