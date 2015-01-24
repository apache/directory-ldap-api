package org.apache.directory.ldap.client.api.search;


import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.junit.Test;


public class SetOfFiltersFilterTest
{
    private String expected( SetOfFiltersFilter.Operator operator, Filter... filters )
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
        AttributeFilter attributeFilter = AttributeFilter.present( "objectClass" );
        AttributeValueAssertionFilter attributeValueAssertionFilter =
            AttributeValueAssertionFilter.equal( "objectClass", "person" );
        String expected = expected( SetOfFiltersFilter.Operator.AND, attributeFilter, attributeValueAssertionFilter );

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
        AttributeFilter attributeFilter = AttributeFilter.present( "objectClass" );
        AttributeValueAssertionFilter attributeValueAssertionFilter =
            AttributeValueAssertionFilter.equal( "objectClass", "person" );
        String expected = expected( SetOfFiltersFilter.Operator.OR, attributeFilter, attributeValueAssertionFilter );

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
