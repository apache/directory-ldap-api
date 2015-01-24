package org.apache.directory.ldap.client.api.search;


import static org.junit.Assert.assertEquals;

import org.junit.Test;


public class UnaryFilterTest
{
    @Test
    public void testNot()
    {
        AttributeFilter attributeFilter = AttributeFilter.present( "objectClass" );
        assertEquals( "(!" + attributeFilter.build().toString() + ")",
            UnaryFilter.not( attributeFilter ).build().toString() );
        assertEquals( "(!" + attributeFilter.build().toString() + ")",
            UnaryFilter.not().setFilter( attributeFilter ).build().toString() );

        AttributeValueAssertionFilter attributeValueAssertionFilter =
            AttributeValueAssertionFilter.equal( "objectClass", "person" );
        assertEquals( "(!" + attributeValueAssertionFilter.build().toString() + ")",
            UnaryFilter.not( attributeValueAssertionFilter ).build().toString() );
        assertEquals( "(!" + attributeValueAssertionFilter.build().toString() + ")",
            UnaryFilter.not().setFilter( attributeValueAssertionFilter ).build().toString() );
    }
}
