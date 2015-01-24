package org.apache.directory.ldap.client.api.search;


import static org.junit.Assert.assertEquals;

import org.junit.Test;


public class AttributeValueAssertionTest
{
    @Test
    public void testApproximatelyEqual()
    {
        assertEquals( "(objectClass~=person)",
            AttributeValueAssertionFilter.approximatelyEqual( "objectClass", "person" )
                .build().toString() );
        assertEquals( "(uid~=admin)",
            AttributeValueAssertionFilter.approximatelyEqual( "uid", "admin" )
                .build().toString() );
    }
    
    
    @Test
    public void testEqual()
    {
        assertEquals( "(objectClass=person)",
            AttributeValueAssertionFilter.equal( "objectClass", "person" )
                .build().toString() );
        assertEquals( "(uid=admin)",
            AttributeValueAssertionFilter.equal( "uid", "admin" )
                .build().toString() );
        assertEquals( "(cn=lu*)",
            AttributeValueAssertionFilter.equal( "cn", "lu*" )
                .build().toString() );
    }
    
    
    @Test
    public void testGreaterThanOrEqual()
    {
        assertEquals( "(objectClass>=person)",
            AttributeValueAssertionFilter.greaterThanOrEqual( "objectClass", "person" )
                .build().toString() );
        assertEquals( "(uid>=admin)",
            AttributeValueAssertionFilter.greaterThanOrEqual( "uid", "admin" )
                .build().toString() );
    }
    
    
    @Test
    public void testLessThanOrEqual()
    {
        assertEquals( "(objectClass<=person)",
            AttributeValueAssertionFilter.lessThanOrEqual( "objectClass", "person" )
                .build().toString() );
        assertEquals( "(uid<=admin)",
            AttributeValueAssertionFilter.lessThanOrEqual( "uid", "admin" )
                .build().toString() );
    }
}
