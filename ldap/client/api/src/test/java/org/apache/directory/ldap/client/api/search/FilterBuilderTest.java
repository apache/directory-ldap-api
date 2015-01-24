package org.apache.directory.ldap.client.api.search;


import static org.apache.directory.ldap.client.api.search.FilterBuilder.and;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.not;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.or;
import static org.junit.Assert.assertEquals;

import org.junit.Test;


public class FilterBuilderTest
{
    @Test
    public void testFilterBuilder()
    {
        assertEquals( "(cn=Babs Jensen)", equal( "cn", "Babs Jensen" ).toString() );
        assertEquals( "(!(cn=Tim Howes))", not( equal( "cn", "Tim Howes" ) ).toString() );
        assertEquals( "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))",
            and( equal( "objectClass", "Person" ),
                or( equal( "sn", "Jensen" ),
                    equal( "cn", "Babs J*" ) ) ).toString() );
        assertEquals( "(o=univ*of*mich*)", equal( "o", "univ*of*mich*" ).toString() );
    }
}
