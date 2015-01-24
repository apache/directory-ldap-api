
package org.apache.directory.ldap.client.api.search;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class AttributeFilterTest
{
    @Test
    public void testPresent() {
        assertEquals( "(objectClass=*)", AttributeFilter.present( "objectClass" ).build().toString() );
        assertEquals( "(uid=*)", AttributeFilter.present( "uid" ).build().toString() );
        assertEquals( "(userPassword=*)", AttributeFilter.present( "userPassword" ).build().toString() );
        assertEquals( "(cn=*)", AttributeFilter.present( "cn" ).build().toString() );
    }
}
