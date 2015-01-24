
package org.apache.directory.ldap.client.api.search;

abstract class AbstractFilter implements Filter
{
    @Override
    public StringBuilder build()
    {
        return build( new StringBuilder() );
    }
}
