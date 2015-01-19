package org.apache.directory.ldap.client.api;

/**
 * An interface for defining wrapper objects.  An implementation of this class
 * <b>MUST</b> implement <code>T</code> as well
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface Wrapper<T>
{
    /**
     * Returns the wrapped object.
     *
     * @return The wrapped object
     */
    public T wrapped();
}
