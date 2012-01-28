package org.apache.directory.shared.ipojo.schema;


import java.util.Dictionary;
import java.util.Hashtable;

import org.apache.directory.shared.ipojo.helpers.IPojoHelper;
import org.apache.directory.shared.ldap.model.schema.LdapComparator;
import org.apache.directory.shared.ldap.model.schema.Normalizer;
import org.apache.directory.shared.ldap.model.schema.SyntaxChecker;
import org.apache.felix.ipojo.ComponentInstance;
import org.apache.felix.ipojo.InstanceManager;


/**
 * Class used to get Schema Elements from IPojo component registry.
 * Schema Elements must be published without specifying component name, which leaves them published
 * with their class name.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SchemaElementsManager
{
    /**
     * Gets {@link LdapComparator} reference by its class name as IPojo component name.
     *
     * @param factoryName Class name of a LdapComparator
     * @param oid OID value to instantiate LdapComparator.
     * @return {@link LdapComparator} reference fetched from IPojo
     * @throws Exception
     */
    public LdapComparator<?> getLdapComparator( String factoryName, String oid ) throws Exception
    {
        Dictionary<String, String> props = new Hashtable<String, String>();
        props.put( "ads.comp.comparator.oid", oid );

        ComponentInstance _comparator = IPojoHelper.createIPojoComponent( factoryName, null, props );
        if ( _comparator == null )
        {
            throw new Exception( "Required Comparator is not registered as IPojo Component" );
        }

        LdapComparator<?> comparator = ( LdapComparator<?> ) ( ( InstanceManager ) _comparator ).getPojoObject();

        return comparator;
    }


    /**
     * Gets {@link Normalizer} reference by its class name as IPojo component name.
     *
     * @param factoryName Class name of a Normalizer
     * @return  {@link Normalizer} reference fetched from IPojo
     * @throws Exception
     */
    public Normalizer getNormalizer( String factoryName ) throws Exception
    {
        ComponentInstance _normalizer = IPojoHelper.createIPojoComponent( factoryName, null, null );

        if ( _normalizer == null )
        {
            throw new Exception( "Required Normalizer is not registered as IPojo Component" );
        }

        Normalizer normalizer = ( Normalizer ) ( ( InstanceManager ) _normalizer ).getPojoObject();

        return normalizer;
    }


    /**
     * Gets {@link SyntaxChecker} reference by its class name as IPojo component name.
     *
     * @param factoryName Class name of a SyntaxChecker
     * @return  {@link SyntaxChecker} reference fetched from IPojo
     * @throws Exception
     */
    public SyntaxChecker getSyntaxChecker( String factoryName ) throws Exception
    {
        ComponentInstance _syntaxer = IPojoHelper.createIPojoComponent( factoryName, null, null );

        if ( _syntaxer == null )
        {
            throw new Exception( "Required Syntax Checker is not registered as IPojo Component" );
        }

        SyntaxChecker syntaxer = ( SyntaxChecker ) ( ( InstanceManager ) _syntaxer ).getPojoObject();

        return syntaxer;
    }
}
