package org.apache.directory.shared.ipojo.schema;


import java.util.Dictionary;
import java.util.Hashtable;

import org.apache.directory.shared.ipojo.helpers.IPojoHelper;
import org.apache.directory.shared.ldap.model.schema.LdapComparator;
import org.apache.directory.shared.ldap.model.schema.Normalizer;
import org.apache.directory.shared.ldap.model.schema.SyntaxChecker;


public class SchemaElementsManager
{
    public LdapComparator<?> getLdapComparator( String factoryName, String oid ) throws Exception
    {
        Dictionary<String, String> props = new Hashtable<String, String>();
        props.put( "ads.comp.comparator.oid", oid );

        LdapComparator<?> comparator = ( LdapComparator<?> ) IPojoHelper
            .createIPojoComponent( factoryName, null, props );

        if ( comparator == null )
        {
            throw new Exception( "Required Comparator is not registered" );
        }

        return comparator;
    }


    public Normalizer getNormalizer( String factoryName ) throws Exception
    {
        Normalizer normalizer = ( Normalizer ) IPojoHelper
            .createIPojoComponent( factoryName, null, null );

        if ( normalizer == null )
        {
            throw new Exception( "Required Normalizer is not registered" );
        }

        return normalizer;
    }


    public SyntaxChecker getSyntaxChecker( String factoryName ) throws Exception
    {
        SyntaxChecker syntaxer = ( SyntaxChecker ) IPojoHelper
            .createIPojoComponent( factoryName, null, null );

        if ( syntaxer == null )
        {
            throw new Exception( "Required Syntax Checker is not registered" );
        }

        return syntaxer;
    }
}
