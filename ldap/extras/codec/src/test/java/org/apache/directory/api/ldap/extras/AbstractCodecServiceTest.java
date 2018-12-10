package org.apache.directory.api.ldap.extras;


import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.junit.AfterClass;
import org.junit.BeforeClass;


/**
 * Initialize the Codec service. This can later be removed.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractCodecServiceTest
{
    protected static LdapApiService codec;


    /**
     * Initialize the codec service
     */
    @BeforeClass
    public static void setupLdapCodecService()
    {
        codec = new DefaultLdapCodecService();
    }


    /**
     * Shutdown the codec service
     */
    @AfterClass
    public static void tearDownLdapCodecService()
    {
        codec = null;
    }
}
