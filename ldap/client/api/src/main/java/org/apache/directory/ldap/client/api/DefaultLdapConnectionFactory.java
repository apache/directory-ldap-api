package org.apache.directory.ldap.client.api;


import java.io.IOException;

import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class DefaultLdapConnectionFactory implements LdapConnectionFactory
{
    private static Logger LOG = LoggerFactory.getLogger( DefaultLdapConnectionFactory.class );

    private LdapApiService apiService;
    private LdapConnectionConfig connectionConfig;
    private long timeout;


    public DefaultLdapConnectionFactory( LdapConnectionConfig config )
    {
        this.connectionConfig = config;
        this.timeout = config.getDefaultTimeout();
    }


    @Override
    public LdapConnection bindConnection( LdapConnection connection ) throws LdapException
    {
        try
        {
            connection.bind( connectionConfig.getName(), connectionConfig.getCredentials() );
        }
        catch ( LdapException e )
        {
            LOG.error( "unable to bind connection: {}", e.getMessage() );
            LOG.debug( "unable to bind connection:", e );
            try
            {
                connection.close();
            }
            catch ( IOException ioe )
            {
                LOG.error( "unable to close failed bind connection: {}", e.getMessage() );
                LOG.debug( "unable to close failed bind connection:", e );
            }
            throw e;
        }
        return connection;
    }


    @Override
    public LdapConnection configureConnection( LdapConnection connection )
    {
        connection.setTimeOut( timeout );
        connection.setBinaryAttributeDetector( connectionConfig.getBinaryAttributeDetector() );
        return connection;
    }


    @Override
    public LdapConnection newLdapConnection() throws LdapException
    {
        return bindConnection( newUnboundLdapConnection() );
    }


    @Override
    @SuppressWarnings("resource")
    public LdapConnection newUnboundLdapConnection()
    {
        return configureConnection( apiService == null
            ? new LdapNetworkConnection( connectionConfig )
            : new LdapNetworkConnection( connectionConfig, apiService ) );
    }


    /**
     * Sets the LdapApiService (codec) to be used by the connections created
     * by this factory.
     *
     * @param apiService The codec to used by connections created by this 
     * factory
     */
    public void setLdapApiService( LdapApiService apiService )
    {
        this.apiService = apiService;
    }


    /**
     * Sets the timeout that will be used by all connections created by this
     * factory.
     *
     * @param timeout The timeout in millis.
     * 
     * @see LdapConnection#setTimeOut(long)
     */
    public void setTimeOut( long timeout )
    {
        this.timeout = timeout;
    }

}
