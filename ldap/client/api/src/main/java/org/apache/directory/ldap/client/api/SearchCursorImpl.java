/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.ldap.client.api;


import java.io.IOException;
import java.util.concurrent.TimeUnit;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.Loggers;
import org.apache.directory.api.ldap.model.cursor.AbstractCursor;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.InvalidCursorPositionException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapReferralException;
import org.apache.directory.api.ldap.model.message.IntermediateResponse;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchResultReference;
import org.apache.directory.ldap.client.api.exception.LdapConnectionTimeOutException;
import org.apache.directory.ldap.client.api.future.SearchFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An implementation of Cursor based on the underlying SearchFuture instance.
 * 
 * Note: This is a forward only cursor hence the only valid operations are next(), get() and close() 
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SearchCursorImpl extends AbstractCursor<Response> implements SearchCursor
{
    /** A dedicated log for cursors */
    private static final Logger LOG_CURSOR = LoggerFactory.getLogger( Loggers.CURSOR_LOG.getName() );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = LOG_CURSOR.isDebugEnabled();

    /** the search future */
    private SearchFuture future;

    /** wait time while polling for a SearchResponse */
    private long timeout;

    /** time units of timeout value */
    private TimeUnit timeUnit;

    /** a reference to hold the retrieved SearchResponse object from SearchFuture */
    private Response response;

    /** the done flag */
    private boolean done;

    /** a reference to hold the SearchResultDone response */
    private SearchResultDone searchDoneResp;


    /**
     * Instantiates a new search cursor.
     *
     * @param future the future
     * @param timeout the timeout
     * @param timeUnit the time unit
     */
    public SearchCursorImpl( SearchFuture future, long timeout, TimeUnit timeUnit )
    {
        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( "Creating SearchCursorImpl {}", this );
        }

        this.future = future;
        this.timeout = timeout;
        this.timeUnit = timeUnit;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean next() throws LdapException, CursorException
    {
        if ( done )
        {
            return false;
        }

        try
        {
            if ( future.isCancelled() )
            {
                response = null;
                done = true;
                return false;
            }

            response = future.get( timeout, timeUnit );
        }
        catch ( Exception e )
        {
            LdapException ldapException = new LdapException( LdapNetworkConnection.NO_RESPONSE_ERROR, e );

            // Send an abandon request
            if ( !future.isCancelled() )
            {
                future.cancel( true );
            }

            // close the cursor
            try 
            {
                close( ldapException );
            }
            catch ( IOException ioe )
            {
                throw new LdapException( ioe.getMessage(), ioe );
            }

            throw ldapException;
        }

        if ( response == null )
        {
            future.cancel( true );

            throw new LdapConnectionTimeOutException( LdapNetworkConnection.TIME_OUT_ERROR );
        }

        done = response instanceof SearchResultDone;

        if ( done )
        {
            searchDoneResp = ( SearchResultDone ) response;

            response = null;
        }

        return !done;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Response get() throws InvalidCursorPositionException
    {
        if ( !available() )
        {
            throw new InvalidCursorPositionException();
        }

        return response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchResultDone getSearchResultDone()
    {
        return searchDoneResp;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean available()
    {
        return response != null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException
    {
        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( "Closing SearchCursorImpl {}", this );
        }

        close( null );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void close( Exception cause ) throws IOException
    {
        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( "Closing SearchCursorImpl {}", this );
        }

        if ( done )
        {
            super.close();
            return;
        }

        if ( !future.isCancelled() )
        {
            future.cancel( true );
        }

        if ( cause != null )
        {
            super.close( cause );
        }
        else
        {
            super.close();
        }
    }


    // rest of all operations will throw UnsupportedOperationException

    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    @Override
    public void after( Response element ) throws LdapException, CursorException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "after( Response element )" ) ) );
    }


    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    @Override
    public void afterLast() throws LdapException, CursorException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "afterLast()" ) ) );
    }


    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    @Override
    public void before( Response element ) throws LdapException, CursorException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "before( Response element )" ) ) );
    }


    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    @Override
    public void beforeFirst() throws LdapException, CursorException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "beforeFirst()" ) ) );
    }


    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    @Override
    public boolean first() throws LdapException, CursorException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "first()" ) ) );
    }


    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    @Override
    public boolean last() throws LdapException, CursorException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "last()" ) ) );
    }


    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    @Override
    public boolean previous() throws LdapException, CursorException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "previous()" ) ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isDone()
    {
        return done;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isReferral()
    {
        return response instanceof SearchResultReference;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Referral getReferral() throws LdapException
    {
        if ( isReferral() )
        {
            return ( ( SearchResultReference ) response ).getReferral();
        }

        throw new LdapException();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isEntry()
    {
        return response instanceof SearchResultEntry;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry getEntry() throws LdapException
    {
        if ( isEntry() )
        {
            return ( ( SearchResultEntry ) response ).getEntry();
        }
        
        if ( isReferral() )
        {
            Referral referral = ( ( SearchResultReference ) response ).getReferral();
            throw new LdapReferralException( referral.getLdapUrls() );
        }

        throw new LdapException();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isIntermediate()
    {
        return response instanceof IntermediateResponse;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public IntermediateResponse getIntermediate() throws LdapException
    {
        if ( isEntry() )
        {
            return ( IntermediateResponse ) response;
        }

        throw new LdapException();
    }
}
