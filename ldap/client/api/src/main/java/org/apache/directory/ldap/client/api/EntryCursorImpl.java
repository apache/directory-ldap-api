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

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.cursor.AbstractCursor;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.cursor.InvalidCursorPositionException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchResultReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An implementation of Cursor based on the underlying SearchFuture instance.
 * 
 * Note: This is a forward only cursor hence the only valid operations are next(), get() and close() 
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EntryCursorImpl extends AbstractCursor<Entry> implements EntryCursor
{
    /** A dedicated log for cursors */
    private static final Logger LOG_CURSOR = LoggerFactory.getLogger( "CURSOR" );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = LOG_CURSOR.isDebugEnabled();

    /** a reference to hold the retrieved SearchResponse object from SearchFuture */
    private Response response;

    /** The encapsulated search cursor */
    private SearchCursor searchCursor;

    /** The underlying messageId */
    private int messageId;


    /**
     * Instantiates a new search cursor, embedding a SearchCursor.
     *
     * @param searchCursor the embedded SearchResponse cursor
     */
    public EntryCursorImpl( SearchCursor searchCursor )
    {
        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( "Creating EntryCursorImpl {}", this );
        }
        
        this.searchCursor = searchCursor;
        messageId = -1;
    }


    /**
     * {@inheritDoc}
     */
    public boolean next() throws LdapException, CursorException, IOException
    {
        if ( !searchCursor.next() )
        {
            return false;
        }

        try
        {

            do
            {
                response = searchCursor.get();

                if ( response == null )
                {
                    throw new LdapException( LdapNetworkConnection.TIME_OUT_ERROR );
                }

                messageId = response.getMessageId();

                if ( response instanceof SearchResultEntry )
                {
                    return true;
                }

                if ( response instanceof SearchResultReference )
                {
                    return true;
                }
            }
            while ( !( response instanceof SearchResultDone ) );

            return false;
        }
        catch ( Exception e )
        {
            LdapException ldapException = new LdapException( LdapNetworkConnection.NO_RESPONSE_ERROR );
            ldapException.initCause( e );

            // close the cursor
            close( ldapException );

            throw ldapException;
        }
    }


    /**
     * {@inheritDoc}
     */
    public Entry get() throws CursorException, IOException
    {
        if ( !searchCursor.available() )
        {
            throw new InvalidCursorPositionException();
        }

        try
        {
            do
            {
                if ( response instanceof SearchResultEntry )
                {
                    return ( ( SearchResultEntry ) response ).getEntry();
                }
            }
            while ( next() && !( response instanceof SearchResultDone ) );
        }
        catch ( Exception e )
        {
            throw new CursorException( e.getMessage(), e );
        }


        return null;
    }


    /**
     * {@inheritDoc}
     */
    public SearchResultDone getSearchResultDone()
    {
        return searchCursor.getSearchResultDone();
    }


    /**
     * {@inheritDoc}
     */
    public boolean available()
    {
        return searchCursor.available();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void close()
    {
        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( "Closing EntryCursorImpl {}", this );
        }
        
        searchCursor.close();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void close( Exception cause )
    {
        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( "Closing EntryCursorImpl {}", this );
        }
        
        searchCursor.close( cause );
    }


    // rest of all operations will throw UnsupportedOperationException

    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    public void after( Entry element ) throws LdapException, CursorException, IOException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "after( Response element )" ) ) );
    }


    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    public void afterLast() throws LdapException, CursorException, IOException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "afterLast()" ) ) );
    }


    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    public void before( Entry element ) throws LdapException, CursorException, IOException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "before( Response element )" ) ) );
    }


    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    public void beforeFirst() throws LdapException, CursorException, IOException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "beforeFirst()" ) ) );
    }


    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    public boolean first() throws LdapException, CursorException, IOException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "first()" ) ) );
    }


    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    public boolean last() throws LdapException, CursorException, IOException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "last()" ) ) );
    }


    /**
     * This operation is not supported in SearchCursor.
     * {@inheritDoc}
     */
    public boolean previous() throws LdapException, CursorException, IOException
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02014_UNSUPPORTED_OPERATION, getClass().getName()
            .concat( "." ).concat( "previous()" ) ) );
    }


    /**
     * {@inheritDoc}
     */
    public int getMessageId()
    {
        return messageId;
    }
}
