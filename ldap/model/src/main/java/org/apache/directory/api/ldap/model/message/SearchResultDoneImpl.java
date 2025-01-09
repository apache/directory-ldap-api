/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.model.message;


/**
 * SearchResponseDone implementation
 * 
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 */
public class SearchResultDoneImpl extends AbstractResultResponse implements SearchResultDone
{
    /** Declares the Serial Version Uid */
    static final long serialVersionUID = 8698484213877460215L;

    /**
     * Creates a SearchResponseDone as a reply to an SearchRequest to
     * indicate the end of a search operation.
     */
    public SearchResultDoneImpl()
    {
        super( -1, MessageTypeEnum.SEARCH_RESULT_DONE );
    }


    /**
     * Creates a SearchResponseDone as a reply to an SearchRequest to
     * indicate the end of a search operation.
     * 
     * @param id the session unique message id
     */
    public SearchResultDoneImpl( final int id )
    {
        super( id, MessageTypeEnum.SEARCH_RESULT_DONE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        hash = hash * 17 + getLdapResult().hashCode();
        hash = hash * 17 + super.hashCode();

        return hash;
    }


    /**
     * Checks for equality by using the underlying LdapResult objects of this
     * SearchResponseDone stub.
     * 
     * @param obj
     *            the object to be tested for equality
     * @return true if obj is equivalent to this SearchResponseDone impl
     */
    @Override
    public boolean equals( Object obj )
    {
        // quickly return if the obj is this object
        if ( obj == this )
        {
            return true;
        }

        if ( !super.equals( obj ) )
        {
            return false;
        }

        LdapResult result = ( ( SearchResultDone ) obj ).getLdapResult();

        return getLdapResult().equals( result );
    }


    /**
     * Get a String representation of a SearchResultDone
     * 
     * @return A SearchResultDone String
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    Search Result Done\n" );
        sb.append( super.toString() );

        return super.toString( sb.toString() );
    }
}
