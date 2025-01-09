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
 * SearchResponseReference implementation
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SearchResultReferenceImpl extends AbstractResponse implements SearchResultReference
{
    /** Declares the Serial Version Uid */
    static final long serialVersionUID = 7423807019951309810L;

    /** Referral holding the reference urls */
    private Referral referral = new ReferralImpl();

    /**
     * Creates a SearchResponseReference as a reply to an SearchRequest
     * to indicate the end of a search operation.
     */
    public SearchResultReferenceImpl()
    {
        super( -1, MessageTypeEnum.SEARCH_RESULT_REFERENCE );
    }


    /**
     * Creates a SearchResponseReference as a reply to an SearchRequest
     * to indicate the end of a search operation.
     * 
     * @param id the session unique message id
     */
    public SearchResultReferenceImpl( final int id )
    {
        super( id, MessageTypeEnum.SEARCH_RESULT_REFERENCE );
    }


    // ------------------------------------------------------------------------
    // SearchResponseReference Interface Method Implementations
    // ------------------------------------------------------------------------

    /**
     * Gets the sequence of LdapUrls as a Referral instance.
     * 
     * @return the sequence of LdapUrls
     */
    @Override
    public Referral getReferral()
    {
        return this.referral;
    }


    /**
     * Sets the sequence of LdapUrls as a Referral instance.
     * 
     * @param referral the sequence of LdapUrls
     */
    @Override
    public void setReferral( Referral referral )
    {
        this.referral = referral;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        if ( this.referral != null )
        {
            hash = hash * 17 + this.referral.hashCode();
        }
        hash = hash * 17 + super.hashCode();

        return hash;
    }


    /**
     * Checks to see if an object is equal to this SearchResponseReference stub.
     * 
     * @param obj
     *            the object to compare to this response stub
     * @return true if the objects are equivalent false otherwise
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( obj == this )
        {
            return true;
        }

        if ( !super.equals( obj ) )
        {
            return false;
        }

        SearchResultReference resp = ( SearchResultReference ) obj;

        if ( referral == null )
        {
            return resp.getReferral() == null;
        }
        
        return referral.equals( resp.getReferral() );
    }


    /**
     * Returns the Search Result Reference string
     * 
     * @return The Search Result Reference string
     */
    @Override
    public String toString()
    {

        StringBuilder sb = new StringBuilder();

        sb.append( "    Search Result Reference\n" );

        if ( ( referral == null ) || ( referral.getLdapUrls() == null ) || referral.getLdapUrls().isEmpty() )
        {
            sb.append( "        No Reference\n" );
        }
        else
        {
            sb.append( "        References\n" );

            for ( String url : referral.getLdapUrls() )
            {
                sb.append( "            '" ).append( url ).append( "'\n" );
            }
        }

        return super.toString( sb.toString() );
    }
}
