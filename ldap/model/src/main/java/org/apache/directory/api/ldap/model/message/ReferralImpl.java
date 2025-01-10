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


import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;


/**
 * A Referral implementation. For the time being this implementation uses a
 * String representation for LDAPURLs. In the future an LdapUrl interface with
 * default implementations will be used once a parser for an LdapUrl is created.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ReferralImpl implements Referral
{
    /** Sequence of LDAPUrls composing this Referral */
    private final List<String> urls = new ArrayList<>();

    /** The encoded LdapURL */
    private final List<byte[]> urlsBytes = new ArrayList<>();

    /** The length of the referral */
    private int referralLength;

    // ------------------------------------------------------------------------
    // LdapResult Interface Method Implementations
    // ------------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public int getReferralLength()
    {
        return referralLength;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setReferralLength( int referralLength )
    {
        this.referralLength = referralLength;
    }


    /**
     * Gets an unmodifiable set of alternative referral urls.
     * 
     * @return the alternative url objects.
     */
    @Override
    public Collection<String> getLdapUrls()
    {
        return Collections.unmodifiableCollection( urls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<byte[]> getLdapUrlsBytes()
    {
        return urlsBytes;
    }


    /**
     * Adds an LDAPv3 URL to this Referral.
     * 
     * @param url the LDAPv3 URL to add
     */
    @Override
    public void addLdapUrl( String url )
    {
        urls.add( url );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void addLdapUrlBytes( byte[] urlBytes )
    {
        urlsBytes.add( urlBytes );
    }


    /**
     * Removes an LDAPv3 URL to this Referral.
     * 
     * @param url
     *            the LDAPv3 URL to remove
     */
    @Override
    public void removeLdapUrl( String url )
    {
        urls.remove( url );
    }


    /**
     * @see Object#hashCode()
     * @return the instance's hash code 
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        hash = hash * 17 + urls.size();

        // Order doesn't matter, so just add the url hashCode
        for ( String url : urls )
        {
            hash = hash + url.hashCode();
        }

        return hash;
    }


    /**
     * Compares this Referral implementation to see if it is the same as
     * another. The classes do not have to be the same implementation to return
     * true. Both this and the compared Referral must have the same entries
     * exactly. The order of Referral URLs does not matter.
     * 
     * @param obj
     *            the object to compare this ReferralImpl to
     * @return true if both implementations contain exactly the same URLs
     */
    @Override
    public boolean equals( Object obj )
    {
        // just in case for speed return true if obj is this object
        if ( obj == this )
        {
            return true;
        }

        if ( obj instanceof Referral )
        {
            Collection<String> refs = ( ( Referral ) obj ).getLdapUrls();

            // if their sizes do not match they are not equal
            if ( refs.size() != urls.size() )
            {
                return false;
            }

            Iterator<String> list = urls.iterator();

            while ( list.hasNext() )
            {
                // if one of our urls is not contained in the obj return false
                if ( !refs.contains( list.next() ) )
                {
                    return false;
                }
            }

            // made it through the checks so we have a match
            return true;
        }

        return false;
    }


    /**
     * Get a String representation of a Referral
     * 
     * @return A Referral String
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        if ( !urls.isEmpty() )
        {
            sb.append( "            Referrals :\n" );

            Object[] urlsArray = urls.toArray();

            for ( int i = 0; i < urlsArray.length; i++ )
            {

                String referral = ( String ) urlsArray[i];

                sb.append( "                Referral[" ).append( i ).append( "] :" ).append( referral ).append( '\n' );
            }
        }

        return sb.toString();
    }
}
