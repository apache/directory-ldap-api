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
package org.apache.directory.api.ldap.model.subtree;


import java.util.HashSet;
import java.util.Set;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.name.Dn;


/**
 * SubtreeSpecification contains no setters so they must be built by a
 * modifiable object containing all the necessary parameters to build the base
 * object.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SubtreeSpecificationModifier
{
    /** the subtree base relative to the administration point */
    private Dn base = new Dn();

    /** the set of subordinates entries and their subordinates to exclude */
    private Set<Dn> chopBefore = new HashSet<>();

    /** the set of subordinates entries whose subordinates are to be excluded */
    private Set<Dn> chopAfter = new HashSet<>();

    /** the minimum distance below base to start including entries */
    private int minBaseDistance = 0;

    /** the maximum distance from base past which entries are excluded */
    private int maxBaseDistance = SubtreeSpecification.UNBOUNDED_MAX;

    /**
     * a filter using only assertions on objectClass attributes for subtree
     * refinement
     */
    private ExprNode filter;


    // -----------------------------------------------------------------------
    // F A C T O R Y M E T H O D
    // -----------------------------------------------------------------------

    /**
     * Creates a SubtreeSpecification using any of the default paramters that
     * may have been modified from their defaults.
     * 
     * @return the newly created subtree specification
     */
    public SubtreeSpecification getSubtreeSpecification()
    {

        return new BaseSubtreeSpecification( this.base, this.minBaseDistance, this.maxBaseDistance, this.chopAfter,
            this.chopBefore, this.filter );
    }


    // -----------------------------------------------------------------------
    // M U T A T O R S
    // -----------------------------------------------------------------------

    /**
     * Sets the subtree base relative to the administration point.
     * 
     * @param base subtree base relative to the administration point
     */
    public void setBase( Dn base )
    {
        this.base = base;
    }


    /**
     * Sets the set of subordinates entries and their subordinates to exclude.
     * 
     * @param chopBeforeExclusions
     *            the set of subordinates entries and their subordinates to
     *            exclude
     */
    public void setChopBeforeExclusions( Set<Dn> chopBeforeExclusions )
    {
        this.chopBefore = chopBeforeExclusions;
    }


    /**
     * Add a subordinate entries and its subordinate to exclude.
     * 
     * @param chopBeforeExclusion
     *            the subordinate entry and its subordinate to
     *            exclude
     */
    public void addChopBeforeExclusions( Dn chopBeforeExclusion )
    {
        this.chopBefore.add( chopBeforeExclusion );
    }


    /**
     * Sets the set of subordinates entries whose subordinates are to be
     * excluded.
     * 
     * @param chopAfterExclusions
     *            the set of subordinates entries whose subordinates are to be
     *            excluded
     */
    public void setChopAfterExclusions( Set<Dn> chopAfterExclusions )
    {
        this.chopAfter = chopAfterExclusions;
    }


    /**
     * Add a subordinate entries and its subordinate to exclude.
     * 
     * @param chopAfterExclusion
     *            the subordinate entry and its subordinate to
     *            exclude
     */
    public void addChopAfterExclusions( Dn chopAfterExclusion )
    {
        this.chopAfter.add( chopAfterExclusion );
    }


    /**
     * Sets the minimum distance below base to start including entries.
     * 
     * @param minBaseDistance
     *            the minimum distance below base to start including entries
     */
    public void setMinBaseDistance( int minBaseDistance )
    {
        if ( minBaseDistance < 0 )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_13029_NEGATIVE_MINIMUM_BASE ) );
        }

        this.minBaseDistance = minBaseDistance;
    }


    /**
     * Sets the maximum distance from base past which entries are excluded.
     * 
     * @param maxBaseDistance
     *            the maximum distance from base past which entries are excluded
     */
    public void setMaxBaseDistance( int maxBaseDistance )
    {
        if ( maxBaseDistance < 0 )
        {
            this.maxBaseDistance = SubtreeSpecification.UNBOUNDED_MAX;
        }
        else
        {
            this.maxBaseDistance = maxBaseDistance;
        }
    }


    /**
     * Sets a filter using only assertions on objectClass attributes for subtree
     * refinement.
     * 
     * @param refinement a filter using only assertions on objectClass attributes for
     *            subtree refinement
     */
    public void setRefinement( ExprNode refinement )
    {
        this.filter = refinement;
    }


    /**
     * Sets a filter
     * 
     * @param filter a filter
     */
    public void setFilter( ExprNode filter )
    {
        this.filter = filter;
    }
}
