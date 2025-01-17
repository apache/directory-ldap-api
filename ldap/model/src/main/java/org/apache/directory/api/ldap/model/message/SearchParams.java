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


import java.util.HashSet;
import java.util.Set;

import javax.naming.directory.SearchControls;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.AttributeTypeOptions;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.SchemaUtils;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A container for Search parameters. It replaces the SearchControls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SearchParams
{
    /** The LoggerFactory used by this class */
    private static final Logger LOG = LoggerFactory.getLogger( SearchParams.class );

    /** The search scope. Default to OBJECT */
    private SearchScope scope = SearchScope.OBJECT;

    /** The time limit. Default to 0 (infinite) */
    private int timeLimit = 0;

    /** The size limit. Default to 0 (infinite) */
    private long sizeLimit = 0;

    /** If we should return only types. Default to false */
    private boolean typesOnly = false;

    /** The aliasDerefMode. Default to DEREF_ALWAYS */
    private AliasDerefMode aliasDerefMode = AliasDerefMode.DEREF_ALWAYS;

    /** The list of attributes to return, as Strings. Default to an empty set */
    private Set<String> returningAttributesStr;

    /** The list of attributes to return, once it has been normalized. Default to an empty set */
    private Set<AttributeTypeOptions> returningAttributes;

    /** The set of controls for this search. Default to an empty set */
    private Set<Control> controls;


    /**
     * Creates a new instance of SearchContext, with all the values set to 
     * default.
     */
    public SearchParams()
    {
        returningAttributes = new HashSet<>();
        returningAttributesStr = new HashSet<>();
        controls = new HashSet<>();
    }


    /**
     * @return the scope
     */
    public SearchScope getScope()
    {
        return scope;
    }


    /**
     * @param scope the scope to set
     */
    public void setScope( SearchScope scope )
    {
        this.scope = scope;
    }


    /**
     * @return the timeLimit
     */
    public int getTimeLimit()
    {
        return timeLimit;
    }


    /**
     * @param timeLimit the timeLimit to set
     */
    public void setTimeLimit( int timeLimit )
    {
        this.timeLimit = timeLimit;
    }


    /**
     * @return the sizeLimit
     */
    public long getSizeLimit()
    {
        return sizeLimit;
    }


    /**
     * @param sizeLimit the sizeLimit to set
     */
    public void setSizeLimit( long sizeLimit )
    {
        this.sizeLimit = sizeLimit;
    }


    /**
     * @return the typesOnly
     */
    public boolean isTypesOnly()
    {
        return typesOnly;
    }


    /**
     * @param typesOnly the typesOnly to set
     */
    public void setTypesOnly( boolean typesOnly )
    {
        this.typesOnly = typesOnly;
    }


    /**
     * @return the aliasDerefMode
     */
    public AliasDerefMode getAliasDerefMode()
    {
        return aliasDerefMode;
    }


    /**
     * @param aliasDerefMode the aliasDerefMode to set
     */
    public void setAliasDerefMode( AliasDerefMode aliasDerefMode )
    {
        this.aliasDerefMode = aliasDerefMode;
    }


    /**
     * @return the returningAttributes
     */
    public Set<AttributeTypeOptions> getReturningAttributes()
    {
        return returningAttributes;
    }


    /**
     * @return the returningAttributes
     */
    public Set<String> getReturningAttributesStr()
    {
        return returningAttributesStr;
    }


    /**
     * Normalize the ReturningAttributes. It reads all the String from the returningAttributesString,
     * and grab the associated AttributeType from the schema to store it into the returningAttributes
     * Set.
     *
     * @param schemaManager The schema manager
     */
    public void normalize( SchemaManager schemaManager )
    {
        for ( String returnAttribute : returningAttributesStr )
        {
            try
            {
                String id = SchemaUtils.stripOptions( returnAttribute );
                Set<String> options = SchemaUtils.getOptions( returnAttribute );

                AttributeType attributeType = schemaManager.lookupAttributeTypeRegistry( id );
                AttributeTypeOptions attrOptions = new AttributeTypeOptions( attributeType, options );

                returningAttributes.add( attrOptions );
            }
            catch ( LdapException ne )
            {
                if ( LOG.isWarnEnabled() )
                {
                    LOG.warn( I18n.msg( I18n.MSG_13500_ATTRIBUTE_NOT_IN_SCHEMA, returnAttribute ) );
                }
                
                // Unknown attributes should be silently ignored, as RFC 2251 states
            }
        }
    }


    /**
     * @param returningAttributes the returningAttributes to set
     */
    public void setReturningAttributes( String... returningAttributes )
    {
        if ( returningAttributes != null )
        {
            for ( String returnAttribute : returningAttributes )
            {
                this.returningAttributesStr.add( returnAttribute );
            }
        }
    }


    /**
     * @param returningAttribute the returningAttributes to add
     */
    public void addReturningAttributes( String returningAttribute )
    {
        this.returningAttributesStr.add( returningAttribute );
    }


    /**
     * @return the controls
     */
    public Set<Control> getControls()
    {
        return controls;
    }


    /**
     * @param controls the controls to set
     */
    public void setControls( Set<Control> controls )
    {
        this.controls = controls;
    }


    /**
     * @param control the controls to set
     */
    public void addControl( Control control )
    {
        this.controls.add( control );
    }


    /**
     * Creates a {@link SearchParams} from JNDI search controls.
     *
     * @param searchControls the search controls
     * @param aliasDerefMode the alias deref mode
     * @return the search params
     */
    public static SearchParams toSearchParams( SearchControls searchControls, AliasDerefMode aliasDerefMode )
    {
        SearchParams searchParams = new SearchParams();

        searchParams.setAliasDerefMode( aliasDerefMode );
        searchParams.setTimeLimit( searchControls.getTimeLimit() );
        searchParams.setSizeLimit( searchControls.getCountLimit() );
        searchParams.setScope( SearchScope.getSearchScope( searchControls.getSearchScope() ) );
        searchParams.setTypesOnly( searchControls.getReturningObjFlag() );

        if ( searchControls.getReturningAttributes() != null )
        {
            for ( String returningAttribute : searchControls.getReturningAttributes() )
            {
                searchParams.addReturningAttributes( returningAttribute );
            }
        }

        return searchParams;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "Search parameters :\n" );
        sb.append( "    scope : " ).append( scope ).append( "\n" );
        sb.append( "    Alias dereferencing : " ).append( aliasDerefMode ).append( "\n" );
        sb.append( "    types only : " ).append( typesOnly ).append( "\n" );

        if ( !returningAttributesStr.isEmpty() )
        {
            sb.append( "    returning attributes : " ).append( Strings.setToString( returningAttributesStr ) )
                .append( "\n" );
        }

        if ( timeLimit > 0 )
        {
            sb.append( "    timeLimit : " ).append( timeLimit ).append( "\n" );
        }
        else
        {
            sb.append( "    no timeLimit\n" );
        }

        if ( sizeLimit > 0 )
        {
            sb.append( "    sizeLimit : " ).append( sizeLimit ).append( "\n" );
        }
        else
        {
            sb.append( "    no sizeLimit\n" );
        }

        if ( !controls.isEmpty() )
        {
            for ( Control control : controls )
            {
                sb.append( "    control : " ).
                    append( control.getOid() ).append( "/" ).
                    append( control.getClass().getName() ).append( "\n" );
            }
        }

        return sb.toString();
    }
}
