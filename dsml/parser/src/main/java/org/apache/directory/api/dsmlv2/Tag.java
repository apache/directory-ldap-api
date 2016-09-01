/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * 
 */
package org.apache.directory.api.dsmlv2;


import org.apache.directory.api.util.Strings;


/**
 * This class represents a XML tag.
 * <br>
 * A XML tag is defined with :
 * <ul>
 *      <li>a name</li>
 *      <li>a type (START tag or END tag)</li>
 * </ul>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Tag
{
    /** The name of the tag */
    private String name;

    /** The type of the tag */
    private int type;

    /** This int represents a START tag */
    public static final int START = 0;

    /** This int represents a END tag */
    public static final int END = 1;


    /**
     * Creates a new instance of Tag.
     *
     * @param name the name of the tag
     * @param type the type of the tag
     */
    public Tag( String name, int type )
    {
        setName( name );
        setType( type );
    }


    /**
     * Gets the name of the tag
     *
     * @return the name of the tag
     */
    public String getName()
    {
        return name;
    }


    /**
     * Sets the name of the tag
     *
     * @param name the name to set
     */
    public void setName( String name )
    {
        this.name = Strings.toLowerCaseAscii( name );
    }


    /**
     * Gets the type of the tag
     *
     * @return the type of the tag
     */
    public int getType()
    {
        return type;
    }


    /**
     * Sets the type of the tag
     *
     * @param type the type to set
     */
    public void setType( int type )
    {
        this.type = type;
    }


    /**
     * {@inheritDoc}
     */
    public boolean equals( Object obj )
    {
        if ( obj instanceof Tag )
        {
            Tag tag = ( Tag ) obj;
            
            return ( ( this.name.equals( tag.getName() ) ) && ( this.type == tag.getType() ) );

        }
        else
        {
            return false;
        }
    }


    /**
     * {@inheritDoc}
     */
    public int hashCode()
    {
        return name.hashCode() + type << 24;
    }


    /**
     * {@inheritDoc}
     */
    public String toString()
    {
        if ( name != null )
        {
            return "<" + ( ( type == Tag.END ) ? "/" : "" ) + name + ">";
        }
        else
        {
            return "Unknown tag";
        }
    }
}
