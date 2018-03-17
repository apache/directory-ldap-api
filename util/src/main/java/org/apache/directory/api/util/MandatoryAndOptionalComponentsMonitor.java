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

package org.apache.directory.api.util;


import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.apache.directory.api.i18n.I18n;


/**
 * A monitor that tracks both, mandatory and optional components.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MandatoryAndOptionalComponentsMonitor implements ComponentsMonitor
{

    /** The mandatory components monitor. */
    private ComponentsMonitor mandatoryComponentsMonitor;

    /** The optional components monitor. */
    private ComponentsMonitor optionalComponentsMonitor;


    /**
     * Instantiates a new mandatory and optional components monitor. The mandatory and optional
     * components must be disjunct.
     *
     * @param mandatoryComponents the mandatory components
     * @param optionalComponents the optional components
     * @throws IllegalArgumentException if the same component is defined as mandatory and optional
     */
    public MandatoryAndOptionalComponentsMonitor( String[] mandatoryComponents, String[] optionalComponents )
    {
        // check for common elements
        for ( int i = 0; i < mandatoryComponents.length; i++ )
        {
            for ( int j = 0; j < optionalComponents.length; j++ )
            {
                if ( mandatoryComponents[i].equals( optionalComponents[j] ) )
                {
                    throw new IllegalArgumentException( I18n.err( I18n.ERR_17035_DUPLICATED_COMMON_ELEMENT, 
                        mandatoryComponents[i] ) );
                }
            }
        }

        mandatoryComponentsMonitor = new MandatoryComponentsMonitor( mandatoryComponents );
        optionalComponentsMonitor = new OptionalComponentsMonitor( optionalComponents );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ComponentsMonitor useComponent( String component )
    {
        try
        {
            mandatoryComponentsMonitor.useComponent( component );
        }
        catch ( IllegalArgumentException e1 )
        {
            try
            {
                optionalComponentsMonitor.useComponent( component );
            }
            catch ( IllegalArgumentException e2 )
            {
                throw new IllegalArgumentException( I18n.err( I18n.ERR_17036_UNREGISTRED_COMPONENT, component ), e1 );
            }
        }

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean allComponentsUsed()
    {
        return mandatoryComponentsMonitor.allComponentsUsed() && optionalComponentsMonitor.allComponentsUsed();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean finalStateValid()
    {
        return mandatoryComponentsMonitor.finalStateValid() && optionalComponentsMonitor.finalStateValid();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getRemainingComponents()
    {
        List<String> remainingComponents = new LinkedList<>();

        remainingComponents.addAll( mandatoryComponentsMonitor.getRemainingComponents() );
        remainingComponents.addAll( optionalComponentsMonitor.getRemainingComponents() );

        return Collections.unmodifiableList( remainingComponents );
    }

}
