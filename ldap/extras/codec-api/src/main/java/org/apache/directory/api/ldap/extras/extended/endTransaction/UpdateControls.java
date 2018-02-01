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
package org.apache.directory.api.ldap.extras.extended.endTransaction;

import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.ldap.model.message.Control;

/**
 * The interface for End Transaction Extended Response UpdateControl. It's described in RFC 5805 :
 * 
 * <pre>
 * updateControls SEQUENCE {
 *     messageID MessageID,
 *               -- msgid associated with controls
 *     controls  Controls
 * } OPTIONAL
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class UpdateControls
{
    /** The message ID for which we want to get back the controls */
    private int messageId;

    /** The list of controls (may be empty) */
    private List<Control> controls = new ArrayList<>();
    
    /**
     * A default constructor for the UpdateControls class
     */
    public UpdateControls()
    {
        // Nothing to do
    }
    
    
    /**
     * @return The messageID
     */
    public int getMessageId()
    {
        return messageId;
    }
    
    
    /**
     * @param messageId the messageId to set
     */
    public void setMessageId( int messageId )
    {
        this.messageId = messageId;
    }
   
   
    /**
     * @return The set of controls associated with the messageID
     */
    public List<Control> getControls()
    {
        return controls;
    }


    /**
     * @param controls the controls to set
     */
    public void setControls( List<Control> controls )
    {
        this.controls = controls;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = 37;

        hash = hash * 17 + messageId;
        
        for ( Control control : controls )
        {
            hash = hash * 17 + control.hashCode();
        }

        return hash;
    }


    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( obj == this )
        {
            return true;
        }

        if ( !( obj instanceof UpdateControls ) )
        {
            return false;
        }
        
        UpdateControls that = ( UpdateControls ) obj;
        
        if ( messageId != that.getMessageId() )
        {
            return false;
        }
        
        if ( controls.size() != that.getControls().size() )
        {
            return false;
        }
        
        for ( Control control : controls )
        {
            if ( !that.getControls().contains( control ) )
            {
                return false;
            }
        }
        
        return true;
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "UpdateControl :" );
        sb.append( "\n    messageId : " ).append( messageId );

        if ( controls.isEmpty() )
        {
            sb.append( "\n    No controls" );
        }
        else
        {
            sb.append( "\n    Controls: [" );
            boolean isFirst = true;
            
            for ( Control control : controls )
            {
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    sb.append( ", " );
                }
                
                sb.append( control.getOid() );
            }
            
            sb.append( ']' );
        }

        return sb.toString();
    }
}
