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


import java.util.Observable;
import java.util.Observer;


/**
 * The base abandonable request message class. All such requests have a response
 * type.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractAbandonableRequest extends AbstractRequest implements AbandonableRequest
{
    /** Flag indicating whether or not this request returns a response. */
    private boolean abandoned = false;

    /** A filed used to check if the request has been abandonned */
    private RequestObservable observable;


    /**
     * Subclasses must provide these parameters via a super constructor call.
     * 
     * @param id the sequential message identifier
     * @param type the request type enum
     */
    protected AbstractAbandonableRequest( final int id, final MessageTypeEnum type )
    {
        super( id, type, true );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void abandon()
    {
        if ( abandoned )
        {
            return;
        }

        abandoned = true;
        
        if ( observable == null )
        {
            observable = new RequestObservable();
        }
        
        observable.setChanged();
        observable.notifyObservers();
        observable.deleteObservers();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAbandoned()
    {
        return abandoned;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AbandonableRequest addAbandonListener( final AbandonListener listener )
    {
        if ( observable == null )
        {
            observable = new RequestObservable();
        }

        observable.addObserver( new Observer()
        {
            @Override
            public void update( Observable o, Object arg )
            {
                listener.requestAbandoned( AbstractAbandonableRequest.this );
            }
        } );

        return this;
    }

    // False positive
    /** 
     * A class used to receive notifications for a Request 
     */
    static class RequestObservable extends Observable
    {
        /** 
         * Public constructor
         */
        RequestObservable()
        {
            super();
        }


        /** 
         * {@inheritDoc}
         */
        @Override
        public void setChanged()
        {
            super.setChanged();
        }
    }
}
