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
package org.apache.directory.api.dsmlv2.request;


import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.dsmlv2.DsmlDecorator;
import org.apache.directory.api.dsmlv2.DsmlLiterals;
import org.apache.directory.api.dsmlv2.ParserUtils;
import org.apache.directory.api.ldap.model.message.Request;
import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;


/**
 * This class represents the Batch Request. It can be used to generate an the XML String of a BatchRequest.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class BatchRequestDsml
{
    /** The Requests list */
    private List<DsmlDecorator<? extends Request>> requests;

    /** The ID of the request */
    private int requestID;

    /** The type of processing of the Batch Request */
    private Processing processing;

    /** The type of on error handling */
    private OnError onError;

    /** The response order */
    private ResponseOrder responseOrder;

    /**
     * This enum represents the different types of processing for a Batch Request 
     *
     * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
     */
    public enum Processing
    {
        /** Sequential processing. */
        SEQUENTIAL,
        /** Parallel processing. */
        PARALLEL
    }

    /**
     * This enum represents the different types of on error handling for a BatchRequest
     *
     * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
         */
    public enum OnError
    {
        /** Resume on error. */
        RESUME,
        /** Exit on error. */
        EXIT
    }

    /**
     * This enum represents the different types of response order for a Batch Request
     *
     * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
         */
    public enum ResponseOrder
    {
        /** Sequential response order. */
        SEQUENTIAL,
        /** Unordered response order. */
        UNORDERED
    }

    /**
     * flag to indicate to store the request objects present in 
     * this batch request. Default is true
     */
    private boolean storeReq = true;

    private DsmlDecorator<? extends Request> currentReq;


    /**
     * Creates a new instance of BatchResponseDsml.
     */
    public BatchRequestDsml()
    {
        requests = new ArrayList<>();
        responseOrder = ResponseOrder.SEQUENTIAL;
        processing = Processing.SEQUENTIAL;
        onError = OnError.EXIT;
    }


    /**
     * Gets the current request
     *
     * @return
     *      the current request
     */
    public DsmlDecorator<? extends Request> getCurrentRequest()
    {
        return currentReq;
    }


    /**
     * Adds a request to the Batch Request DSML.
     *
     * @param request
     *      the request to add
     * @return
     *      true (as per the general contract of the Collection.add method).
     */
    public boolean addRequest( DsmlDecorator<? extends Request> request )
    {
        currentReq = request;

        if ( storeReq )
        {
            return requests.add( request );
        }
        else
        {
            return true;
        }
    }


    /**
     * Removes a request from the Batch Request DSML.
     *
     * @param request
     *      the request to remove
     * @return
     *      true if this list contained the specified element.
     */
    public boolean removeRequest( DsmlDecorator<? extends Request> request )
    {
        return requests.remove( request );
    }


    /**
     * Gets the ID of the request
     *
     * @return
     *      the ID of the request
     */
    public int getRequestID()
    {
        return requestID;
    }


    /**
     * Sets the ID of the request
     *
     * @param requestID
     *      the ID to set
     */
    public void setRequestID( int requestID )
    {
        this.requestID = requestID;
    }


    /**
     * Gets the processing type of the request
     *
     * @return
     *      the processing type of the request
     */
    public Processing getProcessing()
    {
        return processing;
    }


    /**
     * Sets the processing type of the request
     *
     * @param processing
     *      the processing type to set
     */
    public void setProcessing( Processing processing )
    {
        this.processing = processing;
    }


    /**
     * Gets the on error handling type of the request
     *
     * @return
     *      the on error handling type of the request
     */
    public OnError getOnError()
    {
        return onError;
    }


    /**
     * Sets the on error handling type of the request
     *
     * @param onError
     *      the on error handling type to set
     */
    public void setOnError( OnError onError )
    {
        this.onError = onError;
    }


    /**
     * Gets the response order type of the request
     *
     * @return
     *      the response order type of the request
     */
    public ResponseOrder getResponseOrder()
    {
        return responseOrder;
    }


    /**
     * Sets the response order type of the request
     *
     * @param responseOrder
     *      the response order type to set
     */
    public void setResponseOrder( ResponseOrder responseOrder )
    {
        this.responseOrder = responseOrder;
    }


    /**
     * Gets the List of all the requests in the Batch Request
     *
     * @return the List of all the requests in the Batch Request
     */
    public List<DsmlDecorator<? extends Request>> getRequests()
    {
        return requests;
    }


    /**
     * Converts this Batch Request to its XML representation in the DSMLv2 format.
     * 
     * @return the XML representation in DSMLv2 format
     */
    public String toDsml()
    {
        Document document = DocumentHelper.createDocument();
        Element element = document.addElement( DsmlLiterals.BATCH_REQUEST );

        // RequestID
        if ( requestID != 0 )
        {
            element.addAttribute( DsmlLiterals.REQUEST_ID, Integer.toString( requestID ) );
        }

        // ResponseOrder
        if ( responseOrder == ResponseOrder.UNORDERED )
        {
            element.addAttribute( DsmlLiterals.RESPONSE_ORDER, DsmlLiterals.UNORDERED );
        }

        // Processing
        if ( processing == Processing.PARALLEL )
        {
            element.addAttribute( DsmlLiterals.PROCESSING, DsmlLiterals.PARALLEL );
        }

        // On Error
        if ( onError == OnError.RESUME )
        {
            element.addAttribute( DsmlLiterals.ON_ERROR, DsmlLiterals.RESUME );
        }

        // Requests
        for ( DsmlDecorator<? extends Request> request : requests )
        {
            request.toDsml( element );
        }

        return ParserUtils.styleDocument( document ).asXML();
    }


    /**
     * Tells if the request objects are stored
     * 
     * @return <code>true</code> if the request objects are stored, <code>false</code> otherwise
     */
    public boolean isStoringRequests()
    {
        return storeReq;
    }


    /**
     * set the storeReq flag to turn on/off storing of request objects
     * 
     * Note: it is better to set this flag to false while processing large DSML 
     * batch requests
     *   
     * @param storeReq Tells if the request objects must be stored or not
     */
    public void setStoreReq( boolean storeReq )
    {
        this.storeReq = storeReq;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "[" );
        sb.append( "processing: " ).append( processing );
        sb.append( " - " );
        sb.append( "onError: " ).append( onError );
        sb.append( " - " );
        sb.append( "responseOrder: " ).append( responseOrder );
        sb.append( "]" );

        return sb.toString();
    }
}
