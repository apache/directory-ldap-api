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


import java.io.IOException;
import java.lang.reflect.Array;
import java.util.Base64;
import java.util.HashMap;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.dsmlv2.AbstractGrammar;
import org.apache.directory.api.dsmlv2.DsmlControl;
import org.apache.directory.api.dsmlv2.DsmlLiterals;
import org.apache.directory.api.dsmlv2.Dsmlv2Container;
import org.apache.directory.api.dsmlv2.Dsmlv2StatesEnum;
import org.apache.directory.api.dsmlv2.Grammar;
import org.apache.directory.api.dsmlv2.GrammarAction;
import org.apache.directory.api.dsmlv2.GrammarTransition;
import org.apache.directory.api.dsmlv2.ParserUtils;
import org.apache.directory.api.dsmlv2.Tag;
import org.apache.directory.api.dsmlv2.request.BatchRequestDsml.OnError;
import org.apache.directory.api.dsmlv2.request.BatchRequestDsml.Processing;
import org.apache.directory.api.dsmlv2.request.BatchRequestDsml.ResponseOrder;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.AbandonRequestImpl;
import org.apache.directory.api.ldap.model.message.AddRequestImpl;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.CompareRequest;
import org.apache.directory.api.ldap.model.message.CompareRequestImpl;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyDnRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.OpaqueExtendedRequest;
import org.apache.directory.api.ldap.model.message.Request;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.OpaqueControl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.util.Strings;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;


/**
 * This Class represents the DSMLv2 Request Grammar
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class Dsmlv2Grammar extends AbstractGrammar implements Grammar
{
    private LdapApiService codec = LdapApiServiceFactory.getSingleton();

    //*************************
    //*    GRAMMAR ACTIONS    *
    //*************************

    /**
     * GrammarAction that creates a Batch Request
     */
    private final GrammarAction batchRequestCreation = new GrammarAction( "Create Batch Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            BatchRequestDsml batchRequest = new BatchRequestDsml();

            container.setBatchRequest( batchRequest );

            XmlPullParser xpp = container.getParser();

            // Checking and adding the batchRequest's attributes
            String attributeValue;
            // requestID
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.REQUEST_ID );

            if ( attributeValue != null )
            {
                batchRequest.setRequestID( ParserUtils.parseAndVerifyRequestID( attributeValue, xpp ) );
            }
            // processing
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.PROCESSING );

            if ( attributeValue != null )
            {
                if ( DsmlLiterals.SEQUENTIAL.equals( attributeValue ) )
                {
                    batchRequest.setProcessing( Processing.SEQUENTIAL );
                }
                else if ( DsmlLiterals.PARALLEL.equals( attributeValue ) )
                {
                    batchRequest.setProcessing( Processing.PARALLEL );
                }
                else
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03013_UNKNOWN_PROCESSING_VALUE ), xpp, null );
                }
            }
            else
            {
                batchRequest.setProcessing( Processing.SEQUENTIAL );
            }

            // onError
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.ON_ERROR );

            if ( attributeValue != null )
            {
                if ( DsmlLiterals.RESUME.equals( attributeValue ) )
                {
                    batchRequest.setOnError( OnError.RESUME );
                }
                else if ( DsmlLiterals.EXIT.equals( attributeValue ) )
                {
                    batchRequest.setOnError( OnError.EXIT );
                }
                else
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03014_UNKNOWN_ON_ERROR_VALUE ), xpp, null );
                }
            }
            else
            {
                batchRequest.setOnError( OnError.EXIT );
            }

            // responseOrder
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.RESPONSE_ORDER );

            if ( attributeValue != null )
            {
                if ( DsmlLiterals.SEQUENTIAL.equals( attributeValue ) )
                {
                    batchRequest.setResponseOrder( ResponseOrder.SEQUENTIAL );
                }
                else if ( DsmlLiterals.UNORDERED.equals( attributeValue ) )
                {
                    batchRequest.setResponseOrder( ResponseOrder.UNORDERED );
                }
                else
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03015_UNKNOWN_RESPONSE_ORDER_VALUE ), xpp, null );
                }
            }
            else
            {
                batchRequest.setResponseOrder( ResponseOrder.SEQUENTIAL );
            }
        }
    };

    /**
     * GrammarAction that creates an Abandon Request
     */
    private final GrammarAction abandonRequestCreation = new GrammarAction( "Create Abandon Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            AbandonRequestDsml abandonRequest = new AbandonRequestDsml( codec, new AbandonRequestImpl() );
            container.getBatchRequest().addRequest( abandonRequest );

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attributes
            String attributeValue;
            // requestID
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.REQUEST_ID );

            if ( attributeValue != null )
            {
                abandonRequest.setMessageId( ParserUtils.parseAndVerifyRequestID( attributeValue, xpp ) );
            }
            else
            {
                if ( ParserUtils.isRequestIdNeeded( container ) )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03000_REQUEST_ID_REQUIRED ), xpp, null );
                }
            }

            // abandonID
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.ABANDON_ID );

            if ( attributeValue != null )
            {
                try
                {
                    abandonRequest.setAbandoned( Integer.parseInt( attributeValue ) );
                }
                catch ( NumberFormatException nfe )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03017_ABANDON_ID_NOT_INTEGER ), xpp, nfe );
                }
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03018_ABANDON_ID_REQUIRED ), xpp, null );
            }
        }
    };

    /**
     * GrammarAction that creates an Add Request
     */
    private final GrammarAction addRequestCreation = new GrammarAction( "Create Add Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            AddRequestDsml addRequest = new AddRequestDsml( codec, new AddRequestImpl() );
            container.getBatchRequest().addRequest( addRequest );

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attributes
            String attributeValue;
            // requestID
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.REQUEST_ID );

            if ( attributeValue != null )
            {
                addRequest.setMessageId( ParserUtils.parseAndVerifyRequestID( attributeValue, xpp ) );
            }
            else
            {
                if ( ParserUtils.isRequestIdNeeded( container ) )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03000_REQUEST_ID_REQUIRED ), xpp, null );
                }
            }

            // dn
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.DN );

            if ( attributeValue != null )
            {
                try
                {
                    addRequest.setEntryDn( new Dn( attributeValue ) );
                }
                catch ( LdapInvalidDnException lide )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03039_PARSING_ERROR, lide.getMessage() ), xpp, lide );
                }
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03001_DN_ATTRIBUTE_REQUIRED ), xpp, null );
            }
        }
    };

    /**
     * GrammarAction that adds an attribute to an Add Request
     */
    private final GrammarAction addRequestAddAttribute = new GrammarAction( "Add Attribute to Add Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            AddRequestDsml addRequest = ( AddRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attributes
            String attributeValue;
            // name
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NAME );

            if ( attributeValue != null )
            {
                try
                {
                    addRequest.addAttributeType( attributeValue );
                }
                catch ( LdapException le )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03020_CANT_ADD_ATTRIBUTE_VALUE ), xpp, le );
                }
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03002_NAME_ATTRIBUTE_REQUIRED ), xpp, null );
            }
        }
    };

    /**
     * GrammarAction that adds a Value to an Attribute of an Add Request
     */
    private final GrammarAction addRequestAddValue = new GrammarAction( "Add Value to Attribute" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            AddRequestDsml addRequest = ( AddRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            try
            {
                // We have to catch the type Attribute Value before going to the next Text node
                String typeValue = ParserUtils.getXsiTypeAttributeValue( xpp );

                // Getting the value
                String nextText = xpp.nextText();

                if ( !Strings.isEmpty( nextText ) )
                {
                    try
                    {
                        if ( ParserUtils.isBase64BinaryValue( xpp, typeValue ) )
                        {
                            addRequest.addAttributeValue( Base64.getDecoder().decode( nextText.trim() ) );
                        }
                        else
                        {
                            addRequest.addAttributeValue( nextText.trim() );
                        }
                    }
                    catch ( LdapException le )
                    {
                        throw new XmlPullParserException( le.getMessage(), xpp, le );
                    }
                }
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03008_UNEXPECTED_ERROR, ioe.getMessage() ), xpp, ioe );
            }
        }
    };

    /**
     * GrammarAction that creates an Auth Request
     */
    private final GrammarAction authRequestCreation = new GrammarAction( "Create Auth Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            BindRequestDsml authRequest = new BindRequestDsml( codec, new BindRequestImpl() );
            container.getBatchRequest().addRequest( authRequest );

            authRequest.setSimple( true );
            authRequest.setVersion3( true );

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attributes
            String attributeValue;
            // requestID
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.REQUEST_ID );

            if ( attributeValue != null )
            {
                authRequest.setMessageId( ParserUtils.parseAndVerifyRequestID( attributeValue, xpp ) );
            }
            else
            {
                if ( ParserUtils.isRequestIdNeeded( container ) )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03000_REQUEST_ID_REQUIRED ), xpp, null );
                }
            }
            // principal
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.PRINCIPAL );

            if ( attributeValue != null )
            {
                authRequest.setName( attributeValue );
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03021_PRINCIPAL_ATTRIBUTE_REQUIRED ), xpp, null );
            }
        }
    };

    /**
     * GrammarAction that creates an Compare Request
     */
    private final GrammarAction compareRequestCreation = new GrammarAction( "Create Compare Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            CompareRequestDsml compareRequest = new CompareRequestDsml( codec, new CompareRequestImpl() );
            container.getBatchRequest().addRequest( compareRequest );

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attributes
            String attributeValue;
            // requestID
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.REQUEST_ID );

            if ( attributeValue != null )
            {
                compareRequest.setMessageId( ParserUtils.parseAndVerifyRequestID( attributeValue, xpp ) );
            }
            else
            {
                if ( ParserUtils.isRequestIdNeeded( container ) )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03000_REQUEST_ID_REQUIRED ), xpp, null );
                }
            }

            // dn
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.DN );

            if ( attributeValue != null )
            {
                try
                {
                    compareRequest.setName( new Dn( attributeValue ) );
                }
                catch ( LdapInvalidDnException lide )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03039_PARSING_ERROR, lide.getMessage() ), xpp, lide );
                }
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03001_DN_ATTRIBUTE_REQUIRED ), xpp, null );
            }
        }
    };

    /**
     * GrammarAction that adds an Assertion to a Compare Request
     */
    private final GrammarAction compareRequestAddAssertion = new GrammarAction( "Add Assertion to Compare Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            CompareRequest compareRequest = ( CompareRequest ) container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attributes
            String attributeId;

            // name
            attributeId = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NAME );

            if ( attributeId != null )
            {
                compareRequest.setAttributeId( attributeId );
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03002_NAME_ATTRIBUTE_REQUIRED ), xpp, null );
            }
        }
    };

    /**
     * GrammarAction that adds a Value to a Compare Request
     */
    private final GrammarAction compareRequestAddValue = new GrammarAction( "Add Value to Compare Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            CompareRequest compareRequest = ( CompareRequest ) container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            try
            {
                // We have to catch the type Attribute Value before going to the next Text node
                String typeValue = ParserUtils.getXsiTypeAttributeValue( xpp );

                // Getting the value
                String nextText = xpp.nextText();

                if ( !Strings.isEmpty( nextText ) )
                {
                    if ( ParserUtils.isBase64BinaryValue( xpp, typeValue ) )
                    {
                        compareRequest.setAssertionValue( Base64.getDecoder().decode( nextText.trim() ) );
                    }
                    else
                    {
                        compareRequest.setAssertionValue( nextText.trim() );
                    }
                }
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03008_UNEXPECTED_ERROR, ioe.getMessage() ), xpp, ioe );
            }
        }
    };

    /**
     * GrammarAction that creates a Del Request
     */
    private final GrammarAction delRequestCreation = new GrammarAction( "Create Del Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            DelRequestDsml delRequest = new DelRequestDsml( codec, new DeleteRequestImpl() );
            container.getBatchRequest().addRequest( delRequest );

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attributes
            String attributeValue;
            // requestID
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.REQUEST_ID );

            if ( attributeValue != null )
            {
                delRequest.setMessageId( ParserUtils.parseAndVerifyRequestID( attributeValue, xpp ) );
            }
            else
            {
                if ( ParserUtils.isRequestIdNeeded( container ) )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03000_REQUEST_ID_REQUIRED ), xpp, null );
                }
            }

            // dn
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.DN );

            if ( attributeValue != null )
            {
                try
                {
                    delRequest.setName( new Dn( attributeValue ) );
                }
                catch ( LdapInvalidDnException lide )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03039_PARSING_ERROR, lide.getMessage() ), xpp, lide );
                }
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03001_DN_ATTRIBUTE_REQUIRED ), xpp, null );
            }
        }
    };

    /**
     * GrammarAction that creates an Extended Request
     */
    private final GrammarAction extendedRequestCreation = new GrammarAction( "Create Extended Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            ExtendedRequestDsml<?, ?> extendedRequest =
                new ExtendedRequestDsml<>( codec,
                    new OpaqueExtendedRequest() );
            container.getBatchRequest().addRequest( extendedRequest );

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attributes
            String attributeValue;
            // requestID
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.REQUEST_ID );

            if ( attributeValue != null )
            {
                extendedRequest.setMessageId( ParserUtils.parseAndVerifyRequestID( attributeValue, xpp ) );
            }
            else
            {
                if ( ParserUtils.isRequestIdNeeded( container ) )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03000_REQUEST_ID_REQUIRED ), xpp, null );
                }
            }
        }
    };

    /**
     * GrammarAction that adds a Name to an Extended Request
     */
    private final GrammarAction extendedRequestAddName = new GrammarAction( "Add Name to Extended Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            ExtendedRequestDsml<?, ?> extendedRequest = ( ExtendedRequestDsml<?, ?> )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            try
            {
                String nextText = xpp.nextText();

                if ( Strings.isEmpty( nextText ) )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03022_NULL_REQUEST_NAME ), xpp, null );
                }
                else
                {
                    String oid = nextText.trim();

                    if ( Oid.isOid( oid ) )
                    {
                        extendedRequest.setRequestName( nextText.trim() );
                    }
                    else
                    {
                        throw new XmlPullParserException( I18n.err( I18n.ERR_03038_BAD_OID, oid ), xpp, null );
                    }
                }
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03008_UNEXPECTED_ERROR, ioe.getMessage() ), xpp, ioe );
            }
        }
    };

    /**
     * GrammarAction that adds a Value to an Extended Request
     */
    private final GrammarAction extendedRequestAddValue = new GrammarAction( "Add Value to Extended Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            ExtendedRequestDsml<?, ?> extendedRequest = ( ExtendedRequestDsml<?, ?> )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            try
            {
                // We have to catch the type Attribute Value before going to the next Text node
                String typeValue = ParserUtils.getXsiTypeAttributeValue( xpp );

                // Getting the value
                String nextText = xpp.nextText();

                if ( !Strings.isEmpty( nextText ) )
                {
                    if ( ParserUtils.isBase64BinaryValue( xpp, typeValue ) )
                    {
                        extendedRequest.setRequestValue( Base64.getDecoder().decode( nextText.trim() ) );
                    }
                    else
                    {
                        extendedRequest.setRequestValue( Strings.getBytesUtf8( nextText.trim() ) );
                    }
                }
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03008_UNEXPECTED_ERROR, ioe.getMessage() ), xpp, ioe );
            }
        }
    };

    /**
     * GrammarAction that creates a Modify Dn Request
     */
    private final GrammarAction modDNRequestCreation = new GrammarAction( "Create Modify Dn Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            ModifyDNRequestDsml modifyDNRequest = new ModifyDNRequestDsml( codec, new ModifyDnRequestImpl() );
            container.getBatchRequest().addRequest( modifyDNRequest );

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attributes
            String attributeValue;
            // requestID
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.REQUEST_ID );

            if ( attributeValue != null )
            {
                modifyDNRequest.setMessageId( ParserUtils.parseAndVerifyRequestID( attributeValue, xpp ) );
            }
            else
            {
                if ( ParserUtils.isRequestIdNeeded( container ) )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03000_REQUEST_ID_REQUIRED ), xpp, null );
                }
            }

            // dn
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.DN );

            if ( attributeValue != null )
            {
                try
                {
                    modifyDNRequest.setName( new Dn( attributeValue ) );
                }
                catch ( LdapInvalidDnException lide )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03039_PARSING_ERROR, lide.getMessage() ), xpp, lide );
                }
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03001_DN_ATTRIBUTE_REQUIRED ), xpp, null );
            }

            // newrdn
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NEW_RDN );

            if ( attributeValue != null )
            {
                try
                {
                    modifyDNRequest.setNewRdn( new Rdn( attributeValue ) );
                }
                catch ( LdapInvalidDnException lide )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03039_PARSING_ERROR, lide.getMessage() ), xpp, lide );
                }
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03023_NEW_RDN_ATTRIBUTE_REQUESTED ), xpp, null );
            }

            // deleteoldrdn
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.DELETE_OLD_RDN );

            if ( attributeValue != null )
            {
                if ( ( attributeValue.equalsIgnoreCase( DsmlLiterals.TRUE ) ) || ( "1".equals( attributeValue ) ) )
                {
                    modifyDNRequest.setDeleteOldRdn( true );
                }
                else if ( ( attributeValue.equalsIgnoreCase( DsmlLiterals.FALSE ) ) || ( "0".equals( attributeValue ) ) )
                {
                    modifyDNRequest.setDeleteOldRdn( false );
                }
                else
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03024_INCORRECT_DELETE_OLD_RDN_VALUE ), xpp, null );
                }
            }
            else
            {
                modifyDNRequest.setDeleteOldRdn( true );
            }

            // newsuperior
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NEW_SUPERIOR );

            if ( attributeValue != null )
            {
                try
                {
                    modifyDNRequest.setNewSuperior( new Dn( attributeValue ) );
                }
                catch ( LdapInvalidDnException lide )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03039_PARSING_ERROR, lide.getMessage() ), xpp, lide );
                }
            }
        }
    };

    /**
     * GrammarAction that creates a Modify Request
     */
    private final GrammarAction modifyRequestCreation = new GrammarAction( "Create Modify Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            ModifyRequestDsml modifyRequest = new ModifyRequestDsml( codec, new ModifyRequestImpl() );
            container.getBatchRequest().addRequest( modifyRequest );

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attributes
            String attributeValue;
            // requestID
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.REQUEST_ID );

            if ( attributeValue != null )
            {
                modifyRequest.setMessageId( ParserUtils.parseAndVerifyRequestID( attributeValue, xpp ) );
            }
            else
            {
                if ( ParserUtils.isRequestIdNeeded( container ) )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03000_REQUEST_ID_REQUIRED ), xpp, null );
                }
            }

            // dn
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.DN );

            if ( attributeValue != null )
            {
                try
                {
                    modifyRequest.setName( new Dn( attributeValue ) );
                }
                catch ( LdapInvalidDnException lide )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03039_PARSING_ERROR, lide.getLocalizedMessage() ), xpp, lide );
                }
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03001_DN_ATTRIBUTE_REQUIRED ), xpp, null );
            }
        }
    };

    /**
     * GrammarAction that adds a Modification to a Modify Request
     */
    private final GrammarAction modifyRequestAddModification = new GrammarAction( "Adds Modification to Modify Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            ModifyRequestDsml modifyRequest = ( ModifyRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attributes
            String attributeValue;
            // operation
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.OPERATION );

            if ( attributeValue != null )
            {
                if ( DsmlLiterals.ADD.equals( attributeValue ) )
                {
                    modifyRequest.setCurrentOperation( LdapCodecConstants.OPERATION_ADD );
                }
                else if ( DsmlLiterals.DELETE.equals( attributeValue ) )
                {
                    modifyRequest.setCurrentOperation( LdapCodecConstants.OPERATION_DELETE );
                }
                else if ( DsmlLiterals.REPLACE.equals( attributeValue ) )
                {
                    modifyRequest.setCurrentOperation( LdapCodecConstants.OPERATION_REPLACE );
                }
                else if ( DsmlLiterals.INCREMENT.equals( attributeValue ) )
                {
                    modifyRequest.setCurrentOperation( LdapCodecConstants.OPERATION_INCREMENT );
                }
                else
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03040_UNKNOWN_OPERATION ), xpp, null );
                }
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03025_OPERATION_TTRIBUTE_REQUIRED ), xpp, null );
            }

            // name
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NAME );

            if ( attributeValue != null )
            {
                modifyRequest.addAttributeTypeAndValues( attributeValue );
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03002_NAME_ATTRIBUTE_REQUIRED ), xpp, null );
            }
        }
    };

    /**
     * GrammarAction that adds a Value to a Modification of a Modify Request
     */
    private final GrammarAction modifyRequestAddValue = new GrammarAction(
        "Add Value to Modification of Modify Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            ModifyRequestDsml modifyRequest = ( ModifyRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            try
            {
                // We have to catch the type Attribute Value before going to the next Text node
                String typeValue = ParserUtils.getXsiTypeAttributeValue( xpp );

                // Getting the value
                String nextText = xpp.nextText();
                // We are testing if nextText equals "" since a modification can be "".

                try
                {
                    if ( ParserUtils.isBase64BinaryValue( xpp, typeValue ) )
                    {
                        modifyRequest.addAttributeValue( Base64.getDecoder().decode( nextText.trim() ) );
                    }
                    else
                    {
                        modifyRequest.addAttributeValue( nextText.trim() );
                    }
                }
                catch ( LdapException le )
                {
                    throw new XmlPullParserException( le.getMessage(), xpp, le );
                }
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03008_UNEXPECTED_ERROR, ioe.getMessage() ), xpp, ioe );
            }
        }
    };

    /**
     * GrammarAction that creates a Search Request
     */
    private final GrammarAction searchRequestCreation = new GrammarAction( "Create Search Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequest = new SearchRequestDsml( codec, new SearchRequestImpl() );
            container.getBatchRequest().addRequest( searchRequest );

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attributes
            String attributeValue;
            // requestID
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.REQUEST_ID );

            if ( attributeValue != null )
            {
                searchRequest.setMessageId( ParserUtils.parseAndVerifyRequestID( attributeValue, xpp ) );
            }
            else
            {
                if ( ParserUtils.isRequestIdNeeded( container ) )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03000_REQUEST_ID_REQUIRED ), xpp, null );
                }
            }

            // dn
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.DN );

            if ( attributeValue != null )
            {
                try
                {
                    searchRequest.setBase( new Dn( attributeValue ) );
                }
                catch ( LdapInvalidDnException lide )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03039_PARSING_ERROR, lide.getMessage() ), xpp, lide );
                }
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03001_DN_ATTRIBUTE_REQUIRED ), xpp, null );
            }

            // scope
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.SCOPE );

            if ( attributeValue != null )
            {
                if ( DsmlLiterals.BASE_OBJECT.equals( attributeValue ) )
                {
                    searchRequest.setScope( SearchScope.OBJECT );
                }
                else if ( DsmlLiterals.SINGLE_LEVEL.equals( attributeValue ) )
                {
                    searchRequest.setScope( SearchScope.ONELEVEL );
                }
                else if ( DsmlLiterals.WHOLE_SUBTREE.equals( attributeValue ) )
                {
                    searchRequest.setScope( SearchScope.SUBTREE );
                }
                else
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03026_UNKNOWN_SCOPE ), xpp, null );
                }
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03027_SCOPE_ATTRIBUTE_REQUIRED ), xpp, null );
            }

            // derefAliases
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.DEREF_ALIASES );

            if ( attributeValue != null )
            {
                if ( DsmlLiterals.NEVER_DEREF_ALIASES.equals( attributeValue ) )
                {
                    searchRequest.setDerefAliases( AliasDerefMode.NEVER_DEREF_ALIASES );
                }
                else if ( DsmlLiterals.DEREF_IN_SEARCHING.equals( attributeValue ) )
                {
                    searchRequest.setDerefAliases( AliasDerefMode.DEREF_IN_SEARCHING );
                }
                else if ( DsmlLiterals.DEREF_FINDING_BASE_OBJ.equals( attributeValue ) )
                {
                    searchRequest.setDerefAliases( AliasDerefMode.DEREF_FINDING_BASE_OBJ );
                }
                else if ( DsmlLiterals.DEREF_ALWAYS.equals( attributeValue ) )
                {
                    searchRequest.setDerefAliases( AliasDerefMode.DEREF_ALWAYS );
                }
                else
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03028_UNKNOWN_DEREFALIAS_VALUE ), xpp, null );
                }
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03029_DEREFALIA_ATTRIBUTE_REQUIRED ), xpp, null );
            }

            // sizeLimit
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.SIZE_LIMIT );

            if ( attributeValue != null )
            {
                try
                {
                    searchRequest.setSizeLimit( Long.parseLong( attributeValue ) );
                }
                catch ( NumberFormatException nfe )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03030_SIZE_LIMIT_NOT_INTEGER ), xpp, nfe );
                }
            }
            else
            {
                searchRequest.setSizeLimit( 0L );
            }

            // timeLimit
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.TIME_LIMIT );

            if ( attributeValue != null )
            {
                try
                {
                    searchRequest.setTimeLimit( Integer.parseInt( attributeValue ) );
                }
                catch ( NumberFormatException nfe )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03031_TIME_LIMIT_NOT_INTEGER ), xpp, nfe );
                }
            }
            else
            {
                searchRequest.setTimeLimit( 0 );
            }

            // typesOnly
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.TYPES_ONLY );

            if ( attributeValue != null )
            {
                if ( ( attributeValue.equals( DsmlLiterals.TRUE ) ) || ( "1".equals( attributeValue ) ) )
                {
                    searchRequest.setTypesOnly( true );
                }
                else if ( ( attributeValue.equals( DsmlLiterals.FALSE ) ) || ( "0".equals( attributeValue ) ) )
                {
                    searchRequest.setTypesOnly( false );
                }
                else
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03032_TYPES_ONLY_NOT_BOOLEAN ), xpp, null );
                }
            }
            else
            {
                searchRequest.setTypesOnly( false );
            }
        }
    };

    /**
     * GrammarAction that adds an Attribute to a Search Request
     */
    private final GrammarAction searchRequestAddAttribute = new GrammarAction(
        "Add Value to Modification of Modify Request" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequest searchRequest = ( SearchRequest ) container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            // Checking and adding the request's attribute name
            String attributeName = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NAME );

            if ( attributeName != null )
            {
                searchRequest.addAttributes( attributeName );
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03002_NAME_ATTRIBUTE_REQUIRED ), xpp, null );
            }
        }
    };

    /**
     * GrammarAction that create a Substring Filter
     */
    private final GrammarAction substringsFilterCreation = new GrammarAction( "Create Substring Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            SubstringFilter filter = new SubstringFilter();

            // Adding the filter to the Search Filter
            try
            {
                searchRequestDecorator.addCurrentFilter( filter );
            }
            catch ( DecoderException de )
            {
                throw new XmlPullParserException( de.getMessage(), xpp, de );
            }

            searchRequestDecorator.setTerminalFilter( filter );

            // Checking and adding the filter's attributes
            String attributeValue;
            // name
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NAME );

            if ( attributeValue != null )
            {
                filter.setType( attributeValue );
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03002_NAME_ATTRIBUTE_REQUIRED ), xpp, null );
            }
        }
    };

    /**
     * GrammarAction that sets the Initial value to a Substring Filter
     */
    private final GrammarAction substringsFilterSetInitial = new GrammarAction( "Set Initial value to Substring Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            SubstringFilter substringFilter = ( SubstringFilter )
                searchRequestDecorator.getTerminalFilter();

            XmlPullParser xpp = container.getParser();

            try
            {
                // We have to catch the type Attribute Value before going to the next Text node
                String typeValue = ParserUtils.getXsiTypeAttributeValue( xpp );

                // Getting the value
                String nextText = xpp.nextText();

                if ( !Strings.isEmpty( nextText ) )
                {
                    if ( ParserUtils.isBase64BinaryValue( xpp, typeValue ) )
                    {
                        substringFilter
                            .setInitialSubstrings( Strings.utf8ToString( Base64.getDecoder().decode( nextText.trim() ) ) );
                    }
                    else
                    {
                        substringFilter.setInitialSubstrings( nextText.trim() );
                    }
                }
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03008_UNEXPECTED_ERROR, ioe.getMessage() ), xpp, ioe );
            }
        }
    };

    /**
     * GrammarAction that adds a Any value to a Substring Filter
     */
    private final GrammarAction substringsFilterAddAny = new GrammarAction( "Add Any value to Substring Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            SubstringFilter substringFilter = ( SubstringFilter ) searchRequestDecorator.getTerminalFilter();

            XmlPullParser xpp = container.getParser();

            try
            {
                // We have to catch the type Attribute Value before going to the next Text node
                String typeValue = ParserUtils.getXsiTypeAttributeValue( xpp );

                // Getting the value
                String nextText = xpp.nextText();

                if ( !Strings.isEmpty( nextText ) )
                {
                    if ( ParserUtils.isBase64BinaryValue( xpp, typeValue ) )
                    {
                        substringFilter.addAnySubstrings( Strings.utf8ToString( 
                            Base64.getDecoder().decode( nextText.trim() ) ) );
                    }
                    else
                    {
                        substringFilter.addAnySubstrings( nextText.trim() );
                    }
                }
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03008_UNEXPECTED_ERROR, ioe.getMessage() ), xpp, ioe );
            }
        }
    };

    /**
     * GrammarAction that sets the Final value to a Substring Filter
     */
    private final GrammarAction substringsFilterSetFinal = new GrammarAction( "Set Final value to Substring Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            SubstringFilter substringFilter = ( SubstringFilter ) searchRequestDecorator.getTerminalFilter();

            XmlPullParser xpp = container.getParser();

            try
            {
                // We have to catch the type Attribute Value before going to the next Text node
                String typeValue = ParserUtils.getXsiTypeAttributeValue( xpp );

                // Getting the value
                String nextText = xpp.nextText();

                if ( !Strings.isEmpty( nextText ) )
                {
                    if ( ParserUtils.isBase64BinaryValue( xpp, typeValue ) )
                    {
                        substringFilter
                            .setFinalSubstrings( Strings.utf8ToString( 
                                Base64.getDecoder().decode( nextText.trim() ) ) );
                    }
                    else
                    {
                        substringFilter.setFinalSubstrings( nextText.trim() );
                    }
                }
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03008_UNEXPECTED_ERROR, ioe.getMessage() ), xpp, ioe );
            }
        }
    };

    /**
     * GrammarAction that closes a Substring Filter
     */
    private final GrammarAction substringsFilterClose = new GrammarAction( "Close Substring Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            searchRequestDecorator.setTerminalFilter( null );
        }
    };

    /**
     * GrammarAction that create a And Filter
     */
    private final GrammarAction andFilterCreation = new GrammarAction( "Create And Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            AndFilter filter = new AndFilter();

            // Adding the filter to the Search Filter
            try
            {
                searchRequestDecorator.addCurrentFilter( filter );
            }
            catch ( DecoderException de )
            {
                throw new XmlPullParserException( de.getMessage(), xpp, de );
            }
        }
    };

    /**
     * GrammarAction that closes a Connector Filter (And, Or, Not)
     */
    private final GrammarAction connectorFilterClose = new GrammarAction( "Close Connector Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            searchRequestDecorator.endCurrentConnectorFilter();
        }
    };

    /**
     * GrammarAction that create a Or Filter
     */
    private final GrammarAction orFilterCreation = new GrammarAction( "Create Or Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            OrFilter filter = new OrFilter();

            // Adding the filter to the Search Filter
            try
            {
                searchRequestDecorator.addCurrentFilter( filter );
            }
            catch ( DecoderException de )
            {
                throw new XmlPullParserException( de.getMessage(), xpp, de );
            }
        }
    };

    /**
     * GrammarAction that create a Not Filter
     */
    private final GrammarAction notFilterCreation = new GrammarAction( "Create Not Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            NotFilter filter = new NotFilter();

            // Adding the filter to the Search Filter
            try
            {
                searchRequestDecorator.addCurrentFilter( filter );
            }
            catch ( DecoderException de )
            {
                throw new XmlPullParserException( de.getMessage(), xpp, de );
            }
        }
    };

    /**
     * GrammarAction that create a Equality Match Filter
     */
    private final GrammarAction equalityMatchFilterCreation = new GrammarAction( "Create Equality Match Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            AttributeValueAssertion assertion = new AttributeValueAssertion();

            // Checking and adding the filter's attributes
            String attributeName = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NAME );

            if ( attributeName != null )
            {
                assertion.setAttributeDesc( attributeName );
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03002_NAME_ATTRIBUTE_REQUIRED ), xpp, null );
            }

            AttributeValueAssertionFilter filter = new AttributeValueAssertionFilter(
                LdapCodecConstants.EQUALITY_MATCH_FILTER );

            filter.setAssertion( assertion );

            // Adding the filter to the Search Filter
            try
            {
                searchRequestDecorator.addCurrentFilter( filter );
            }
            catch ( DecoderException de )
            {
                throw new XmlPullParserException( de.getMessage(), xpp, de );
            }

            searchRequestDecorator.setTerminalFilter( filter );
        }
    };

    /**
     * GrammarAction that create a Greater Or Equal Filter
     */
    private final GrammarAction greaterOrEqualFilterCreation = new GrammarAction( "Create Greater Or Equal Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            AttributeValueAssertion assertion = new AttributeValueAssertion();

            // Checking and adding the filter's attributes
            String attributeName = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NAME );

            if ( attributeName != null )
            {
                assertion.setAttributeDesc( attributeName );
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03002_NAME_ATTRIBUTE_REQUIRED ), xpp, null );
            }

            AttributeValueAssertionFilter filter = new AttributeValueAssertionFilter(
                LdapCodecConstants.GREATER_OR_EQUAL_FILTER );

            filter.setAssertion( assertion );

            // Adding the filter to the Search Filter
            try
            {
                searchRequestDecorator.addCurrentFilter( filter );
            }
            catch ( DecoderException de )
            {
                throw new XmlPullParserException( de.getMessage(), xpp, de );
            }

            searchRequestDecorator.setTerminalFilter( filter );
        }
    };

    /**
     * GrammarAction that create a Less Or Equal Filter
     */
    private final GrammarAction lessOrEqualFilterCreation = new GrammarAction( "Create Less Or Equal Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            AttributeValueAssertion assertion = new AttributeValueAssertion();

            // Checking and adding the filter's attributes
            String attributeValue;
            // name
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NAME );

            if ( attributeValue != null )
            {
                assertion.setAttributeDesc( attributeValue );
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03002_NAME_ATTRIBUTE_REQUIRED ), xpp, null );
            }

            AttributeValueAssertionFilter filter = new AttributeValueAssertionFilter(
                LdapCodecConstants.LESS_OR_EQUAL_FILTER );

            filter.setAssertion( assertion );

            // Adding the filter to the Search Filter
            try
            {
                searchRequestDecorator.addCurrentFilter( filter );
            }
            catch ( DecoderException de )
            {
                throw new XmlPullParserException( de.getMessage(), xpp, de );
            }

            searchRequestDecorator.setTerminalFilter( filter );
        }
    };

    /**
     * GrammarAction that create an Approx Match Filter
     */
    private final GrammarAction approxMatchFilterCreation = new GrammarAction( "Create Approx Match Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            XmlPullParser xpp = container.getParser();

            AttributeValueAssertion assertion = new AttributeValueAssertion();

            // Checking and adding the filter's attributes
            String attributeName = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NAME );

            if ( attributeName != null )
            {
                assertion.setAttributeDesc( attributeName );
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03002_NAME_ATTRIBUTE_REQUIRED ), xpp, null );
            }

            AttributeValueAssertionFilter filter = new AttributeValueAssertionFilter(
                LdapCodecConstants.APPROX_MATCH_FILTER );

            filter.setAssertion( assertion );

            // Adding the filter to the Search Filter
            try
            {
                searchRequestDecorator.addCurrentFilter( filter );
            }
            catch ( DecoderException de )
            {
                throw new XmlPullParserException( de.getMessage(), xpp, de );
            }

            searchRequestDecorator.setTerminalFilter( filter );
        }
    };

    /**
     * GrammarAction that adds a Value to a Filter
     */
    private final GrammarAction filterAddValue = new GrammarAction( "Adds Value to Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();
            AttributeValueAssertionFilter filter = ( AttributeValueAssertionFilter ) searchRequestDecorator
                .getTerminalFilter();
            AttributeValueAssertion assertion = filter.getAssertion();

            XmlPullParser xpp = container.getParser();

            try
            {
                // We have to catch the type Attribute Value before going to the next Text node
                String typeValue = ParserUtils.getXsiTypeAttributeValue( xpp );

                // Getting the value
                String nextText = xpp.nextText();

                if ( !Strings.isEmpty( nextText ) )
                {
                    if ( ParserUtils.isBase64BinaryValue( xpp, typeValue ) )
                    {
                        Value value = new Value( Base64.getDecoder().decode( nextText.trim() ) );
                        assertion.setAssertionValue( value );
                    }
                    else
                    {
                        Value value = new Value( nextText.trim() );
                        assertion.setAssertionValue( value );
                    }
                }
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03008_UNEXPECTED_ERROR, ioe.getMessage() ), xpp, ioe );
            }
        }
    };

    /**
     * GrammarAction that creates a Present Filter
     */
    private final GrammarAction presentFilterCreation = new GrammarAction( "Create Present Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            PresentFilter presentFilter = new PresentFilter();

            XmlPullParser xpp = container.getParser();

            // Adding the filter to the Search Filter
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            try
            {
                searchRequestDecorator.addCurrentFilter( presentFilter );
            }
            catch ( DecoderException de )
            {
                throw new XmlPullParserException( de.getMessage(), xpp, de );
            }

            // Checking and adding the filter's attributes
            String attributeValue;
            // name
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NAME );

            if ( attributeValue != null )
            {
                presentFilter.setAttributeDescription( attributeValue );
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03002_NAME_ATTRIBUTE_REQUIRED ), xpp, null );
            }
        }
    };

    /**
     * GrammarAction that store the Filter into the searchRequest
     */
    private final GrammarAction storeFilter = new GrammarAction( "Store Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            // Adding the filter to the Search Filter
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();
            SearchRequest searchRequest = searchRequestDecorator.getDecorated();

            try
            {
                ExprNode exprNode = searchRequestDecorator.getFilterNode();

                if ( exprNode == null )
                {
                    throw new IllegalStateException( I18n.err( I18n.ERR_03041_NO_FILTER_ELEMENT ) );
                }

                searchRequest.setFilter( exprNode );
            }
            catch ( LdapSchemaException lse )
            {

            }
        }
    };

    /**
     * GrammarAction that creates an Extensible Match Filter
     */
    private final GrammarAction extensibleMatchFilterCreation = new GrammarAction( "Create Extensible Match Filter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            ExtensibleMatchFilter extensibleMatchFilter = new ExtensibleMatchFilter();

            XmlPullParser xpp = container.getParser();

            // Adding the filter to the Search Filter
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();

            try
            {
                searchRequestDecorator.addCurrentFilter( extensibleMatchFilter );
            }
            catch ( DecoderException de )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03002_NAME_ATTRIBUTE_REQUIRED ), xpp, de );
            }

            searchRequestDecorator.setTerminalFilter( extensibleMatchFilter );

            // Checking and adding the filter's attributes
            String attributeValue;
            // dnAttributes
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.DN_ATTRIBUTES );

            if ( attributeValue != null )
            {
                if ( ( attributeValue.equals( DsmlLiterals.TRUE ) ) || ( "1".equals( attributeValue ) ) )
                {
                    extensibleMatchFilter.setDnAttributes( true );
                }
                else if ( ( attributeValue.equals( DsmlLiterals.FALSE ) ) || ( "0".equals( attributeValue ) ) )
                {
                    extensibleMatchFilter.setDnAttributes( false );
                }
                else
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03033_DN_ATTRIBUTES_NOT_BOOLEAN ), xpp, null );
                }
            }
            else
            {
                extensibleMatchFilter.setDnAttributes( false );
            }

            // matchingRule
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING,  DsmlLiterals.MATCHING_RULE );

            if ( attributeValue != null )
            {
                extensibleMatchFilter.setMatchingRule( attributeValue );
            }

            // name
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.NAME );

            if ( attributeValue != null )
            {
                extensibleMatchFilter.setType( attributeValue );
            }
        }
    };

    /**
     * GrammarAction that adds a Value to an Extensible Match Filter
     */
    private final GrammarAction extensibleMatchAddValue = new GrammarAction( "Adds Value to Extensible MatchFilter" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            SearchRequestDsml searchRequestDecorator = ( SearchRequestDsml )
                container.getBatchRequest().getCurrentRequest();
            ExtensibleMatchFilter filter = ( ExtensibleMatchFilter ) searchRequestDecorator.getTerminalFilter();

            XmlPullParser xpp = container.getParser();

            try
            {
                // We have to catch the type Attribute Value before going to the next Text node
                String typeValue = ParserUtils.getXsiTypeAttributeValue( xpp );

                // Getting the value
                String nextText = xpp.nextText();

                if ( !Strings.isEmpty( nextText ) )
                {
                    if ( ParserUtils.isBase64BinaryValue( xpp, typeValue ) )
                    {
                        filter.setMatchValue( new Value( Base64.getDecoder().decode( nextText.trim() ) ) );
                    }
                    else
                    {
                        filter.setMatchValue( new Value( nextText.trim() ) );
                    }
                }
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03008_UNEXPECTED_ERROR, ioe.getMessage() ), xpp, ioe );
            }
        }
    };

    /**
     * GrammarAction that creates a Control
     */
    private final GrammarAction controlCreation = new GrammarAction( "Create Control" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            XmlPullParser xpp = container.getParser();
            Control control;

            // Checking and adding the Control's attributes
            String attributeValue;
            
            // TYPE
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.TYPE );

            if ( attributeValue != null )
            {
                if ( !Oid.isOid( attributeValue ) )
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03034_INCORRECT_TYPE_VALUE ), xpp, null );
                }
                
                ControlFactory<? extends Control> factory = codec.getRequestControlFactories().get( attributeValue );
                
                if ( factory == null )
                {
                    control = new OpaqueControl( attributeValue );
                }
                else
                {
                    control = factory.newControl();
                }
                
                ( ( Request ) container.getBatchRequest().getCurrentRequest() ).addControl( control );
            }
            else
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03035_TYPE_ATTRIBUTE_REQUIRED ), xpp, null );
            }

            // CRITICALITY
            attributeValue = xpp.getAttributeValue( Strings.EMPTY_STRING, DsmlLiterals.CRITICALITY );

            if ( attributeValue != null )
            {
                if ( attributeValue.equals( DsmlLiterals.TRUE ) )
                {
                    control.setCritical( true );
                }
                else if ( attributeValue.equals( DsmlLiterals.FALSE ) )
                {
                    control.setCritical( false );
                }
                else
                {
                    throw new XmlPullParserException( I18n.err( I18n.ERR_03007_INCORRECT_CRITICALITY_VALUE ), xpp, null );
                }
            }
        }
    };

    /**
     * GrammarAction that adds a Value to a Control
     */
    private final GrammarAction controlValueCreation = new GrammarAction( "Add ControlValue to Control" )
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public void action( Dsmlv2Container container ) throws XmlPullParserException
        {
            AbstractRequestDsml<? extends Request> request =
                ( AbstractRequestDsml<? extends Request> ) container.getBatchRequest().getCurrentRequest();
            DsmlControl<? extends Control> control = request.getCurrentControl();

            XmlPullParser xpp = container.getParser();

            try
            {
                // We have to catch the type Attribute Value before going to the next Text node
                String typeValue = ParserUtils.getXsiTypeAttributeValue( xpp );

                // Getting the value
                String nextText = xpp.nextText();

                if ( !Strings.isEmpty( nextText ) )
                {
                    if ( ParserUtils.isBase64BinaryValue( xpp, typeValue ) )
                    {
                        control.setValue( Base64.getDecoder().decode( nextText.trim() ) );
                    }
                    else
                    {
                        control.setValue( Strings.getBytesUtf8( nextText.trim() ) );
                    }
                }
            }
            catch ( IOException ioe )
            {
                throw new XmlPullParserException( I18n.err( I18n.ERR_03008_UNEXPECTED_ERROR, ioe.getMessage() ), xpp, ioe );
            }
        }
    };


    /**
     * Creates a new instance of Dsmlv2Grammar.
     */
    @SuppressWarnings("unchecked")
    public Dsmlv2Grammar()
    {
        name = Dsmlv2Grammar.class.getName();

        // Create the transitions table
        super.transitions = ( HashMap<Tag, GrammarTransition>[] ) Array.newInstance( HashMap.class, 200 );

        //====================================================
        //  Transitions concerning : BATCH REQUEST
        //====================================================
        super.transitions[Dsmlv2StatesEnum.INIT_GRAMMAR_STATE.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_LOOP.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // ** OPEN BATCH REQUEST **
        // State: [INIT_GRAMMAR_STATE] - Tag: <batchRequest>
        super.transitions[Dsmlv2StatesEnum.INIT_GRAMMAR_STATE.ordinal()].put( new Tag( DsmlLiterals.BATCH_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.INIT_GRAMMAR_STATE, Dsmlv2StatesEnum.BATCHREQUEST_START_TAG,
                batchRequestCreation ) );

        // ** CLOSE BATCH REQUEST **
        // state: [BATCHREQUEST_START_TAG] - Tag: </batchRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_START_TAG.ordinal()]
            .put( new Tag( DsmlLiterals.BATCH_REQUEST, Tag.END ), new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_START_TAG,
                Dsmlv2StatesEnum.BATCHREQUEST_END_TAG, null ) );
        //state: [BATCHREQUEST_LOOP] - Tag: </batchRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_LOOP.ordinal()].put( new Tag( DsmlLiterals.BATCH_REQUEST, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_LOOP, Dsmlv2StatesEnum.GRAMMAR_END, null ) );

        // ** ABANDON REQUEST **
        // State: [BATCHREQUEST_START_TAG] - Tag: <abandonRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.ABANDON_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_START_TAG, Dsmlv2StatesEnum.ABANDON_REQUEST_START_TAG,
                abandonRequestCreation ) );
        // state: [BATCHREQUEST_LOOP] - Tag: <abandonRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_LOOP.ordinal()].put( new Tag( DsmlLiterals.ABANDON_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_LOOP, Dsmlv2StatesEnum.ABANDON_REQUEST_START_TAG,
                abandonRequestCreation ) );

        // ** ADD REQUEST **
        // state: [BATCHREQUEST_START_TAG] - Tag: <addRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.ADD_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_START_TAG, Dsmlv2StatesEnum.ADD_REQUEST_START_TAG,
                addRequestCreation ) );
        // state: [BATCHREQUEST_LOOP] - Tag: <addRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_LOOP.ordinal()].put( new Tag( DsmlLiterals.ADD_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_LOOP, Dsmlv2StatesEnum.ADD_REQUEST_START_TAG,
                addRequestCreation ) );

        // ** AUTH REQUEST **
        // state: [BATCHREQUEST_START_TAG] - Tag: <authRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.AUTH_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_START_TAG, Dsmlv2StatesEnum.AUTH_REQUEST_START_TAG,
                authRequestCreation ) );

        // ** COMPARE REQUEST **
        // state: [BATCHREQUEST_START_TAG] - Tag: <compareRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.COMPARE_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_START_TAG, Dsmlv2StatesEnum.COMPARE_REQUEST_START_TAG,
                compareRequestCreation ) );
        // state: [BATCHREQUEST_LOOP] - Tag: <compareRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_LOOP.ordinal()].put( new Tag( DsmlLiterals.COMPARE_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_LOOP, Dsmlv2StatesEnum.COMPARE_REQUEST_START_TAG,
                compareRequestCreation ) );

        // ** DEL REQUEST **
        // state: [BATCHREQUEST_START_TAG] - Tag: <delRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.DEL_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_START_TAG, Dsmlv2StatesEnum.DEL_REQUEST_START_TAG,
                delRequestCreation ) );
        // state: [BATCHREQUEST_LOOP] - Tag: <delRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_LOOP.ordinal()].put( new Tag( DsmlLiterals.DEL_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_LOOP, Dsmlv2StatesEnum.DEL_REQUEST_START_TAG,
                delRequestCreation ) );

        // ** EXTENDED REQUEST **
        // state: [BATCHREQUEST_START_TAG] - Tag: <extendedRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.EXTENDED_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_START_TAG,
                Dsmlv2StatesEnum.EXTENDED_REQUEST_START_TAG, extendedRequestCreation ) );
        // state: [BATCHREQUEST_LOOP] - Tag: <extendedRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_LOOP.ordinal()].put( new Tag( DsmlLiterals.EXTENDED_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_LOOP, Dsmlv2StatesEnum.EXTENDED_REQUEST_START_TAG,
                extendedRequestCreation ) );

        // ** MOD Dn REQUEST **
        // state: [BATCHREQUEST_START_TAG] - Tag: <modDNRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.MOD_DN_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_START_TAG,
                Dsmlv2StatesEnum.MODIFY_DN_REQUEST_START_TAG, modDNRequestCreation ) );
        // state: [BATCHREQUEST_LOOP] - Tag: <modDNRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_LOOP.ordinal()].put( new Tag( DsmlLiterals.MOD_DN_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_LOOP, Dsmlv2StatesEnum.MODIFY_DN_REQUEST_START_TAG,
                modDNRequestCreation ) );

        // ** MODIFY REQUEST **
        // state: [BATCHREQUEST_START_TAG] - Tag: <modifyRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.MODIFY_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_START_TAG, Dsmlv2StatesEnum.MODIFY_REQUEST_START_TAG,
                modifyRequestCreation ) );
        // state: [BATCHREQUEST_LOOP] - Tag: <modifyRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_LOOP.ordinal()].put( new Tag( DsmlLiterals.MODIFY_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_LOOP, Dsmlv2StatesEnum.MODIFY_REQUEST_START_TAG,
                modifyRequestCreation ) );

        // ** SEARCH REQUEST **
        // state: [BATCHREQUEST_START_TAG] - Tag: <searchRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.SEARCH_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_START_TAG, Dsmlv2StatesEnum.SEARCH_REQUEST_START_TAG,
                searchRequestCreation ) );
        // state: [BATCHREQUEST_LOOP] - Tag: <searchRequest>
        super.transitions[Dsmlv2StatesEnum.BATCHREQUEST_LOOP.ordinal()].put( new Tag( DsmlLiterals.SEARCH_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.BATCHREQUEST_LOOP, Dsmlv2StatesEnum.SEARCH_REQUEST_START_TAG,
                searchRequestCreation ) );

        //====================================================
        //  Transitions concerning : ABANDON REQUEST
        //====================================================
        super.transitions[Dsmlv2StatesEnum.ABANDON_REQUEST_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROLVALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // State: [ABANDON_REQUEST_START_TAG] - Tag: </abandonRequest>
        super.transitions[Dsmlv2StatesEnum.ABANDON_REQUEST_START_TAG.ordinal()]
            .put( new Tag( DsmlLiterals.ABANDON_REQUEST, Tag.END ), new GrammarTransition(
                Dsmlv2StatesEnum.ABANDON_REQUEST_START_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        // State: [ABANDON_REQUEST_START_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.ABANDON_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.ABANDON_REQUEST_START_TAG,
                Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [ABANDON_REQUEST_CONTROL_START_TAG] - Tag: <controlValue>
        super.transitions[Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.CONTROL_VALUE, Tag.START ), new GrammarTransition(
                Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROLVALUE_END_TAG, controlValueCreation ) );

        // State: [ABANDON_REQUEST_CONTROLVALUE_END_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROLVALUE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROLVALUE_END_TAG,
                Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_END_TAG, null ) );

        // State: [ABANDON_REQUEST_CONTROL_START_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_END_TAG, null ) );

        // State: [ABANDON_REQUEST_CONTROL_END_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [ABANDON_REQUEST_CONTROL_END_TAG] - Tag: </abandonRequest>
        super.transitions[Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.ABANDON_REQUEST,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.ABANDON_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        //====================================================
        //  Transitions concerning : ADD REQUEST
        //====================================================
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_CONTROLVALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_ATTR_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_ATTR_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // state: [ADD_REQUEST_START_TAG] -> Tag: </addRequest>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.ADD_REQUEST, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_START_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        // State: [ADD_REQUEST_START_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_START_TAG,
                Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [ADD_REQUEST_CONTROL_START_TAG] - Tag: <controlValue>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL_VALUE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.ADD_REQUEST_CONTROLVALUE_END_TAG, controlValueCreation ) );

        // State: [ADD_REQUEST_CONTROLVALUE_END_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_CONTROLVALUE_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.CONTROL, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_CONTROLVALUE_END_TAG,
                Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_END_TAG, null ) );

        // State: [ADD_REQUEST_CONTROL_START_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_END_TAG, null ) );

        // State: [ADD_REQUEST_CONTROL_END_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [ADD_REQUEST_CONTROL_END_TAG] - Tag: </addRequest>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.ADD_REQUEST, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_END_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP,
                null ) );

        // State: [ADD_REQUEST_START_TAG] - Tag: <attr>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.ATTR, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_START_TAG, Dsmlv2StatesEnum.ADD_REQUEST_ATTR_START_TAG,
                addRequestAddAttribute ) );

        // State: [ADD_REQUEST_CONTROL_END_TAG] - Tag: <attr>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.ATTR, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.ADD_REQUEST_ATTR_START_TAG, addRequestAddAttribute ) );

        // State: [ADD_REQUEST_ATTR_END_TAG] - Tag: <attr>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_ATTR_END_TAG.ordinal()].put( new Tag( DsmlLiterals.ATTR, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_ATTR_END_TAG,
                Dsmlv2StatesEnum.ADD_REQUEST_ATTR_START_TAG, addRequestAddAttribute ) );

        // State: [ADD_REQUEST_ATTR_START_TAG] - Tag: </attr>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_ATTR_START_TAG.ordinal()].put( new Tag( DsmlLiterals.ATTR, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_ATTR_START_TAG,
                Dsmlv2StatesEnum.ADD_REQUEST_ATTR_END_TAG, null ) );

        // State: [ADD_REQUEST_ATTR_START_TAG] - Tag: <value>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_ATTR_START_TAG.ordinal()].put( new Tag( DsmlLiterals.VALUE, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_ATTR_START_TAG,
                Dsmlv2StatesEnum.ADD_REQUEST_ATTR_START_TAG, addRequestAddValue ) );

        // State: [ADD_REQUEST_ATTR_END_TAG] - Tag: </addRequest>
        super.transitions[Dsmlv2StatesEnum.ADD_REQUEST_ATTR_END_TAG.ordinal()]
            .put( new Tag( DsmlLiterals.ADD_REQUEST, Tag.END ), new GrammarTransition( Dsmlv2StatesEnum.ADD_REQUEST_ATTR_END_TAG,
                Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        //====================================================
        //  Transitions concerning : AUTH REQUEST
        //====================================================
        super.transitions[Dsmlv2StatesEnum.AUTH_REQUEST_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.AUTH_REQUEST_CONTROLVALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // state: [AUTH_REQUEST_START_TAG] -> Tag: </authRequest>
        super.transitions[Dsmlv2StatesEnum.AUTH_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.AUTH_REQUEST, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.AUTH_REQUEST_START_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        // State: [AUTH_REQUEST_START_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.AUTH_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.AUTH_REQUEST_START_TAG,
                Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [AUTH_REQUEST_CONTROL_START_TAG] - Tag: <controlValue>
        super.transitions[Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL_VALUE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.AUTH_REQUEST_CONTROLVALUE_END_TAG, controlValueCreation ) );

        // State: [AUTH_REQUEST_CONTROLVALUE_END_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.AUTH_REQUEST_CONTROLVALUE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.AUTH_REQUEST_CONTROLVALUE_END_TAG,
                Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_END_TAG, null ) );

        // State: [AUTH_REQUEST_CONTROL_START_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.CONTROL, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_END_TAG, null ) );

        // State: [AUTH_REQUEST_CONTROL_END_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [AUTH_REQUEST_CONTROL_END_TAG] - Tag: </authRequest>
        super.transitions[Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.AUTH_REQUEST, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.AUTH_REQUEST_CONTROL_END_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP,
                null ) );

        //====================================================
        //  Transitions concerning : COMPARE REQUEST
        //====================================================
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROLVALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_ASSERTION_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_ASSERTION_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_VALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // State: [COMPARE_REQUEST_START_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.COMPARE_REQUEST_START_TAG,
                Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [COMPARE_REQUEST_CONTROL_START_TAG] - Tag: <controlValue>
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.CONTROL_VALUE, Tag.START ), new GrammarTransition(
                Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROLVALUE_END_TAG, controlValueCreation ) );

        // State: [COMPARE_REQUEST_CONTROLVALUE_END_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROLVALUE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROLVALUE_END_TAG,
                Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_END_TAG, null ) );

        // State: [COMPARE_REQUEST_CONTROL_START_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_END_TAG, null ) );

        // State: [COMPARE_REQUEST_CONTROL_END_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [COMPARE_REQUEST_CONTROL_END_TAG] - Tag: </compareRequest>
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.COMPARE_REQUEST,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        // State: [COMPARE_REQUEST_START_TAG] - Tag: <assertion>
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.ASSERTION, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.COMPARE_REQUEST_ASSERTION_START_TAG, compareRequestAddAssertion ) );

        // State: [COMPARE_REQUEST_CONTROL_END_TAG] - Tag: <assertion>
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.ASSERTION,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.COMPARE_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.COMPARE_REQUEST_ASSERTION_START_TAG, compareRequestAddAssertion ) );

        // State: [COMPARE_REQUEST_ASSERTION_START_TAG] - Tag: <value>
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_ASSERTION_START_TAG.ordinal()].put( new Tag( DsmlLiterals.VALUE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.COMPARE_REQUEST_ASSERTION_START_TAG,
                Dsmlv2StatesEnum.COMPARE_REQUEST_VALUE_END_TAG, compareRequestAddValue ) );

        //State: [COMPARE_REQUEST_VALUE_END_TAG] - Tag: </assertion>
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_VALUE_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.ASSERTION, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.COMPARE_REQUEST_VALUE_END_TAG,
                Dsmlv2StatesEnum.COMPARE_REQUEST_ASSERTION_END_TAG, null ) );

        // State: [COMPARE_REQUEST_ASSERTION_END_TAG] - Tag: </compareRequest>
        super.transitions[Dsmlv2StatesEnum.COMPARE_REQUEST_ASSERTION_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.COMPARE_REQUEST, Tag.END ), new GrammarTransition(
                Dsmlv2StatesEnum.COMPARE_REQUEST_ASSERTION_END_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        //====================================================
        //  Transitions concerning : DEL REQUEST
        //====================================================
        super.transitions[Dsmlv2StatesEnum.DEL_REQUEST_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.DEL_REQUEST_CONTROLVALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // State: [DEL_REQUEST_START_TAG] - Tag: </delRequest>
        super.transitions[Dsmlv2StatesEnum.DEL_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.DEL_REQUEST, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.DEL_REQUEST_START_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        // State: [DEL_REQUEST_START_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.DEL_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.DEL_REQUEST_START_TAG,
                Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [DEL_REQUEST_CONTROL_START_TAG] - Tag: <controlValue>
        super.transitions[Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL_VALUE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.DEL_REQUEST_CONTROLVALUE_END_TAG, controlValueCreation ) );

        // State: [DEL_REQUEST_CONTROLVALUE_END_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.DEL_REQUEST_CONTROLVALUE_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.CONTROL, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.DEL_REQUEST_CONTROLVALUE_END_TAG,
                Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_END_TAG, null ) );

        // State: [DEL_REQUEST_CONTROL_START_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_END_TAG, null ) );

        // State: [DEL_REQUEST_CONTROL_END_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [DEL_REQUEST_CONTROL_END_TAG] - Tag: </delRequest>
        super.transitions[Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.DEL_REQUEST, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.DEL_REQUEST_CONTROL_END_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP,
                null ) );

        //====================================================
        //  Transitions concerning : EXTENDED REQUEST
        //====================================================
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROLVALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_REQUESTNAME_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_REQUESTVALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // State: [EXTENDED_REQUEST_START_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.EXTENDED_REQUEST_START_TAG,
                Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [EXTENDED_REQUEST_CONTROL_START_TAG] - Tag: <controlValue>
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.CONTROL_VALUE, Tag.START ), new GrammarTransition(
                Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROLVALUE_END_TAG, controlValueCreation ) );

        // State: [EXTENDED_REQUEST_CONTROLVALUE_END_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROLVALUE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROLVALUE_END_TAG,
                Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_END_TAG, null ) );

        // State: [EXTENDED_REQUEST_CONTROL_START_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_END_TAG, null ) );

        // State: [EXTENDED_REQUEST_CONTROL_END_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [EXTENDED_REQUEST_CONTROL_END_TAG] - Tag: </extendedRequest>
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.EXTENDED_REQUEST, Tag.END ), new GrammarTransition(
                Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_END_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        // State: [EXTENDED_REQUEST_START_TAG] - Tag: <requestName>
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.REQUEST_NAME, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.EXTENDED_REQUEST_START_TAG,
                Dsmlv2StatesEnum.EXTENDED_REQUEST_REQUESTNAME_END_TAG, extendedRequestAddName ) );

        // State: [EXTENDED_REQUEST_CONTROL_END_TAG] - Tag: <requestName>
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.REQUEST_NAME,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.EXTENDED_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.EXTENDED_REQUEST_REQUESTNAME_END_TAG, extendedRequestAddName ) );

        // State: [EXTENDED_REQUEST_REQUESTNAME_END_TAG] - Tag: </extendedRequest>
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_REQUESTNAME_END_TAG.ordinal()].put( new Tag(
            DsmlLiterals.EXTENDED_REQUEST,
            Tag.END ), new GrammarTransition( Dsmlv2StatesEnum.EXTENDED_REQUEST_REQUESTNAME_END_TAG,
            Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        // State: [EXTENDED_REQUEST_REQUESTNAME_END_TAG] - Tag: <requestValue>
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_REQUESTNAME_END_TAG.ordinal()].put( new Tag(
            DsmlLiterals.REQUEST_VALUE,
            Tag.START ), new GrammarTransition( Dsmlv2StatesEnum.EXTENDED_REQUEST_REQUESTNAME_END_TAG,
            Dsmlv2StatesEnum.EXTENDED_REQUEST_REQUESTVALUE_END_TAG, extendedRequestAddValue ) );

        // State: [EXTENDED_REQUEST_REQUESTVALUE_END_TAG] - Tag: </requestRequest>
        super.transitions[Dsmlv2StatesEnum.EXTENDED_REQUEST_REQUESTVALUE_END_TAG.ordinal()].put( new Tag(
            DsmlLiterals.EXTENDED_REQUEST,
            Tag.END ), new GrammarTransition( Dsmlv2StatesEnum.EXTENDED_REQUEST_REQUESTVALUE_END_TAG,
            Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        //====================================================
        //  Transitions concerning : MODIFY Dn REQUEST
        //====================================================
        super.transitions[Dsmlv2StatesEnum.MODIFY_DN_REQUEST_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROLVALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // State: [MODIFY_DN_REQUEST_START_TAG] - Tag: </modDNRequest>
        super.transitions[Dsmlv2StatesEnum.MODIFY_DN_REQUEST_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.MOD_DN_REQUEST, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_DN_REQUEST_START_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP,
                null ) );

        // State: [MODIFY_DN_REQUEST_START_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.MODIFY_DN_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_DN_REQUEST_START_TAG,
                Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [MODIFY_DN_REQUEST_CONTROL_START_TAG] - Tag: <controlValue>
        super.transitions[Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.CONTROL_VALUE, Tag.START ), new GrammarTransition(
                Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROLVALUE_END_TAG, controlValueCreation ) );

        // State: [MODIFY_DN_REQUEST_CONTROLVALUE_END_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROLVALUE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROLVALUE_END_TAG,
                Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_END_TAG, null ) );

        // State: [MODIFY_DN_REQUEST_CONTROL_START_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_END_TAG, null ) );

        // State: [MODIFY_DN_REQUEST_CONTROL_END_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [MODIFY_DN_REQUEST_CONTROL_END_TAG] - Tag: </modDNRequest>
        super.transitions[Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.MOD_DN_REQUEST,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_DN_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        //====================================================
        //  Transitions concerning : MODIFY REQUEST
        //====================================================
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROLVALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_VALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // State: [MODIFY_REQUEST_START_TAG] - Tag: </modifyRequest>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_START_TAG.ordinal()]
            .put( new Tag( DsmlLiterals.MODIFY_REQUEST, Tag.END ), new GrammarTransition(
                Dsmlv2StatesEnum.MODIFY_REQUEST_START_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        // State: [MODIFY_REQUEST_START_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_REQUEST_START_TAG,
                Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [MODIFY_REQUEST_CONTROL_START_TAG] - Tag: <controlValue>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL_VALUE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROLVALUE_END_TAG, controlValueCreation ) );

        // State: [MODIFY_REQUEST_CONTROLVALUE_END_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROLVALUE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROLVALUE_END_TAG,
                Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_END_TAG, null ) );

        // State: [MODIFY_REQUEST_CONTROL_START_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.CONTROL, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_END_TAG, null ) );

        // State: [MODIFY_REQUEST_CONTROL_END_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [MODIFY_REQUEST_CONTROL_END_TAG] - Tag: </modifyRequest>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.MODIFY_REQUEST,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_END_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP,
                null ) );

        // State: [MODIFY_REQUEST_CONTROL_END_TAG] - Tag: <modification>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.MODIFICATION,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_START_TAG, modifyRequestAddModification ) );

        // State: [MODIFY_REQUEST_START_TAG] - Tag: <modification>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.MODIFICATION, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_REQUEST_START_TAG,
                Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_START_TAG, modifyRequestAddModification ) );

        // State: [MODIFY_REQUEST_MODIFICATION_END_TAG] - Tag: <modification>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.MODIFICATION, Tag.START ), new GrammarTransition(
                Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_END_TAG,
                Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_START_TAG, modifyRequestAddModification ) );

        // State: [MODIFY_REQUEST_MODIFICATION_START_TAG] - Tag: </modification>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.MODIFICATION, Tag.END ), new GrammarTransition(
                Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_START_TAG,
                Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_END_TAG, null ) );

        // State: [MODIFY_REQUEST_MODIFICATION_START_TAG] - Tag: <value>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_START_TAG.ordinal()].put( new Tag( DsmlLiterals.VALUE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_START_TAG,
                Dsmlv2StatesEnum.MODIFY_REQUEST_VALUE_END_TAG, modifyRequestAddValue ) );

        // State: [MODIFY_REQUEST_VALUE_END_TAG] - Tag: <value>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_VALUE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.VALUE, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_REQUEST_VALUE_END_TAG,
                Dsmlv2StatesEnum.MODIFY_REQUEST_VALUE_END_TAG, modifyRequestAddValue ) );

        // State: [MODIFY_REQUEST_VALUE_END_TAG] - Tag: </modification>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_VALUE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.MODIFICATION,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.MODIFY_REQUEST_VALUE_END_TAG,
                Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_END_TAG, null ) );

        // State: [MODIFY_REQUEST_MODIFICATION_END_TAG] - Tag: </modifyRequest>
        super.transitions[Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.MODIFY_REQUEST, Tag.END ), new GrammarTransition(
                Dsmlv2StatesEnum.MODIFY_REQUEST_MODIFICATION_END_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP, null ) );

        //====================================================
        //  Transitions concerning : SEARCH REQUEST
        //====================================================
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROLVALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTES_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTES_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTE_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // State: [SEARCH_REQUEST_START_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [SEARCH_REQUEST_CONTROL_START_TAG] - Tag: <controlValue>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL_VALUE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROLVALUE_END_TAG, controlValueCreation ) );

        // State: [SEARCH_REQUEST_CONTROLVALUE_END_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROLVALUE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.CONTROL,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROLVALUE_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_END_TAG, null ) );

        // State: [SEARCH_REQUEST_CONTROL_START_TAG] - Tag: </control>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.CONTROL, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_END_TAG, null ) );

        // State: [SEARCH_REQUEST_CONTROL_END_TAG] - Tag: <control>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.CONTROL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_START_TAG, controlCreation ) );

        // State: [SEARCH_REQUEST_FILTER_END_TAG] - Tag: </searchRequest>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.SEARCH_REQUEST,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_END_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP,
                storeFilter ) );

        // State: [SEARCH_REQUEST_ATTRIBUTES_START_TAG] - Tag: </attributes>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTES_START_TAG.ordinal()].put( new Tag( DsmlLiterals.ATTRIBUTES,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTES_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTES_END_TAG, null ) );

        // State: [SEARCH_REQUEST_ATTRIBUTES_START_TAG] - Tag: <attribute>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTES_START_TAG.ordinal()].put( new Tag( DsmlLiterals.ATTRIBUTE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTES_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTE_START_TAG, searchRequestAddAttribute ) );

        // State: [SEARCH_REQUEST_ATTRIBUTE_START_TAG] - Tag: </attribute>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTE_START_TAG.ordinal()].put( new Tag( DsmlLiterals.ATTRIBUTE,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTE_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTE_END_TAG, null ) );

        // State: [SEARCH_REQUEST_ATTRIBUTE_END_TAG] - Tag: <attribute>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.ATTRIBUTE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTE_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTE_START_TAG, searchRequestAddAttribute ) );

        // State: [SEARCH_REQUEST_ATTRIBUTE_END_TAG] - Tag: </attributes>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.ATTRIBUTES,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTE_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTES_END_TAG, null ) );

        // State: [SEARCH_REQUEST_ATTRIBUTES_END_TAG] - Tag: </searchRequest>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTES_END_TAG.ordinal()].put( new Tag( DsmlLiterals.SEARCH_REQUEST,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTES_END_TAG,
                Dsmlv2StatesEnum.BATCHREQUEST_LOOP, storeFilter ) );

        //====================================================
        //  Transitions concerning : FILTER
        //====================================================
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_EQUALITYMATCH_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_GREATEROREQUAL_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_LESSOREQUAL_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_APPROXMATCH_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_PRESENT_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_EXTENSIBLEMATCH_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_EXTENSIBLEMATCH_VALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // State: [SEARCH_REQUEST_START_TAG] - Tag: <filter>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_START_TAG.ordinal()].put( new Tag( DsmlLiterals.FILTER, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG, null ) );

        // State: [SEARCH_REQUEST_CONTROL_END_TAG] - Tag: <filter>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.FILTER, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_CONTROL_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG, null ) );

        //*** AND ***
        // State: [SEARCH_REQUEST_FILTER_START_TAG] - Tag: <and>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG.ordinal()].put( new Tag( DsmlLiterals.AND, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, andFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: <and>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put( new Tag( DsmlLiterals.AND, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, andFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: </and>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put( new Tag( DsmlLiterals.AND, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, connectorFilterClose ) );

        //*** OR ***
        // State: [SEARCH_REQUEST_FILTER_START_TAG] - Tag: <or>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG.ordinal()].put( new Tag( DsmlLiterals.OR, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, orFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: <or>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put( new Tag( DsmlLiterals.OR, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, orFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: </or>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put( new Tag( DsmlLiterals.OR, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, connectorFilterClose ) );

        //*** NOT ***
        // State: [SEARCH_REQUEST_FILTER_START_TAG] - Tag: <not>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG.ordinal()].put( new Tag( DsmlLiterals.NOT, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, notFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: <not>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put( new Tag( DsmlLiterals.NOT, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, notFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: </not>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put( new Tag( DsmlLiterals.NOT, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, connectorFilterClose ) );

        //*** DsmlLiterals.SUBSTRINGS ***
        // State: [SEARCH_REQUEST_FILTER_START_TAG] - Tag: <substrings>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG.ordinal()].put( new Tag( DsmlLiterals.SUBSTRINGS,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_SUBSTRINGS_START_TAG, substringsFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: <substrings>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put(
            new Tag( DsmlLiterals.SUBSTRINGS, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_SUBSTRINGS_START_TAG, substringsFilterCreation ) );

        //*** EQUALITY MATCH ***
        // State: [SEARCH_REQUEST_FILTER_START_TAG] - Tag: <equalityMatch>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG.ordinal()].put( new Tag( DsmlLiterals.EQUALITY_MATCH,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_EQUALITYMATCH_START_TAG, equalityMatchFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: <equalityMatch>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put( new Tag( DsmlLiterals.EQUALITY_MATCH,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_EQUALITYMATCH_START_TAG, equalityMatchFilterCreation ) );

        // State: [SEARCH_REQUEST_EQUALITYMATCH_START_TAG] - Tag: <value>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_EQUALITYMATCH_START_TAG.ordinal()].put( new Tag( DsmlLiterals.VALUE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_EQUALITYMATCH_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG, filterAddValue ) );

        // State: [SEARCH_REQUEST_VALUE_END_TAG] - Tag: </equalityMatch>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.EQUALITY_MATCH,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, null ) );

        //*** GREATER OR EQUAL ***
        // State: [SEARCH_REQUEST_FILTER_START_TAG] - Tag: <greaterOrEqual>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.GREATER_OR_EQUAL, Tag.START ), new GrammarTransition(
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_GREATEROREQUAL_START_TAG, greaterOrEqualFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: <greaterOrEqual>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put( new Tag( DsmlLiterals.GREATER_OR_EQUAL,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_GREATEROREQUAL_START_TAG, greaterOrEqualFilterCreation ) );

        // State: [SEARCH_REQUEST_GREATEROREQUAL_START_TAG] - Tag: <value>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_GREATEROREQUAL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.VALUE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_GREATEROREQUAL_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG, filterAddValue ) );

        // State: [SEARCH_REQUEST_VALUE_END_TAG] - Tag: </greaterOrEqual>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG.ordinal()].put( new Tag( DsmlLiterals.GREATER_OR_EQUAL,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, null ) );

        //*** LESS OR EQUAL ***
        // State: [SEARCH_REQUEST_FILTER_START_TAG] - Tag: <lessOrEqual>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG.ordinal()].put( new Tag( DsmlLiterals.LESS_OR_EQUAL,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_LESSOREQUAL_START_TAG, lessOrEqualFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: <lessOrEqual>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put(
            new Tag( DsmlLiterals.LESS_OR_EQUAL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_LESSOREQUAL_START_TAG, lessOrEqualFilterCreation ) );

        // State: [SEARCH_REQUEST_LESSOREQUAL_START_TAG] - Tag: <value>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_LESSOREQUAL_START_TAG.ordinal()].put( new Tag( DsmlLiterals.VALUE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_LESSOREQUAL_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG, filterAddValue ) );

        // State: [SEARCH_REQUEST_VALUE_END_TAG] - Tag: </lessOrEqual>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.LESS_OR_EQUAL, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, null ) );

        //*** LESS OR EQUAL ***
        // State: [SEARCH_REQUEST_FILTER_START_TAG] - Tag: <approxMatch>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG.ordinal()].put( new Tag( DsmlLiterals.APPROX_MATCH,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_APPROXMATCH_START_TAG, approxMatchFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: <approxMatch>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put(
            new Tag( DsmlLiterals.APPROX_MATCH, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_APPROXMATCH_START_TAG, approxMatchFilterCreation ) );

        // State: [SEARCH_REQUEST_APPROXMATCH_START_TAG] - Tag: <value>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_APPROXMATCH_START_TAG.ordinal()].put( new Tag( DsmlLiterals.VALUE,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_APPROXMATCH_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG, filterAddValue ) );

        // State: [SEARCH_REQUEST_VALUE_END_TAG] - Tag: </approxMatch>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.APPROX_MATCH, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_VALUE_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, null ) );

        //*** PRESENT ***
        // State: [SEARCH_REQUEST_FILTER_START_TAG] - Tag: <present>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG.ordinal()].put( new Tag( DsmlLiterals.PRESENT,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_PRESENT_START_TAG, presentFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: <present>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put( new Tag( DsmlLiterals.PRESENT, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_PRESENT_START_TAG, presentFilterCreation ) );

        // State: [SEARCH_REQUEST_PRESENT_START_TAG] - Tag: </present>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_PRESENT_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.PRESENT, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_PRESENT_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, null ) );

        //*** EXTENSIBLE MATCH ***
        // State: [SEARCH_REQUEST_FILTER_START_TAG] - Tag: <extensibleMatch>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.EXTENSIBLE_MATCH, Tag.START ), new GrammarTransition(
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_EXTENSIBLEMATCH_START_TAG, extensibleMatchFilterCreation ) );

        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: <extensibleMatch>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put( new Tag( DsmlLiterals.EXTENSIBLE_MATCH,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_EXTENSIBLEMATCH_START_TAG, extensibleMatchFilterCreation ) );

        // State: [SEARCH_REQUEST_EXTENSIBLEMATCH_START_TAG] - Tag: <value>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_EXTENSIBLEMATCH_START_TAG.ordinal()].put(
            new Tag( DsmlLiterals.VALUE, Tag.START ), new GrammarTransition(
                Dsmlv2StatesEnum.SEARCH_REQUEST_EXTENSIBLEMATCH_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_EXTENSIBLEMATCH_VALUE_END_TAG, extensibleMatchAddValue ) );

        // State: [SEARCH_REQUEST_EXTENSIBLEMATCH_VALUE_END_TAG] - Tag: </extensibleMatch>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_EXTENSIBLEMATCH_VALUE_END_TAG.ordinal()].put( new Tag(
            DsmlLiterals.EXTENSIBLE_MATCH, Tag.END ), new GrammarTransition(
            Dsmlv2StatesEnum.SEARCH_REQUEST_EXTENSIBLEMATCH_VALUE_END_TAG, Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
            null ) );

        //*** Filter (end) ***
        // State: [SEARCH_REQUEST_FILTER_LOOP] - Tag: </filter>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP.ordinal()].put( new Tag( DsmlLiterals.FILTER, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_END_TAG, null ) );

        // State: [SEARCH_REQUEST_FILTER_END_TAG] - Tag: <attributes>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_END_TAG.ordinal()].put( new Tag( DsmlLiterals.ATTRIBUTES,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_ATTRIBUTES_START_TAG, null ) );

        // State: [SEARCH_REQUEST_FILTER_END_TAG] - Tag: </searchRequest>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_END_TAG.ordinal()].put( new Tag( DsmlLiterals.SEARCH_REQUEST,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_END_TAG, Dsmlv2StatesEnum.BATCHREQUEST_LOOP,
                storeFilter ) );

        //====================================================
        //  Transitions concerning : SUBSTRING FILTER
        //====================================================
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_SUBSTRINGS_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_INITIAL_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ANY_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FINAL_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_SUBSTRINGS_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // State: [SEARCH_REQUEST_SUBSTRINGS_START_TAG] - Tag: </substrings>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_SUBSTRINGS_START_TAG.ordinal()].put( new Tag( DsmlLiterals.SUBSTRINGS,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_SUBSTRINGS_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, null ) );

        // State: [SEARCH_REQUEST_SUBSTRINGS_START_TAG] - Tag: <initial>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_SUBSTRINGS_START_TAG.ordinal()].put( new Tag( DsmlLiterals.INITIAL,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_SUBSTRINGS_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_INITIAL_END_TAG, substringsFilterSetInitial ) );

        // State: [SEARCH_REQUEST_INITIAL_END_TAG] - Tag: <any>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_INITIAL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.ANY, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_INITIAL_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_ANY_END_TAG, substringsFilterAddAny ) );

        // State: [SEARCH_REQUEST_INITIAL_END_TAG] - Tag: <final>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_INITIAL_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.FINAL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_INITIAL_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FINAL_END_TAG, substringsFilterSetFinal ) );

        // State: [SEARCH_REQUEST_INITIAL_END_TAG] - Tag: </substrings>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_INITIAL_END_TAG.ordinal()].put( new Tag( DsmlLiterals.SUBSTRINGS,
            Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_INITIAL_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, substringsFilterClose ) );

        // State: [SEARCH_REQUEST_SUBSTRINGS_START_TAG] - Tag: <any>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_SUBSTRINGS_START_TAG.ordinal()].put( new Tag( DsmlLiterals.ANY,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_SUBSTRINGS_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_ANY_END_TAG, substringsFilterAddAny ) );

        // State: [SEARCH_REQUEST_ANY_END_TAG] - Tag: </any>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ANY_END_TAG.ordinal()].put( new Tag( DsmlLiterals.ANY, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_ANY_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_ANY_END_TAG, substringsFilterAddAny ) );

        // State: [SEARCH_REQUEST_ANY_END_TAG] - Tag: <final>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ANY_END_TAG.ordinal()].put( new Tag( DsmlLiterals.FINAL, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_ANY_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FINAL_END_TAG, substringsFilterSetFinal ) );

        // State: [SEARCH_REQUEST_ANY_END_TAG] - Tag: </substrings>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_ANY_END_TAG.ordinal()].put( new Tag( DsmlLiterals.SUBSTRINGS, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_ANY_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, substringsFilterClose ) );

        // State: [SEARCH_REQUEST_SUBSTRINGS_START_TAG] - Tag: <final>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_SUBSTRINGS_START_TAG.ordinal()].put( new Tag( DsmlLiterals.FINAL,
            Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_SUBSTRINGS_START_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FINAL_END_TAG, substringsFilterSetFinal ) );

        // State: [SEARCH_REQUEST_FINAL_END_TAG] - Tag: </substrings>
        super.transitions[Dsmlv2StatesEnum.SEARCH_REQUEST_FINAL_END_TAG.ordinal()].put(
            new Tag( DsmlLiterals.SUBSTRINGS, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.SEARCH_REQUEST_FINAL_END_TAG,
                Dsmlv2StatesEnum.SEARCH_REQUEST_FILTER_LOOP, substringsFilterClose ) );

        //------------------------------------------ handle SOAP envelopes --------------------------
        super.transitions[Dsmlv2StatesEnum.SOAP_ENVELOPE_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SOAP_HEADER_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SOAP_HEADER_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SOAP_BODY_START_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();
        super.transitions[Dsmlv2StatesEnum.SOAP_BODY_END_TAG.ordinal()] = new HashMap<Tag, GrammarTransition>();

        super.transitions[Dsmlv2StatesEnum.GRAMMAR_END.ordinal()] = new HashMap<Tag, GrammarTransition>();

        // State: [INIT_GRAMMAR_STATE] - Tag: <envelope>
        super.transitions[Dsmlv2StatesEnum.INIT_GRAMMAR_STATE.ordinal()].put( new Tag( DsmlLiterals.ENVELOPE, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.INIT_GRAMMAR_STATE, Dsmlv2StatesEnum.SOAP_ENVELOPE_START_TAG,
                null ) );

        // state: [SOAP_ENVELOPE_START_TAG] -> Tag: <header>
        super.transitions[Dsmlv2StatesEnum.SOAP_ENVELOPE_START_TAG.ordinal()].put( new Tag( DsmlLiterals.HEADER, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SOAP_ENVELOPE_START_TAG, Dsmlv2StatesEnum.SOAP_HEADER_START_TAG,
                ParserUtils.READ_SOAP_HEADER ) );

        // state: [SOAP_HEADER_START_TAG] -> Tag: </header>
        super.transitions[Dsmlv2StatesEnum.SOAP_HEADER_START_TAG.ordinal()]
            .put( new Tag( DsmlLiterals.HEADER, Tag.END ),
                new GrammarTransition( Dsmlv2StatesEnum.SOAP_HEADER_START_TAG, Dsmlv2StatesEnum.SOAP_HEADER_END_TAG,
                    null ) );

        // state: [SOAP_HEADER_END_TAG] -> Tag: <body>
        super.transitions[Dsmlv2StatesEnum.SOAP_HEADER_END_TAG.ordinal()].put( new Tag( DsmlLiterals.BODY, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SOAP_HEADER_END_TAG, Dsmlv2StatesEnum.SOAP_BODY_START_TAG, null ) );

        // state: [SOAP_BODY_START_TAG] -> Tag: <batchRequest>
        super.transitions[Dsmlv2StatesEnum.SOAP_BODY_START_TAG.ordinal()].put( new Tag( DsmlLiterals.BATCH_REQUEST, Tag.START ),
            new GrammarTransition( Dsmlv2StatesEnum.SOAP_BODY_START_TAG, Dsmlv2StatesEnum.BATCHREQUEST_START_TAG,
                batchRequestCreation ) );

        // the optional transition if no soap header is present
        // state: [SOAP_ENVELOPE_START_TAG] -> Tag: <body>
        super.transitions[Dsmlv2StatesEnum.SOAP_ENVELOPE_START_TAG.ordinal()]
            .put( new Tag( DsmlLiterals.BODY, Tag.START ),
                new GrammarTransition( Dsmlv2StatesEnum.SOAP_ENVELOPE_START_TAG, Dsmlv2StatesEnum.SOAP_BODY_START_TAG,
                    null ) );

        // the below two transitions are a bit unconventional, technically the container's state is set to GRAMMAR_END
        // when the </batchRequest> tag is encountered by the parser and the corresponding action gets executed but in
        // a SOAP envelop we still have two more end tags(</body> and </envelope>) are left so we set those corresponding
        // current and next transition states always to GRAMMAR_END
        super.transitions[Dsmlv2StatesEnum.GRAMMAR_END.ordinal()].put( new Tag( DsmlLiterals.BODY, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.GRAMMAR_END, Dsmlv2StatesEnum.GRAMMAR_END, null ) );

        super.transitions[Dsmlv2StatesEnum.GRAMMAR_END.ordinal()].put( new Tag( DsmlLiterals.ENVELOPE, Tag.END ),
            new GrammarTransition( Dsmlv2StatesEnum.GRAMMAR_END, Dsmlv2StatesEnum.GRAMMAR_END, null ) );

        //------------------------------------------

    } // End of the constructor


    /**
     * @return The LDAP codec service.
     */
    public LdapApiService getLdapCodecService()
    {
        return codec;
    }
}
