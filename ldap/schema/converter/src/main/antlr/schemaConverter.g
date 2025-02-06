// ============================================================================
//
//
//                    OpenLDAP Schema Parser
//
//
// ============================================================================
// $Rev$
// ============================================================================


header {
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
/*
 * Keep the semicolon right next to the package name or else there will be a
 * bug that comes into the foreground in the new antlr release.
 */
package org.apache.directory.api.ldap.schema.converter;
import java.util.List ;
import java.util.ArrayList ;
import java.util.Collections;
import java.io.IOException;

import org.apache.directory.api.ldap.schema.converter.SchemaElement;
import org.apache.directory.api.ldap.model.schema.UsageEnum;
import org.apache.directory.api.ldap.model.schema.ObjectClassTypeEnum;
}


class AntlrSchemaConverterLexer extends Lexer ;

options    {
    k = 7 ;
    exportVocab=AntlrSchema ;
    charVocabulary = '\3'..'\377' ;
    caseSensitive = false ;
    defaultErrorHandler = false ;
}


WS  :   (   '#' (~'\n')* '\n' { newline(); }
        |    ' '
        |   '\t'
        |   '\r' '\n' { newline(); }
        |   '\n'      { newline(); }
        |   '\r'      { newline(); }
        )
        {$setType(Token.SKIP);} //ignore this token
    ;

QUOTE              : '\''
    ;

DIGIT              : '0' .. '9'
    ;

DOLLAR             : '$'
    ;

OPEN_PAREN         : '('
    ;

CLOSE_PAREN        : ')'
    ;

OPEN_BRACKET       : '{'
    ;

CLOSE_BRACKET      : '}'
    ;

protected NUMERIC_STRING : ('0' .. '9')+
    ;

NUMERICOID         :
        NUMERIC_STRING ( '.' NUMERIC_STRING )+
    ;

IDENTIFIER options { testLiterals=true; }
    : 
        ( 'a' .. 'z') ( 'a' .. 'z' | '0' .. '9' | '-' | ';' )*
    ;

DESC
    :
        "desc" WS QUOTE ( ~'\'' | '\\' '\'' )+ QUOTE
    ;

SYNTAX
    :
        "syntax" WS NUMERICOID ( OPEN_BRACKET ( DIGIT )+ CLOSE_BRACKET )?
    ;

class AntlrSchemaConverterParser extends Parser ;

options    {
    k = 5 ;
    defaultErrorHandler = false ;
}


{
    private List<SchemaElement> schemaElements = new ArrayList<SchemaElement>();

    // ------------------------------------------------------------------------
    // Public Methods
    // ------------------------------------------------------------------------
    public void clear()
    {
        schemaElements.clear();
    }


    public List<SchemaElement> getSchemaElements()
    {
        return Collections.unmodifiableList( schemaElements );
    }
}


// ----------------------------------------------------------------------------
// Main Entry Point Production
// ----------------------------------------------------------------------------


parseSchema
    :
    ( attributeType | objectClass )* "END"
    ;


// ----------------------------------------------------------------------------
// AttributeType Productions
// ----------------------------------------------------------------------------


objectClass
{
    ObjectClassHolder objectClass = null;
}
    :
    "objectclass"
    OPEN_PAREN oid:NUMERICOID
    {
        objectClass = new ObjectClassHolder( oid.getText() );
    }
    ( objectClassNames[objectClass] )?
    ( objectClassDesc[objectClass] )?
    ( "OBSOLETE" { objectClass.setObsolete( true ); } )?
    ( objectClassSuperiors[objectClass] )?
    ( 
        "ABSTRACT"   { objectClass.setClassType( ObjectClassTypeEnum.ABSTRACT ); } |
        "STRUCTURAL" { objectClass.setClassType( ObjectClassTypeEnum.STRUCTURAL ); } |
        "AUXILIARY"  { objectClass.setClassType( ObjectClassTypeEnum.AUXILIARY ); }
    )?
    ( must[objectClass] )?
    ( may[objectClass] )?
    // @TODO : add ( extension[type] )*
    CLOSE_PAREN
    {
        schemaElements.add( objectClass );
    }
    ;


may [ObjectClassHolder objectClass]
{
    List<String> list = null;
}
    : "MAY" list=woidlist
    {
        objectClass.setMay( list );
    }
    ;


must [ObjectClassHolder objectClass]
{
    List<String> list = null;
}
    : "MUST" list=woidlist
    {
        objectClass.setMust( list );
    }
    ;


objectClassSuperiors [ObjectClassHolder objectClass]
{
    List<String> list = null;
}
    : "SUP" list=woidlist
    {
        objectClass.setSuperiors( list );
    }
    ;


woid returns [String oid]
{
    oid = null;
}
    :
    (
        opt1:NUMERICOID
        {
            oid = opt1.getText();
        }
        |
        opt2:IDENTIFIER
        {
            oid = opt2.getText();
        }
    )
    ;


woidlist returns [List<String> list]
{
    list = new ArrayList<String>( 2 );
    String oid = null;
}
    :
    (
        oid=woid { list.add( oid ); } |
        (
            OPEN_PAREN
            oid=woid { list.add( oid ); } ( DOLLAR oid=woid { list.add( oid ); } )*
            CLOSE_PAREN
        )
    )
    ;

objectClassDesc [ObjectClassHolder objectClass]
    : d:DESC
    {
        String text = d.getText();
        int start = text.indexOf( '\'' );
        String desc = text.substring( start + 1, text.length() - 1 );
        desc = desc.replace( "\\\"", "\"" );
        desc = desc.replace( "\\'", "'" );
        desc = desc.replace( "\\27", "'" );
        desc = desc.replace( "\\5C", "\"" );
        objectClass.setDescription( desc );
    }
    ;


objectClassNames [ObjectClassHolder objectClass]
{
    List<String> list = new ArrayList<String>();
}
    :
    (
        "NAME"
        ( QUOTE id0:IDENTIFIER QUOTE
        {
            list.add( id0.getText() );
        }
        |
        ( OPEN_PAREN QUOTE id1:IDENTIFIER
        {
            list.add( id1.getText() );
        } QUOTE
        ( QUOTE id2:IDENTIFIER QUOTE
        {
            list.add( id2.getText() );
        } )* CLOSE_PAREN )
        )
    )
    {
        objectClass.setNames( list );
    }
    ;


// ----------------------------------------------------------------------------
// AttributeType Productions
// ----------------------------------------------------------------------------


attributeType
{
    AttributeTypeHolder type = null;
}
    :
    "attributetype"
    OPEN_PAREN oid:NUMERICOID
    {
        type = new AttributeTypeHolder( oid.getText() );
    }
        ( names[type] )?
        ( attributeTypeDesc[type] )?
        ( "OBSOLETE" { type.setObsolete( true ); } )?
        ( superior[type] )?
        ( equality[type] )?
        ( ordering[type] )?
        ( substr[type] )?
        ( syntax[type] )?
        ( "SINGLE-VALUE" { type.setSingleValue( true ); } )?
        ( "COLLECTIVE" { type.setCollective( true ); } )?
        ( "NO-USER-MODIFICATION" { type.setNoUserModification( true ); } )?
        ( usage[type] )?
        // @TODO : add ( extension[type] )*

    CLOSE_PAREN
    {
        schemaElements.add( type );
    }
    ;


attributeTypeDesc [AttributeTypeHolder type]
    : d:DESC
    {
        String text = d.getText();
        int start = text.indexOf( '\'' );
        String desc = text.substring( start +1, text.length() - 1 );
        desc = desc.replace( "\\\"", "\"" );
        desc = desc.replace( "\\'", "'" );
        desc = desc.replace( "\\27", "'" );
        desc = desc.replace( "\\5C", "\"" );
        type.setDescription( desc );
    }
    ;


superior [AttributeTypeHolder type]
    : "SUP"
    (
        oid:NUMERICOID
        {
            type.setSuperior( oid.getText() );
        }
        |
        id:IDENTIFIER
        {
            type.setSuperior( id.getText() );
        }
    );


equality [AttributeTypeHolder type]
    : "EQUALITY"
    (
        oid:NUMERICOID
        {
            type.setEquality( oid.getText() );
        }
        |
        id:IDENTIFIER
        {
            type.setEquality( id.getText() );
        }
    );


substr [AttributeTypeHolder type]
    : "SUBSTR"
    (
        oid:NUMERICOID
        {
            type.setSubstr( oid.getText() );
        }
        |
        id:IDENTIFIER
        {
            type.setSubstr( id.getText() );
        }
    );


ordering [AttributeTypeHolder type]
    : "ORDERING"
    (
        oid:NUMERICOID
        {
            type.setOrdering( oid.getText() );
        }
        |
        id:IDENTIFIER
        {
            type.setOrdering( id.getText() );
        }
    );


names [AttributeTypeHolder type]
{
    List<String> list = new ArrayList<String>();
}
    :
        "NAME"
    (
        QUOTE id0:IDENTIFIER QUOTE 
        { 
            list.add( id0.getText() ); 
        } 
        |
        ( OPEN_PAREN
            ( QUOTE id1:IDENTIFIER
                {
                    list.add( id1.getText() );
                }
              QUOTE
            )+
        CLOSE_PAREN )
    )
    {
        type.setNames( list );
    }
    ;


syntax [AttributeTypeHolder type]
    : token:SYNTAX
    {
        String[] comps = token.getText().split( " " );

        int index = comps[1].indexOf( "{" );
        if ( index == -1 )
        {
            type.setSyntax( comps[1] );
            return;
        }

        String oid = comps[1].substring( 0, index );
        String length = comps[1].substring( index + 1, comps[1].length() - 1 );

        type.setSyntax( oid );
        type.setOidLen( Long.parseLong( length ) );
    }
    ;


usage [AttributeTypeHolder type]
    :
    "USAGE"
    (
        "userApplications" { type.setUsage( UsageEnum.USER_APPLICATIONS ); } |
        "directoryOperation" { type.setUsage( UsageEnum.DIRECTORY_OPERATION ); } |
        "distributedOperation" { type.setUsage( UsageEnum.DISTRIBUTED_OPERATION ); } |
        "dSAOperation" { type.setUsage( UsageEnum.DSA_OPERATION ); }
    );
