package org.apache.directory.shared.ldap.codec.api;

import java.util.Set;

import org.apache.directory.shared.ldap.model.schema.AttributeType;
import org.apache.directory.shared.ldap.model.schema.LdapSyntax;
import org.apache.directory.shared.ldap.model.schema.SchemaManager;
import org.apache.directory.shared.util.Strings;
import org.apache.mina.util.ConcurrentHashSet;

public class DefaultBinaryAttributeDectector implements BinaryAttributeDetector
{
    private Set<String> binaryAttributes = new ConcurrentHashSet<String>();
    private Set<String> binarySyntaxes = new ConcurrentHashSet<String>();
    private SchemaManager schemaManager;
    
    
    public DefaultBinaryAttributeDectector( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
    }
    
    
    /**
     * {@inheritDoc}
     */
    public boolean isBinary( String attributeId )
    {
        String attrId = Strings.toLowerCase( attributeId );

        if ( attrId.endsWith( ";binary" ) )
        {
            return true;
        }

        if ( schemaManager != null )
        {
            AttributeType attributeType =  schemaManager.getAttributeType( attrId );
            
            if ( attributeType == null )
            {
                return false;
            }
            
            LdapSyntax ldapSyntax = attributeType.getSyntax();
            
            if ( ldapSyntax != null )
            {
                if ( !ldapSyntax.isHumanReadable() )
                {
                    return true;
                }
                else
                {
                    
                }
                
                String syntaxId = ldapSyntax.getOid();
                
                return ( binarySyntaxes.contains( syntaxId ) );
            }
            else
            {
            }
        }
        else
        {
            return binaryAttributes.contains( attrId );
        }
        
        return false;
    }
    

    /**
     * {@inheritDoc}
     */
    public void addBinaryAttribute( String... binaryAttributes )
    {
        if ( binaryAttributes != null )
        {
            for ( String binaryAttribute : binaryAttributes )
            {
                String attrId = Strings.toLowerCase( binaryAttribute );
                this.binaryAttributes.add( attrId );
            }
        }
    }
    

    /**
     * {@inheritDoc}
     */
    public void removeBinaryAttribute( String... binaryAttributes )
    {
        if ( binaryAttributes != null )
        {
            for ( String binaryAttribute : binaryAttributes )
            {
                String attrId = Strings.toLowerCase( binaryAttribute );
                this.binaryAttributes.remove( attrId );
            }
        }
    }
    

    /**
     * {@inheritDoc}
     */
    public void setBinaryAttributes( Set<String> binaryAttributes )
    {
        if ( binaryAttributes != null )
        {
            this.binaryAttributes.clear();
            
            for ( String binaryAttribute : binaryAttributes )
            {
                String attrId = Strings.toLowerCase( binaryAttribute );
                this.binaryAttributes.add( attrId );
            }
        }
    }
    

    /**
     * {@inheritDoc}
     */
    public void addBinarySyntaxes( String... binarySyntaxes )
    {
        if ( binarySyntaxes != null )
        {
            for ( String binarySyntax : binarySyntaxes )
            {
                String syntaxId = Strings.toLowerCase( binarySyntax );
                this.binarySyntaxes.add( syntaxId );
            }
        }
    }
    

    /**
     * {@inheritDoc}
     */
    public void setBinarySyntaxes( Set<String> binarySyntaxes )
    {
        if ( binarySyntaxes != null )
        {
            this.binarySyntaxes.clear();
            
            for ( String binarySyntax : binarySyntaxes )
            {
                String syntaxId = Strings.toLowerCase( binarySyntax );
                this.binarySyntaxes.add( syntaxId );
            }
        }
    }
    

    /**
     * {@inheritDoc}
     */
    public void removeBinarySyntaxes( String... binarySyntaxes )
    {
        if ( binarySyntaxes != null )
        {
            for ( String binarySyntax : binarySyntaxes )
            {
                String syntaxId = Strings.toLowerCase( binarySyntax );
                this.binarySyntaxes.remove( syntaxId );
            }
        }
    }
}
