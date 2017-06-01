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
package org.apache.directory.api.ldap.util.tree;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapUnwillingToPerformException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A class storing nodes in a tree designed to map DNs.<br>
 * Branch nodes in this tree refers to child nodes. Leaf nodes in the tree
 * don't have any children. <br>
 * A node may contain a reference to an object whose suffix is the path through the
 * nodes of the tree from the root. <br>
 * A node may also have no attached element.<br>
 * Each child node is referenced by a Rdn, and holds the full Dn corresponding to its position<br>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @param <N> The type of node we store
 */
public class DnNode<N>
{
    /** The logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( DnNode.class );

    /** The stored element */
    private N nodeElement;

    /** The node's key */
    private Rdn nodeRdn;

    /** The node's Dn */
    private Dn nodeDn;

    /** The node's depth in the tree */
    private int depth;

    /** The parent, if any */
    private DnNode<N> parent;

    /** Stores the list of all the descendant */
    private Map<Rdn, DnNode<N>> children;


    //-------------------------------------------------------------------------
    // Constructors
    //-------------------------------------------------------------------------
    /**
     * Creates a new instance of DnNode.
     */
    public DnNode()
    {
        children = new HashMap<Rdn, DnNode<N>>();
        nodeDn = Dn.EMPTY_DN;
        nodeRdn = Rdn.EMPTY_RDN;
    }


    /**
     * Creates a new instance of DnNode.
     *
     * @param element the element to store
     */
    public DnNode( N element )
    {
        this.nodeElement = element;
        children = new HashMap<Rdn, DnNode<N>>();
    }


    /**
     * Creates a new instance of DnNode.
     *
     * @param dn the node's Dn
     * @param element the element to store
     */
    public DnNode( Dn dn, N element )
    {
        if ( ( dn == null ) || ( dn.isEmpty() ) )
        {
            children = new HashMap<Rdn, DnNode<N>>();
            this.nodeDn = Dn.EMPTY_DN;

            return;
        }

        try
        {
            DnNode<N> rootNode = createNode( dn, element, dn.size() );

            // Now copy back the created node into this
            this.children = rootNode.children;
            this.depth = rootNode.depth;
            this.nodeDn = rootNode.nodeDn;
            this.nodeElement = rootNode.nodeElement;
            this.nodeRdn = rootNode.nodeRdn;
            this.parent = null;
        }
        catch ( LdapException le )
        {
            // Special cas e: the Dn is empty, this is not allowed
            throw new IllegalArgumentException( le.getMessage(), le );
        }
    }


    //-------------------------------------------------------------------------
    // Helper methods
    //-------------------------------------------------------------------------
    /**
     * Check that the Dn is not null
     */
    private void checkDn( Dn dn ) throws LdapException
    {
        if ( ( dn == null ) || dn.isEmpty() )
        {
            String message = "Cannot process an empty Dn";
            LOG.error( message );
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, message );
        }
    }


    /**
     * Create a new DnNode, recursively creating all the intermediate nodes.
     */
    private DnNode<N> createNode( Dn dn, N element, int nbRdns ) throws LdapException
    {
        checkDn( dn );

        DnNode<N> rootNode = null;

        // No parent : add from the current position
        for ( Rdn rdn : dn.getRdns() )
        {
            if ( nbRdns == 0 )
            {
                break;
            }

            if ( rootNode == null )
            {
                // Create the new top node
                DnNode<N> node = new DnNode<>( element );
                node.nodeRdn = rdn;
                node.nodeDn = dn;
                node.depth = dn.size() + depth;

                rootNode = node;
            }
            else
            {
                DnNode<N> node = new DnNode<>();
                node.nodeRdn = rdn;
                node.nodeDn = rootNode.nodeDn.getParent();
                node.depth = node.nodeDn.size() + depth;
                rootNode.parent = node;
                node.children.put( rootNode.nodeRdn, rootNode );
                rootNode = node;
            }

            nbRdns--;
        }

        return rootNode;
    }


    /**
     * Store the given element into the node
     */
    private synchronized void setElement( N element )
    {
        this.nodeElement = element;
    }


    /**
     * Tells if the implementation is a leaf node. If it's a branch node
     * then false is returned.
     *
     * @return <code>true</code> if the class is a leaf node, false otherwise.
     */
    public synchronized boolean isLeaf()
    {
        return !hasChildren();
    }


    /**
     * Tells if the implementation is a leaf node. If it's a branch node
     * then false is returned.
     *
     * @param dn The Dn we want to check
     * @return <code>true</code> if this is a leaf node, false otherwise.
     */
    public synchronized boolean isLeaf( Dn dn )
    {
        DnNode<N> node = getNode( dn );

        if ( node == null )
        {
            return false;
        }

        return node.children.size() == 0;
    }


    /**
     * Returns the number of entries under this node. It includes
     * the node itself, plus the number of all it children and descendants.
     *
     * @return The number of descendents
     */
    public synchronized int size()
    {
        // The node itself
        int size = 1;

        // Iterate through the children if any
        if ( children.size() != 0 )
        {
            for ( DnNode<N> node : children.values() )
            {
                size += node.size();
            }
        }

        return size;
    }


    /**
     * @return Return the stored element, if any
     */
    public synchronized N getElement()
    {
        return nodeElement;
    }


    /**
     * @return Return the stored element, if any
     * @param dn The Dn we want to get the element for
     */
    public synchronized N getElement( Dn dn )
    {
        DnNode<N> node = getNode( dn );

        if ( node == null )
        {
            return null;
        }

        return node.nodeElement;
    }


    /**
     * @return True if the Node stores an element. BranchNode may not hold any
     * element.
     */
    public synchronized boolean hasElement()
    {
        return nodeElement != null;
    }


    /**
     * @return True if the Node stores an element. BranchNode may not hold any
     * element.
     * @param dn The Dn we want to get the element for
     */
    public synchronized boolean hasElement( Dn dn )
    {
        DnNode<N> node = getNode( dn );

        if ( node == null )
        {
            return false;
        }

        return node.nodeElement != null;
    }


    /**
     * recursively check if the node has a descendant having an element
     */
    private synchronized boolean hasDescendantElement( DnNode<N> node )
    {
        if ( node == null )
        {
            return false;
        }

        if ( node.hasElement() )
        {
            return true;
        }

        for ( DnNode<N> child : node.getChildren().values() )
        {
            if ( hasDescendantElement( child ) )
            {
                return true;
            }
        }

        // Nothing found ...
        return false;
    }


    /**
     * @return True if one of the node below the current node has one element, 
     * False otherwise
     * @param dn The Dn we want to get the element for
     */
    public synchronized boolean hasDescendantElement( Dn dn )
    {
        DnNode<N> node = getNode( dn );

        if ( node == null )
        {
            return false;
        }

        // We must be at the right place in the tree
        if ( node.getDn().size() != dn.size() )
        {
            return false;
        }

        if ( node.hasChildren() )
        {
            for ( DnNode<N> child : node.getChildren().values() )
            {
                if ( hasDescendantElement( child ) )
                {
                    return true;
                }
            }
        }

        return false;
    }


    /**
     * recursively get all the elements from nodes having an element
     */
    private synchronized void getDescendantElements( DnNode<N> node, List<N> descendants )
    {
        if ( node == null )
        {
            return;
        }

        if ( node.hasElement() )
        {
            descendants.add( node.getElement() );

            // Stop here
            return;
        }

        for ( DnNode<N> child : node.getChildren().values() )
        {
            getDescendantElements( child, descendants );
        }
    }


    /**
     * @return True if one of the node below the current node has one element, 
     * False otherwise
     * @param dn The Dn we want to get the element for
     */
    public synchronized List<N> getDescendantElements( Dn dn )
    {
        List<N> descendants = new ArrayList<>();

        DnNode<N> node = getNode( dn );

        if ( node == null )
        {
            return descendants;
        }

        // We must be at the right place in the tree
        if ( node.getDn().size() != dn.size() )
        {
            return descendants;
        }

        if ( node.hasChildren() )
        {
            for ( DnNode<N> child : node.getChildren().values() )
            {
                getDescendantElements( child, descendants );
            }
        }

        return descendants;
    }


    /**
     * Tells if the current DnNode has some children or not
     *
     * @return <code>true</code> if the node has some children
     */
    public synchronized boolean hasChildren()
    {
        return ( children != null ) && children.size() != 0;
    }


    /**
     * Tells if a node has some children or not.
     *
     * @param dn the node's Dn
     * @return <code>true</code> if the node has some children
     * @throws LdapException if the Dn is null or empty
     */
    public synchronized boolean hasChildren( Dn dn ) throws LdapException
    {
        checkDn( dn );

        DnNode<N> node = getNode( dn );

        return ( node != null ) && node.hasChildren();
    }


    /**
     * @return The list of DnNode
     */
    public synchronized Map<Rdn, DnNode<N>> getChildren()
    {
        return children;
    }


    /**
     * @return The parent DnNode, if any
     */
    public synchronized DnNode<N> getParent()
    {
        return parent;
    }


    /**
     * @return True if the current DnNode has a parent
     */
    public synchronized boolean hasParent()
    {
        return parent != null;
    }


    /**
     * Tells if there is a parent for a given Dn,. This parent should be a
     * subset of the given dn.<br>
     * For instance, if we have stored dc=acme, dc=org into the tree,
     * the Dn: ou=example, dc=acme, dc=org will have a parent
     * <br>For the Dn ou=apache, dc=org, there is no parent, so false will be returned.
     *
     * @param dn the normalized distinguished name to resolve to a parent
     * @return true if there is a parent associated with the normalized dn
     */
    public synchronized boolean hasParent( Dn dn )
    {
        List<Rdn> rdns = dn.getRdns();

        DnNode<N> currentNode = this;
        DnNode<N> parentNode = null;

        // Iterate through all the Rdn until we find the associated element
        for ( int i = rdns.size() - 1; i >= 0; i-- )
        {
            Rdn rdn = rdns.get( i );

            if ( rdn.equals( currentNode.nodeRdn ) )
            {
                parentNode = currentNode;
            }
            else if ( currentNode.hasChildren() )
            {
                currentNode = currentNode.children.get( rdn );

                if ( currentNode == null )
                {
                    break;
                }

                parentNode = currentNode;
            }
            else
            {
                break;
            }
        }

        return parentNode != null;
    }


    /**
     * Add a new node in the tree. The added node won't have any element.
     *
     * @param dn The node's Dn
     * @return the corresponding node
     * @throws LdapException if the Dn is null or empty
     */
    public synchronized DnNode<N> add( Dn dn ) throws LdapException
    {
        return add( dn, null );
    }


    /**
     * Add a new node in the tree. We can't add a node if its Dn is empty. The
     * added element is attached to the node, which is named by the Dn's Rdn.<br>
     *
     * @param dn The node's Dn
     * @param element The element to associate with this Node. Can be null.
     * @return the corresponding node
     * @throws LdapException if the Dn is null or empty
     */
    public synchronized DnNode<N> add( Dn dn, N element ) throws LdapException
    {
        checkDn( dn );

        // We first have to find the Node which will be the parent
        DnNode<N> parentNode = getNode( dn );

        if ( parentNode == null )
        {
            // No parent : add a new node to the root
            DnNode<N> childNode = createNode( dn, element, dn.size() );
            childNode.parent = this;
            children.put( childNode.nodeRdn, childNode );
            
            return childNode;
        }
        else
        {
            // We have a parent. Add the new node to the found parent
            int nbRdns = dn.size() - parentNode.depth;

            if ( nbRdns == 0 )
            {
                // That means the added Dn is already present. Check if it already has an element
                if ( parentNode.hasElement() )
                {
                    String message = "Cannot add a node to a node already having an element";
                    LOG.error( message );
                    throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, message );
                }
                // We may try to add twice the same Dn, without any element
                else if ( element == null )
                {
                    String message = "Cannot add a node with no element if it already exists";
                    LOG.error( message );
                    throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, message );
                }
                // All is fine : we are just injecting some data into an existing node
                else
                {
                    parentNode.setElement( element );
                    
                    return parentNode;
                }
            }
            else
            {
                DnNode<N> childNode = createNode( dn, element, nbRdns );

                // done. now, add the newly created tree to the parent node
                childNode.parent = parentNode;
                parentNode.children.put( childNode.nodeRdn, childNode );

                return childNode;
            }
        }
    }


    /**
     * Removes a node from the tree.
     *
     * @param dn the node's Dn
     * @throws LdapException if the Dn is null or empty
     */
    public synchronized void remove( Dn dn ) throws LdapException
    {
        checkDn( dn );

        // Find the parent first : we won't be able to remove
        // a node if it's not present in the tree !
        DnNode<N> parentNode = getNode( dn );

        if ( parentNode == null )
        {
            return;
        }

        // Now, check that this parent has the same Dn than the one
        // we gave and that there is no children
        if ( ( dn.size() != parentNode.depth ) || parentNode.hasChildren() )
        {
            return;
        }

        // Ok, no children, same Dn, let's remove what we can.
        parentNode = parentNode.getParent();

        for ( Rdn rdn : dn.getRdns() )
        {
            parentNode.children.remove( rdn );

            if ( parentNode.children.size() > 0 )
            {
                // We have to stop here, because the parent's node is shared with other Node.
                break;
            }

            parentNode = parentNode.getParent();
        }
    }


    /**
     * Tells if the current DnBranchNode contains another node associated
     * with an rdn.
     *
     * @param rdn The name we are looking for
     * @return <code>true</code> if the tree instance contains this name
     */
    public synchronized boolean contains( Rdn rdn )
    {
        return children.containsKey( rdn );
    }


    /**
     * Get's a child using an rdn string.
     *
     * @param rdn the rdn to use as the node key
     * @return the child node corresponding to the rdn.
     */
    public synchronized DnNode<N> getChild( Rdn rdn )
    {
        if ( children.containsKey( rdn ) )
        {
            return children.get( rdn );
        }

        return null;
    }


    /**
     * @return The Node's Rdn
     */
    public synchronized Rdn getRdn()
    {
        return nodeRdn;
    }


    /**
     * Get the Node for a given Dn, if present in the tree.<br>
     * For instance, if we have stored dc=acme, dc=org into the tree,
     * the Dn: ou=example, dc=acme, dc=org will have a parent, and
     * dc=acme, dc=org will be returned.
     * <br>For the Dn ou=apache, dc=org, there is no parent, so null will be returned.
     *
     * @param dn the normalized distinguished name to resolve to a parent
     * @return the Node associated with the normalized dn
     */
    public synchronized DnNode<N> getNode( Dn dn )
    {
        List<Rdn> rdns = dn.getRdns();

        DnNode<N> currentNode = this;
        DnNode<N> parentNode = null;

        // Iterate through all the Rdn until we find the associated partition
        for ( int i = rdns.size() - 1; i >= 0; i-- )
        {
            Rdn rdn = rdns.get( i );

            if ( currentNode.hasChildren() )
            {
                currentNode = currentNode.children.get( rdn );

                if ( currentNode == null )
                {
                    break;
                }

                parentNode = currentNode;
            }
            else
            {
                break;
            }
        }

        return parentNode;
    }


    /**
     * Get the closest Node for a given Dn which has an element, if present in the tree.<br>
     * For instance, if we have stored dc=acme, dc=org into the tree,
     * the Dn: ou=example, dc=acme, dc=org will have a parent, and
     * dc=acme, dc=org will be returned if it has an associated element.
     * <br>For the Dn ou=apache, dc=org, there is no parent, so null will be returned.
     *
     * @param dn the normalized distinguished name to resolve to a parent
     * @return the Node associated with the normalized dn
     */
    public synchronized boolean hasParentElement( Dn dn )
    {
        List<Rdn> rdns = dn.getRdns();

        DnNode<N> currentNode = this;
        boolean hasElement = false;

        // Iterate through all the Rdn until we find the associated partition
        for ( int i = rdns.size() - 1; i >= 0; i-- )
        {
            Rdn rdn = rdns.get( i );

            if ( currentNode.hasChildren() )
            {
                currentNode = currentNode.children.get( rdn );

                if ( currentNode == null )
                {
                    break;
                }

                if ( currentNode.hasElement() )
                {
                    hasElement = true;
                }

                parent = currentNode;
            }
            else
            {
                break;
            }
        }

        return hasElement;
    }


    /**
     * Get the closest Node for a given Dn which has an element, if present in the tree.<br>
     * For instance, if we have stored dc=acme, dc=org into the tree,
     * the Dn: ou=example, dc=acme, dc=org will have a parent, and
     * dc=acme, dc=org will be returned if it has an associated element.
     * <br>For the Dn ou=apache, dc=org, there is no parent, so null will be returned.
     *
     * @param dn the normalized distinguished name to resolve to a parent
     * @return the Node associated with the normalized dn
     */
    public synchronized DnNode<N> getParentWithElement( Dn dn )
    {
        List<Rdn> rdns = dn.getRdns();

        DnNode<N> currentNode = this;
        DnNode<N> element = null;

        // Iterate through all the Rdn until we find the associated partition
        for ( int i = rdns.size() - 1; i >= 1; i-- )
        {
            Rdn rdn = rdns.get( i );

            if ( currentNode.hasChildren() )
            {
                currentNode = currentNode.children.get( rdn );

                if ( currentNode == null )
                {
                    break;
                }

                if ( currentNode.hasElement() )
                {
                    element = currentNode;
                }

                parent = currentNode;
            }
            else
            {
                break;
            }
        }

        return element;
    }


    /**
     * Get the closest Node for a given Dn which has an element, if present in the tree.<br>
     * For instance, if we have stored dc=acme, dc=org into the tree,
     * the Dn: ou=example, dc=acme, dc=org will have a parent, and
     * dc=acme, dc=org will be returned if it has an associated element.
     * <br>For the Dn ou=apache, dc=org, there is no parent, so null will be returned.
     *
     * @return the Node associated with the normalized dn
     */
    public synchronized DnNode<N> getParentWithElement()
    {
        DnNode<N> currentNode = parent;

        while ( currentNode != null )
        {
            if ( currentNode.nodeElement != null )
            {
                return currentNode;
            }

            currentNode = currentNode.parent;
        }

        return null;
    }


    /**
     * rename the DnNode's Dn
     * 
     * @param newRdn the new Rdn of this node
     * @throws LdapException If the rename failed
     */
    public synchronized void rename( Rdn newRdn ) throws LdapException
    {
        Dn temp = nodeDn.getParent();
        temp = temp.add( newRdn );

        Rdn oldRdn = nodeRdn;

        nodeRdn = temp.getRdn();
        nodeDn = temp;

        if ( parent != null )
        {
            parent.children.remove( oldRdn );
            parent.children.put( nodeRdn, this );
        }

        updateAfterModDn( nodeDn );
    }


    /**
     * move the DnNode's Dn
     *
     * @param newParent the new parent Dn
     * @throws LdapException If the move failed
     */
    public synchronized void move( Dn newParent ) throws LdapException
    {
        DnNode<N> tmp = null;

        Dn tmpDn = null;

        // check if the new parent Dn is child of the parent
        if ( newParent.isDescendantOf( parent.nodeDn ) )
        {
            tmp = parent;
            tmpDn = parent.nodeDn;
        }

        // if yes, then drill for the new parent node
        if ( tmpDn != null )
        {
            int parentNodeSize = tmpDn.size();
            int count = newParent.size() - parentNodeSize;

            while ( count-- > 0 )
            {
                tmp = tmp.getChild( newParent.getRdn( parentNodeSize++ ) );
            }
        }

        // if not, we have to traverse all the way up to the 
        // root node and then find the new parent node
        if ( tmp == null )
        {
            tmp = this;
            while ( tmp.parent != null )
            {
                tmp = tmp.parent;
            }

            tmp = tmp.getNode( newParent );
        }

        nodeDn = newParent.add( nodeRdn );
        updateAfterModDn( nodeDn );

        if ( parent != null )
        {
            parent.children.remove( nodeRdn );
        }

        parent = tmp;
        parent.children.put( nodeRdn, this );
    }


    /**
     * update the children's Dn based on the new parent Dn created
     * after a rename or move operation
     * 
     * @param newParentDn
     */
    private synchronized void updateAfterModDn( Dn newParentDn ) throws LdapInvalidDnException
    {
        if ( children != null )
        {
            for ( DnNode<N> child : children.values() )
            {
                child.nodeDn = newParentDn.add( child.nodeRdn );
                child.updateAfterModDn( child.nodeDn );
            }
        }
    }


    private String toString( String tabs )
    {
        if ( nodeRdn == null )
        {
            return tabs;
        }

        StringBuilder sb = new StringBuilder();
        sb.append( tabs );

        boolean hasChildren = hasChildren();

        if ( isLeaf() )
        {
            sb.append( "Leaf[" ).append( nodeDn ).append( "]: " ).append( "'" ).append( nodeElement ).append( "'" );
            return sb.toString();
        }

        sb.append( "Branch[" ).append( nodeDn ).append( "]: " );

        if ( nodeElement != null )
        {
            sb.append( "'" ).append( nodeElement ).append( "'" );
        }

        tabs += "    ";

        sb.append( '\n' );

        boolean isFirst = true;

        if ( hasChildren )
        {
            for ( Map.Entry<Rdn, DnNode<N>> entry : children.entrySet() )
            {
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    sb.append( "\n" );
                }

                DnNode<N> child = entry.getValue();

                sb.append( child.toString( tabs ) );
            }
        }

        return sb.toString();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return toString( "" );
    }


    /**
     * @return the dn
     */
    public synchronized Dn getDn()
    {
        return nodeDn;
    }
}
