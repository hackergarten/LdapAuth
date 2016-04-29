/*
 * Copyright 2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.hackergarten.ldapauth;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

public class LdapAuthenticator {

    private static final String CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    private static final String DEFAULT_AUTHENTICATION_METHOD = "simple";

    //i.e "ou=accounts,dc=hackergarten,dc=net"
    private String searchBase;
    //i.e "ldap://hackergartenserver:389/"
    private String ldapURI;
    private String uidProperty = "uid";
    private String searchAttributes = "cn,givenName,mail";

    public LdapAuthenticator(String searchBase, String ldapURI) {
        this.searchBase = searchBase;
        this.ldapURI = ldapURI;
    }

    public void setUidProperty(String uidProperty) {
        this.uidProperty = uidProperty;
    }

    public String getUidProperty() {
        return uidProperty;
    }

    public void setSearchAttributes(String searchAttributes) {
        this.searchAttributes = searchAttributes;
    }

    private DirContext ldapContext() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        return ldapContext(env);
    }

    DirContext ldapContext(Hashtable<String, String> env) throws NamingException {
        env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
        env.put(Context.PROVIDER_URL, ldapURI);
        return new InitialDirContext(env);
    }

    /**
     * find the full distinguished name (DN) for a given (identifying) property
     *
     * @param idPropValue the value to use to lookup the user, use "setUidProperty" to define the attribute
     * @return DN for the user, NULL if no match could be found
     * @throws NamingException
     */
    public String getDn(String idPropValue) throws NamingException {
        DirContext ctx = ldapContext();

        String filter = "(" + uidProperty + "=" + idPropValue + ")";
        SearchControls ctrl = new SearchControls();
        ctrl.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration answer = ctx.search(searchBase, filter, ctrl);

        String dn;
        if (answer.hasMore()) {
            SearchResult result = (SearchResult) answer.next();
            dn = result.getNameInNamespace();
        } else {
            dn = null;
        }
        answer.close();
        return dn;
    }

    /**
     *
     * @param dn the LDAP DistinguishedName of the user to authenticate ("bind" in LDAP terms)
     * @param password password of the user
     * @return boolean indicating if authentication was successful
     * @throws NamingException
     */
    public boolean testBind(String dn, String password) throws NamingException {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.SECURITY_AUTHENTICATION, DEFAULT_AUTHENTICATION_METHOD);
        env.put(Context.SECURITY_PRINCIPAL, dn);
        env.put(Context.SECURITY_CREDENTIALS, password);

        try {
            ldapContext(env);
        } catch (javax.naming.AuthenticationException e) {
            return false;
        }
        return true;
    }

    /**
     * Search for a LDAP entity with an identifying value, the property to use for the search can be declared with
     * `setUidProperty`, the attributes included in the results can be set with `etSearchAttributes`.
     *
     * @param uid value to search for
     * @return a Map of the properties set by `setSearchAttributes`
     * @throws NamingException
     */
    public Map<String, String> search(String uid) throws NamingException {
        DirContext ldap = ldapContext();

        SearchControls searchCtls = new SearchControls();
        searchCtls.setReturningAttributes(searchAttributes.split(","));
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        NamingEnumeration<SearchResult> answer = ldap.search(searchBase, "(" + uidProperty + "=" + uid + ")", searchCtls);
        Map<String, String> amap = null;
        if (answer.hasMoreElements()) {
            Attributes attrs = answer.next().getAttributes();
            if (attrs != null) {
                amap = new HashMap<>();
                NamingEnumeration<? extends Attribute> ne = attrs.getAll();

                while (ne.hasMore()) {
                    Attribute attr = ne.next();
                    amap.put(attr.getID(), attr.get().toString());
                }
                ne.close();
            }
        }
        return amap;
    }
}
