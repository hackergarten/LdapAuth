package net.hackergarten.ldapauth;

/*
 *
 */

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
    private String searchBase = "ou=accounts,dc=hackergarten,dc=net";
    private String ldapURI = "ldap://hackergartenserver:389/";// + searchBase;
    private String uidProperty = "uid";
    private String searchAttributes = "cn,givenName,mail";

    public LdapAuthenticator(String searchBase, String ldapURI) {
        this.searchBase = searchBase;
        this.ldapURI = ldapURI;
    }

    void setUidProperty(String uidProperty) {
        this.uidProperty = uidProperty;
    }

    void setSearchAttributes(String searchAttributes) {
        this.searchAttributes = searchAttributes;
    }

    private DirContext ldapContext() throws NamingException {
        Hashtable<String, String> env = new Hashtable<String, String>();
        return ldapContext(env);
    }

    private DirContext ldapContext(Hashtable<String, String> env) throws NamingException {
        env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY);
        env.put(Context.PROVIDER_URL, ldapURI);
        DirContext ctx = new InitialDirContext(env);
        return ctx;
    }

    public String getUid(String user) throws Exception {
        DirContext ctx = ldapContext();

        String filter = "(" + uidProperty + "=" + user + ")";
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

    public boolean testBind(String dn, String password) throws Exception {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, dn);
        env.put(Context.SECURITY_CREDENTIALS, password);

        try {
            ldapContext(env);
        } catch (javax.naming.AuthenticationException e) {
            return false;
        }
        return true;
    }

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
                amap = new HashMap<String, String>();
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
