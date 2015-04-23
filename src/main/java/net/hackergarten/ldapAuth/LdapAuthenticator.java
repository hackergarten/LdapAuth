package net.hackergarten.ldapauth;

/*
 *
 */

import java.util.*;
import javax.naming.*;
import javax.naming.directory.*;

public class LdapAuthenticator {
    private final static String searchBase = "ou=accounts,dc=hackergarten,dc=net";
    private final static String ldapURI = "ldap://hackergartenserver:389/";// + searchBase;
    private final static String contextFactory = "com.sun.jndi.ldap.LdapCtxFactory";

    private DirContext ldapContext () throws NamingException {
        Hashtable<String,String> env = new Hashtable <String,String>();
        return ldapContext(env);
    }

    private DirContext ldapContext (Hashtable <String,String>env) throws NamingException {
        env.put(Context.INITIAL_CONTEXT_FACTORY, contextFactory);
        env.put(Context.PROVIDER_URL, ldapURI);
        DirContext ctx = new InitialDirContext(env);
        return ctx;
    }

    public String getUid (String user) throws Exception {
        DirContext ctx = ldapContext();

        String filter = "(uid=" + user + ")";
        SearchControls ctrl = new SearchControls();
        ctrl.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration answer = ctx.search(searchBase, filter, ctrl);

        String dn;
        if (answer.hasMore()) {
            SearchResult result = (SearchResult) answer.next();
            dn = result.getNameInNamespace();
        }
        else {
            dn = null;
        }
        answer.close();
        return dn;
    }

    public boolean testBind (String dn, String password) throws Exception {
        Hashtable<String,String> env = new Hashtable <String,String>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, dn);
        env.put(Context.SECURITY_CREDENTIALS, password);

        try {
            ldapContext(env);
        }
        catch (javax.naming.AuthenticationException e) {
            return false;
        }
        return true;
    }

    public Map<String,String> search(String uid) throws NamingException{
        DirContext ldap = ldapContext();

        SearchControls searchCtls = new SearchControls();
        searchCtls.setReturningAttributes("cn,givenName,mail".split(","));
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        NamingEnumeration<SearchResult> answer = ldap.search(searchBase, "(uid=" + uid + ")", searchCtls);
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
