package net.hackergarten.ldapauth;

import java.util.Map;

import junit.framework.TestCase;

/**
 * Implement some basic test using the public ldap from forumsys.
 *
 * see http://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/
 */
public class LdapAuthenticatorTest extends TestCase {

    public void testGetUid() throws Exception {
        LdapAuthenticator ldapAuthenticator = new LdapAuthenticator("dc=example,dc=com", "ldap://ldap.forumsys.com:389/");
        ldapAuthenticator.setUidProperty("cn");
        String uid = ldapAuthenticator.getUid("read-only-admin");
        assertEquals("cn=read-only-admin,dc=example,dc=com",uid);
    }

    public void testBind() throws Exception {
        LdapAuthenticator ldapAuthenticator = new LdapAuthenticator("dc=example,dc=com", "ldap://ldap.forumsys.com:389/");
        boolean authenticated = ldapAuthenticator.testBind("cn=read-only-admin,dc=example,dc=com", "password");
        assertTrue(authenticated);
    }

    public void testSearch() throws Exception{
        LdapAuthenticator ldapAuthenticator = new LdapAuthenticator("dc=example,dc=com", "ldap://ldap.forumsys.com:389/");
        ldapAuthenticator.setUidProperty("uid");
        ldapAuthenticator.setSearchAttributes("uid");
        Map<String, String> result = ldapAuthenticator.search("riemann");
        assertNotNull(result);
        assertEquals(1,result.size());
        assertEquals("riemann", ((Map.Entry)result.entrySet().toArray()[0]).getValue());
    }
}
