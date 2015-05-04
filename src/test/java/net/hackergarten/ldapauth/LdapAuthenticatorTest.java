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
        String dn = ldapAuthenticator.getDn("read-only-admin");
        assertEquals("cn=read-only-admin,dc=example,dc=com",dn);
    }

    public void testGetUidForUnknownUserReturnsNull() throws Exception {
        LdapAuthenticator ldapAuthenticator = new LdapAuthenticator("dc=example,dc=com", "ldap://ldap.forumsys.com:389/");
        ldapAuthenticator.setUidProperty("cn");
        String uid = ldapAuthenticator.getDn("non-existent-user");
        assertNull(uid);
    }

    public void testBind() throws Exception {
        LdapAuthenticator ldapAuthenticator = new LdapAuthenticator("dc=example,dc=com", "ldap://ldap.forumsys.com:389/");
        boolean authenticated = ldapAuthenticator.testBind("cn=read-only-admin,dc=example,dc=com", "password");
        assertTrue(authenticated);
    }

    public void testBindFailsOnInvalidPassword() throws Exception {
        LdapAuthenticator ldapAuthenticator = new LdapAuthenticator("dc=example,dc=com", "ldap://ldap.forumsys.com:389/");
        boolean authenticated = ldapAuthenticator.testBind("cn=read-only-admin,dc=example,dc=com", "wrongPassword");
        assertFalse(authenticated);
    }

    public void testSearch() throws Exception{
        // tag::search[]
        LdapAuthenticator ldapAuthenticator = new LdapAuthenticator("dc=example,dc=com", "ldap://ldap.forumsys.com:389/");
        ldapAuthenticator.setUidProperty("uid");
        ldapAuthenticator.setSearchAttributes("uid,cn,sn,mail");
        Map<String, String> result = ldapAuthenticator.search("riemann");
        assertNotNull(result);
        assertEquals(4,result.size());
        assertEquals("riemann", ((Map.Entry) result.entrySet().toArray()[0]).getValue());
        assertEquals("riemann@ldap.forumsys.com", ((Map.Entry) result.entrySet().toArray()[1]).getValue());
        assertEquals("Riemann", ((Map.Entry) result.entrySet().toArray()[2]).getValue());
        assertEquals("Bernhard Riemann", ((Map.Entry) result.entrySet().toArray()[3]).getValue());
        // end::search[]
    }

    public void testSearchForUnknownUserReturnsNull() throws Exception {
        LdapAuthenticator ldapAuthenticator = new LdapAuthenticator("dc=example,dc=com", "ldap://ldap.forumsys.com:389/");
        ldapAuthenticator.setUidProperty("cn");
        Map<String, String> result = ldapAuthenticator.search("non-existent-user");
        assertNull(result);
    }

    public void testSearchForUserWithWrongAttrsReturnsEmptyMap() throws Exception {
        LdapAuthenticator ldapAuthenticator = new LdapAuthenticator("dc=example,dc=com", "ldap://ldap.forumsys.com:389/");
        ldapAuthenticator.setUidProperty("uid");
        ldapAuthenticator.setSearchAttributes("unknown,sample");
        Map<String, String> result = ldapAuthenticator.search("riemann");
        assertEquals(0,result.size());
    }
}
