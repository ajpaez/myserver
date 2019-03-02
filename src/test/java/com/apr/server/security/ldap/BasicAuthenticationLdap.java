package com.apr.server.security.ldap;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
//@SpringBootTest
public class BasicAuthenticationLdap {

    @Test
    public void exampleTest() {
        //String username = "read-only-admin";
        String username = "tesla";
        try {
            LdapContextSource ldapContextSource = new LdapContextSource();
            ldapContextSource.setUrl("ldap://ldap.forumsys.com:389/");
            ldapContextSource.setBase("dc=example,dc=com");
            ldapContextSource.setUserDn("uid="+ username +",dc=example,dc=com");
            ldapContextSource.setPassword("password");

            try {
                // initialize the context
                ldapContextSource.afterPropertiesSet();
            } catch (Exception e) {
                e.printStackTrace();
            }

            LdapTemplate ldapTemplate = new LdapTemplate(ldapContextSource);
            ldapTemplate.afterPropertiesSet();

            ldapTemplate.setIgnorePartialResultException(true); // Active Directory doesn’t transparently handle referrals. This fixes that.
            AndFilter filter = new AndFilter();
            filter.and(new EqualsFilter("uid", username));


            try {
                boolean authed = ldapTemplate.authenticate(DistinguishedName.EMPTY_PATH, filter.encode(), "password");
                System.out.println("Authenticated: " + authed);

                // SpringPerson extension of Person class from Spring
                Person person = (Person) ldapTemplate.lookup("uid="+ username , new PersonAttributesMapper());
                assertEquals(person.getFullname(), "Nikola Tesla");
                assertEquals(person.getLastname(), "Tesla");
                assertEquals(person.getEmail(), "tesla@ldap.forumsys.com");

            }
            catch(org.springframework.ldap.AuthenticationException ee)
            {
                ee.printStackTrace();
                System.out.println("error");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
