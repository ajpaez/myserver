package com.apr.server.security.ldap;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;

import org.springframework.ldap.core.AttributesMapper;

public class PersonAttributesMapper implements AttributesMapper {

    /**
     * Maps the given attributes into a {@link Person} object.
     *
     * @see org.springframework.ldap.core.AttributesMapper#mapFromAttributes(javax.naming.directory.Attributes)
     */
    public Object mapFromAttributes(Attributes attributes)
            throws NamingException {
        Person person = new Person();
        person.setFullname((String) attributes.get("cn").get());
        person.setLastname((String) attributes.get("sn").get());
        person.setEmail((String) attributes.get("mail").get());
        return person;
    }
}
