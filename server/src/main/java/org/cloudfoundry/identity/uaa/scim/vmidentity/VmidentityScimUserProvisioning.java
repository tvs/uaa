/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2017] VMware, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.vmidentity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.client.VmidentityDataAccessException;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Name;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.Validate;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;

import com.vmware.identity.idm.InvalidPrincipalException;
import com.vmware.identity.idm.PersonDetail;
import com.vmware.identity.idm.PersonUser;
import com.vmware.identity.idm.PrincipalId;
import com.vmware.identity.idm.client.CasIdmClient;

import static org.cloudfoundry.identity.uaa.util.CompareUtils.compareToList;


public class VmidentityScimUserProvisioning implements ScimUserProvisioning, ResourceMonitor<ScimUser> {

    public static final String USER_FIELDS = "id,version,created,lastModified,username,email,givenName,familyName,active,phoneNumber,verified,origin,external_id,identity_zone_id,salt,passwd_lastmodified ";

    private final Log logger = LogFactory.getLog(VmidentityScimUserProvisioning.class);
    private final CasIdmClient idmClient;

    public VmidentityScimUserProvisioning(CasIdmClient casIdmClient) {
        this.idmClient = casIdmClient;
    }

    @Override
    public List<ScimUser> retrieveAll() {
        return query("id pr");
    }

    @Override
    public ScimUser retrieve(String id) {
        try {
            String tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);
            String[] parts = id.split("@");
            PrincipalId userId = new PrincipalId(parts[0], parts[1]);
            PersonUser personUser = this.idmClient.findPersonUser(tenant, userId);

            if (personUser == null) {
                throw new InvalidPrincipalException("User not found.", id);
            }
            return getScimUser(personUser, tenant, systemDomain);
        } catch (InvalidPrincipalException ex) {
            throw new ScimResourceNotFoundException(id);
        } catch (Exception ex) {
            throw new IllegalStateException(
                    String.format("User '%s' not found in tenant '%s'.", id, VmidentityUtils.getZoneId()), ex);
        }
    }

    @Override
    public ScimUser create(ScimUser resource) {
        return this.createUser(resource, resource.getPassword());
    }

    @Override
    public ScimUser update(String id, ScimUser resource) {
        // todo: fix no op
        return this.retrieve(id);
    }

    @Override
    public ScimUser delete(String id, int version) {
        try {
            String tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);
            String[] parts = id.split("@");
            PrincipalId userId = new PrincipalId(parts[0], parts[1]);

            ScimUser user = getScimUser(this.idmClient.findPersonUser(tenant, userId), tenant, systemDomain);
            this.idmClient.deletePrincipal(tenant, parts[0]);
            return user;
        } catch (InvalidPrincipalException ex) {
            throw new ScimResourceNotFoundException(id);
        } catch (Exception ex) {
            throw new IllegalStateException(String.format("User '%s' not found in tenant '%s'.", id, VmidentityUtils.getZoneId()), ex);
        }
    }

    @Override
    public List<ScimUser> query(String filter) {
        logger.debug("Querying users with filter: " + filter);

        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);

            Set<PersonUser> users = idmClient.findPersonUsersByScimFilter(tenant, filter);
            ArrayList<ScimUser> scimUsers = new ArrayList<ScimUser>(users.size());
            for (PersonUser user : users) {
                scimUsers.add(getScimUser(user, tenant, systemDomain));
            }

            return scimUsers;
        } catch (Exception e) {
            logger.error("Unable to query users by filter '" + filter + "'", e);
            throw new VmidentityDataAccessException("Unable to query users by filter: " + filter);
        }
    }

    @Override
    public List<ScimUser> query(String filter, String sortBy, boolean ascending) {
        List<ScimUser> users = query(filter);

        if (sortBy != null) {
            sortScimUsers(users, sortBy, ascending);
        }
        return users;
    }

    @Override
    public int delete(String filter) {
        logger.debug("Filtering users with query: " + filter);

        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            Set<PersonUser> users = idmClient.findPersonUsersByScimFilter(tenant, filter);
            for (PersonUser user : users) {
                idmClient.deletePrincipal(tenant, user.getId().getUPN());
            }
            return users.size();
        } catch (Exception e) {
            logger.error("Unable to delete users by filter '" + filter + "'", e);
            throw new VmidentityDataAccessException("Unable to delete users by filter: " + filter);
        }
    }

    @Override
    public ScimUser createUser(ScimUser user, String password)
            throws InvalidPasswordException, InvalidScimResourceException {
        try {
            String tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);
            String name = user.getUserName();
            String[] parts = name.split("@");
            if (parts.length > 2) {
                throw new InvalidScimResourceException(String.format("Invalid format for user name '%s'", name));
            } else if (parts.length == 2) {
                if (systemDomain.equalsIgnoreCase(parts[1]) == false) {
                    throw new InvalidScimResourceException("Cannot create users in external domains.");
                }

                name = parts[0];
            }
            PersonDetail.Builder builder = new PersonDetail.Builder()
                                                                     .firstName(user.getGivenName())
                                                                     .lastName(user.getFamilyName());
            PrincipalId userId = this.idmClient.addPersonUser(tenant, name, builder.build(), password.toCharArray());
            PersonUser personUser = this.idmClient.findPersonUser(tenant, userId);

            if (personUser == null) {
                throw new InvalidPrincipalException("User not found.", userId.toString());
            }
            return getScimUser(personUser, tenant, systemDomain);
        } catch (InvalidPrincipalException ex) {
            throw new ScimResourceNotFoundException(user.getUserName());
        } catch (Exception ex) // todo: exception
        {
            throw new IllegalStateException(String.format("User '%s' not found in tenant '%s'.", user.getUserName(), VmidentityUtils.getZoneId()), ex);
        }
    }

    @Override
    public void changePassword(String id, String oldPassword, String newPassword) throws ScimResourceNotFoundException {
        throw new UnsupportedOperationException();
    }

    @Override
    public ScimUser verifyUser(String id, int version)
            throws ScimResourceNotFoundException, InvalidScimResourceException {
        return this.retrieve(id);
    }

    @Override
    public boolean checkPasswordMatches(String id, String password) throws ScimResourceNotFoundException {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getTotalCount() {
        // TODO need to plumb through idm - get total user's count
        return 3;
    }

    private static ScimUser getScimUser(PersonUser personUser, String tenant, String systemDomain) {
        String upn = VmidentityUtils.getPrincipalUpn(personUser.getId());
        ScimUser user = new ScimUser();
        user.setId(upn);
        ScimMeta meta = new ScimMeta();
        meta.setVersion(1);
        // meta.setCreated(created);
        // meta.setLastModified(lastModified);
        user.setMeta(meta);
        user.setUserName(upn);
        user.addEmail(upn);
        // if (phoneNumber != null) {
        // user.addPhoneNumber(phoneNumber);
        // }
        Name name = new Name();
        name.setGivenName(personUser.getDetail().getFirstName());
        name.setFamilyName(personUser.getDetail().getLastName());
        user.setName(name);
        user.setActive((!personUser.isDisabled()) && (!personUser.isLocked()));
        user.setVerified(true);
        user.setOrigin((systemDomain.equalsIgnoreCase(personUser.getId().getDomain())) ? OriginKeys.UAA : OriginKeys.LDAP);
        // user.setExternalId(externalId);
        user.setZoneId(tenant);
        // user.setSalt(salt);
        user.setPasswordLastModified(new Date(personUser.getDetail().getPwdLastSet()));
        return user;
    }

    private void sortScimUsers(List<ScimUser> list, String sortBy, boolean ascending) {
        validateOrderBy(sortBy);
        switch (sortBy.toLowerCase()) {
            case "id":
                Collections.sort(list, (a, b) -> a.getId().compareTo(b.getId()));
                break;
            case "version":
                Collections.sort(list, (a, b) -> Integer.compare(a.getVersion(), b.getVersion()));
                break;
            case "created":
                Collections.sort(list, (a, b) -> a.getMeta().getCreated().compareTo(b.getMeta().getCreated()));
                break;
            case "lastmodified":
                Collections.sort(list, (a, b) -> a.getMeta().getLastModified().compareTo(b.getMeta().getLastModified()));
                break;
            case "username":
                Collections.sort(list, (a, b) -> a.getUserName().compareTo(b.getUserName()));
                break;
            case "email":
                Collections.sort(list, (a, b) -> compareToList(a.getEmails(), b.getEmails()));
                break;
            case "givenname":
                Collections.sort(list, (a, b) -> a.getGivenName().compareTo(b.getGivenName()));
                break;
            case "familyname":
                Collections.sort(list, (a, b) -> a.getFamilyName().compareTo(b.getFamilyName()));
                break;
            case "active":
                Collections.sort(list, (a, b) -> Boolean.compare(a.isActive(), b.isActive()));
                break;
            case "phonenumber":
                Collections.sort(list, (a, b) -> compareToList(a.getPhoneNumbers(), b.getPhoneNumbers()));
                break;
            case "verified":
                Collections.sort(list, (a, b) -> Boolean.compare(a.isVerified(), b.isVerified()));
                break;
            case "origin":
                Collections.sort(list, (a, b) -> a.getOrigin().compareTo(b.getOrigin()));
                break;
            case "external_id":
                Collections.sort(list, (a, b) -> a.getExternalId().compareTo(b.getExternalId()));
                break;
            case "identity_zone_id":
                Collections.sort(list, (a, b) -> a.getZoneId().compareTo(b.getZoneId()));
                break;
            case "salt":
                Collections.sort(list, (a, b) -> a.getSalt().compareTo(b.getSalt()));
                break;
            case "passwd_lastmodified":
                Collections.sort(list, (a, b) -> a.getPasswordLastModified().compareTo(b.getPasswordLastModified()));
                break;
        }

        if (!ascending) {
            Collections.reverse(list);
        }
    }

    private void validateOrderBy(String orderBy) throws IllegalArgumentException {
        Validate.validateOrderBy(orderBy.toLowerCase(), USER_FIELDS.toLowerCase());
    }

}
