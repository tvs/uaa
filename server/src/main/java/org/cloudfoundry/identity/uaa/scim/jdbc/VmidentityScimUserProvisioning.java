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
package org.cloudfoundry.identity.uaa.scim.jdbc;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Name;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;

import com.unboundid.scim.sdk.SCIMException;
import com.unboundid.scim.sdk.SCIMFilter;
import com.unboundid.scim.sdk.SCIMFilterType;
import com.vmware.identity.idm.InvalidPrincipalException;
import com.vmware.identity.idm.PersonDetail;
import com.vmware.identity.idm.PersonUser;
import com.vmware.identity.idm.PrincipalId;
import com.vmware.identity.idm.client.CasIdmClient;


public class VmidentityScimUserProvisioning implements ScimUserProvisioning, ResourceMonitor<ScimUser> {

    private final Log logger = LogFactory.getLog(VmidentityScimUserProvisioning.class);
    private final CasIdmClient _idmClient;

    public VmidentityScimUserProvisioning(CasIdmClient casIdmClient) {
        this._idmClient = casIdmClient;
    }

    @Override
    public List<ScimUser> retrieveAll() {
        throw new UnsupportedOperationException();
    }

    @Override
    public ScimUser retrieve(String id) {
        try {
            String tenant = VmidentityUtils.getTenantName(this._idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this._idmClient);
            String[] parts = id.split("@");
            PrincipalId userId = new PrincipalId(parts[0], parts[1]);
            PersonUser personUser = this._idmClient.findPersonUser(tenant, userId);

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
            String tenant = VmidentityUtils.getTenantName(this._idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this._idmClient);
            String[] parts = id.split("@");
            PrincipalId userId = new PrincipalId(parts[0], parts[1]);

            ScimUser user = getScimUser(this._idmClient.findPersonUser(tenant, userId), tenant, systemDomain);
            this._idmClient.deletePrincipal(tenant, parts[0]);
            return user;
        } catch (InvalidPrincipalException ex) {
            throw new ScimResourceNotFoundException(id);
        } catch (Exception ex) {
            throw new IllegalStateException(String.format("User '%s' not found in tenant '%s'.", id, VmidentityUtils.getZoneId()), ex);
        }
    }

    @Override
    public List<ScimUser> query(String filter)
    {
        logger.debug(String.format("query called with filter '%s'", filter));

        ArrayList<ScimUser> users = new ArrayList<ScimUser>();
        SCIMFilter scimFilter = null;
        try
        {
            scimFilter = this.scimFilter(filter);
        }
        catch (SCIMException ex)
        {
            logger.debug(String.format("Invalid scim filter '%s'", filter), ex);
            throw new IllegalStateException(String.format("Invalid scim filter '%s'", filter), ex);
        }

        // todo: only support simple filters for now
        // we need implement proper filter support
        //id eq "#{user_id}" or id eq "#{user_id}" or ...
        //username eq "#{username}"

        // UserIdConversionEndpoints does a wrapping of this filter
        // with an AND (origin 1 or origin 2 or origin3 ...) from all active providers
        // idm should always only return active providers.
        //
        // todo: we should revisit if we need existing logic in UserIdConversionEndpoints
        // on this layer it might be unsafe to ignore origin should it ever be done by other logic
        // does not seem to be like this atm ...

        List<SCIMFilter> scimFilters = null;
        if ( ( scimFilter.getFilterType() == SCIMFilterType.AND )
             &&
             (scimFilter.getFilterComponents().size() == 2) )
        {
            if ( isOriginFilter( scimFilter.getFilterComponents().get(1) ) )
            {
                scimFilter = scimFilter.getFilterComponents().get(0);
            }
            else if ( isOriginFilter( scimFilter.getFilterComponents().get(0) ) )
            {
                scimFilter = scimFilter.getFilterComponents().get(1);
            }
        }

        if ( scimFilter.getFilterType() == SCIMFilterType.OR )
        {
            scimFilters = scimFilter.getFilterComponents();
        }
        else if ( scimFilter.getFilterType() == SCIMFilterType.EQUALITY )
        {
            scimFilters = new ArrayList<SCIMFilter>();
            scimFilters.add(scimFilter);
        }
        else
        {
            logger.debug(String.format("Scim filter '%s' not yet supported", filter));
            throw new UnsupportedOperationException(String.format("Scim filter '%s' not yet supported", filter));
        }

        for(SCIMFilter f : scimFilters)
        {
            // for now only support equality by id or username
            if ( f.getFilterType() == SCIMFilterType.EQUALITY )
            {
                if ( ( "id".equalsIgnoreCase(f.getFilterAttribute().getAttributeName()) )
                    || "username".equalsIgnoreCase(f.getFilterAttribute().getAttributeName()))
                {
                    if ( f.getFilterValue() != null )
                    {
                        users.add(this.retrieve(f.getFilterValue()));
                    }
                }
                else
                {
                    logger.debug(String.format("Scim filter '%s' attribute '%s' not yet supported",
                            filter, f.getFilterAttribute().getAttributeName()));
                    throw new UnsupportedOperationException(
                        String.format("Scim filter '%s' attribute '%s' not yet supported",
                            filter, f.getFilterAttribute().getAttributeName()));

                }
            }
            else
            {
                logger.debug(String.format("Scim filter '%s' not yet supported", filter));
                throw new UnsupportedOperationException(String.format("Scim filter '%s' not yet supported" , filter));
            }
        }
        return users;
    }

    @Override
    public List<ScimUser> query(String filter, String sortBy, boolean ascending)
    {
        // todo: sort by, ascending
        return this.query(filter);
    }

    @Override
    public int delete(String filter) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ScimUser createUser(ScimUser user, String password)
            throws InvalidPasswordException, InvalidScimResourceException {
        try {
            String tenant = VmidentityUtils.getTenantName(this._idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this._idmClient);
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
            PrincipalId userId = this._idmClient.addPersonUser(tenant, name, builder.build(), password.toCharArray());
            PersonUser personUser = this._idmClient.findPersonUser(tenant, userId);

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

    private SCIMFilter scimFilter(String filter) throws SCIMException {
        SCIMFilter scimFilter;
        try {
            scimFilter = SCIMFilter.parse(filter);
        } catch (SCIMException e) {
            logger.debug("Attempting legacy scim filter conversion for [" + filter + "]", e);
            filter = filter.replaceAll("'","\"");
            scimFilter = SCIMFilter.parse(filter);
        }
        return scimFilter;
    }

    private static boolean isOriginEqualityFilter(SCIMFilter filter)
    {
        return
           ( (filter.getFilterType() == SCIMFilterType.EQUALITY)
            &&
             ("origin".equalsIgnoreCase(filter.getFilterAttribute().getAttributeName()) ) );
    }

    private static boolean isOriginFilter(SCIMFilter filter)
    {
        boolean result = false;
        if (isOriginEqualityFilter(filter))
        {
            result = true;
        }
        else if ( filter.getFilterType() == SCIMFilterType.OR )
        {
            result = true;
            for(SCIMFilter component : filter.getFilterComponents() )
            {
                if ( isOriginEqualityFilter(component) == false )
                {
                    result = false;
                    break;
                }
            }
        }

        return result;
    }
}
