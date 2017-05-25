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
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.event.SystemDeletable;
import org.cloudfoundry.identity.uaa.client.VmidentityDataAccessException;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;

import com.vmware.identity.idm.Group;
import com.vmware.identity.idm.GroupDetail;
import com.vmware.identity.idm.InvalidPrincipalException;
import com.vmware.identity.idm.PrincipalId;
import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityScimGroupProvisioning implements ScimGroupProvisioning, SystemDeletable {

    private final CasIdmClient idmClient;
    private final Log logger = LogFactory.getLog(VmidentityScimGroupProvisioning.class);

    public VmidentityScimGroupProvisioning(CasIdmClient casIdmClient) {
        this.idmClient = casIdmClient;
    }

    @Override
    public List<ScimGroup> retrieveAll() {
        return query("id pr");
    }

    @Override
    public ScimGroup retrieve(String id) {
        try {
            String tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);
            String[] parts = id.split("@");
            PrincipalId groupId = new PrincipalId(parts[0], parts[1]);
            Group group = this.idmClient.findGroup(tenant, groupId);

            if (group == null) {
                throw new InvalidPrincipalException("Group not found.", id);
            }
            return getScimGroup(group, tenant, systemDomain);
        } catch (InvalidPrincipalException ex) {
            throw new ScimResourceNotFoundException(id);
        } catch (Exception ex) {
            throw new IllegalStateException(String.format("Group '%s' not found in tenant '%s'.", id, VmidentityUtils.getZoneId()), ex);
        }
    }

    @Override
    public ScimGroup create(ScimGroup resource) {
        try {
            logger.debug("creating group dislay name='" + resource.getDisplayName() + "', id='" + resource.getId() + "'.");
            String tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);
            String name = resource.getDisplayName();
            String[] parts = name.split("@");
            if (parts.length > 2) {
                throw new InvalidScimResourceException(String.format("Invalid format for group name '%s'", name));
            } else if (parts.length == 2) {
                if (systemDomain.equalsIgnoreCase(parts[1]) == false) {
                    throw new InvalidScimResourceException("Cannot create groups in external domains.");
                }

                name = parts[0];
            }

            GroupDetail gd = new GroupDetail();
            gd.setDescription(resource.getDescription());
            PrincipalId groupId = this.idmClient.addGroup(tenant, name, gd);
            Group group = this.idmClient.findGroup(tenant, groupId);

            if (group == null) {
                throw new InvalidPrincipalException("Group not found.", groupId.toString());
            }
            return getScimGroup(group, tenant, systemDomain);
        } catch (InvalidPrincipalException ex) {
            logger.error("create group failed...", ex);
            throw new ScimResourceNotFoundException(resource.getDisplayName());
        } catch (Exception ex) {
            logger.error("create group failed...", ex);
            throw new IllegalStateException(String.format("Group '%s' not found in tenant '%s'.", resource.getDisplayName(), VmidentityUtils.getZoneId()), ex);
        }
    }

    @Override
    public ScimGroup update(String id, ScimGroup resource) {
        // TODO impl no op
        return this.retrieve(id);
    }

    @Override
    public ScimGroup delete(String id, int version) {
        try {
            String tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);
            String[] parts = id.split("@");
            PrincipalId groupId = new PrincipalId(parts[0], parts[1]);
            Group group = this.idmClient.findGroup(tenant, groupId);

            if (group == null) {
                throw new InvalidPrincipalException("Group not found.", id);
            }
            ScimGroup sg = getScimGroup(group, tenant, systemDomain);
            this.idmClient.deletePrincipal(tenant, groupId.getName());
            return sg;
        } catch (InvalidPrincipalException ex) {
            logger.error("delete group failed...", ex);
            throw new ScimResourceNotFoundException(id);
        } catch (Exception ex) {
            logger.error("delete group failed...", ex);
            throw new IllegalStateException(
                String.format("Group '%s' not found in tenant '%s'.", id, VmidentityUtils.getZoneId()), ex);
        }
    }

    @Override
    public List<ScimGroup> query(String filter) {
        logger.debug("Querying groups with filter: " + filter);

        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            String systemDomain = VmidentityUtils.getSystemDomain(tenant,  this.idmClient);

            Set<Group> groups = idmClient.findGroupsByScimFilter(tenant, filter);
            ArrayList<ScimGroup> scimGroups = new ArrayList<ScimGroup>(groups.size());
            for (Group group : groups) {
                scimGroups.add(getScimGroup(group, tenant, systemDomain));
            }

            return scimGroups;
        } catch (Exception e) {
            logger.error("Unable to query groups by filter '" + filter + "'", e);
            throw new VmidentityDataAccessException("Unable to query users by filter: " + filter);
        }
    }

    @Override
    public List<ScimGroup> query(String filter, String sortBy, boolean ascending) {
        // todo: sort by ascending
        return this.query(filter);
    }

    @Override
    public int delete(String filter) {
        logger.debug("Filtering groups with query: " + filter);

        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            Set<Group> groups = idmClient.findGroupsByScimFilter(tenant, filter);
            for (Group group : groups) {
                idmClient.deletePrincipal(tenant, group.getId().getUPN());
            }
            return groups.size();
        } catch (Exception e) {
            logger.error("Unable to delete groups by filter '" + filter + "'", e);
            throw new VmidentityDataAccessException("Unable to delete groups by filter: " + filter);
        }
    }

    static ScimGroup getScimGroup(Group idmGroup, String tenant, String systemDomain) {
        String upn = VmidentityUtils.getPrincipalUpn(idmGroup.getId());
        ScimGroup group = new ScimGroup(upn, upn, tenant);
        group.setDescription(idmGroup.getDetail().getDescription());
        ScimMeta meta = new ScimMeta();
        meta.setVersion(1);
        group.setMeta(meta);
        return group;
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public Log getLogger() {
        return logger;
    }
}
