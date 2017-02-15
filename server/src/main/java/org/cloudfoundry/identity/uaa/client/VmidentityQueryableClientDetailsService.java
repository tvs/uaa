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
package org.cloudfoundry.identity.uaa.client;

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.resources.Queryable;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.zone.MultitenantVmidentityClientDetailsService;
import org.springframework.security.oauth2.provider.ClientDetails;

public class VmidentityQueryableClientDetailsService implements Queryable<ClientDetails>,
                QueryableResourceManager<ClientDetails> {

    private static final Log logger = LogFactory.getLog(VmidentityQueryableClientDetailsService.class);

    private MultitenantVmidentityClientDetailsService delegate;

    protected VmidentityQueryableClientDetailsService(MultitenantVmidentityClientDetailsService delegate) {
        this.delegate = delegate;
    }

    @Override
    public List<ClientDetails> query(String filter, String sortBy, boolean ascending) {
        logger.debug("query filtering not yet implemented");
        return delegate.listClientDetails();
    }

    @Override
    public List<ClientDetails> retrieveAll() {
        return delegate.listClientDetails();
    }

    @Override
    public ClientDetails retrieve(String id) {
        return delegate.loadClientByClientId(id);
    }

    @Override
    public ClientDetails create(ClientDetails resource) {
        delegate.addClientDetails(resource);
        return delegate.loadClientByClientId(resource.getClientId());
    }

    @Override
    public ClientDetails update(String id, ClientDetails resource) {
        delegate.updateClientDetails(resource);
        return delegate.loadClientByClientId(id);
    }

    @Override
    public ClientDetails delete(String id, int version) {
        ClientDetails client = delegate.loadClientByClientId(id);
        delegate.removeClientDetails(id);
        return client;
    }

    @Override
    public List<ClientDetails> query(String filter) {
        return query(filter, null, true);
    }

    @Override
    public int delete(String filter) {
        logger.debug("Delete-by-filter not yet implemented");
        return 0;
    }

}
