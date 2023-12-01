package org.springframework.security.acls.domain;

import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Permission;

public class CumulativePermissionGrantingStrategy extends DefaultPermissionGrantingStrategy {
    /**
     * Creates an instance with the logger which will be used to record granting and
     * denial of requested permissions.
     *
     * @param auditLogger
     */
    public CumulativePermissionGrantingStrategy(AuditLogger auditLogger) {
        super(auditLogger);
    }

    @Override
    protected boolean isGranted(AccessControlEntry ace, Permission p) {
        return (ace.getPermission().getMask() & p.getMask()) == p.getMask();
    }
}
