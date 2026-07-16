package com.prototype.vulnwatch.migration;

/** Compatibility entry point. ProductionBootstrapCli owns all bootstrap phases. */
public final class TenantSchemaMigrationCli {

    private TenantSchemaMigrationCli() {
    }

    public static void main(String[] args) throws Exception {
        ProductionBootstrapCli.main(args);
    }
}
