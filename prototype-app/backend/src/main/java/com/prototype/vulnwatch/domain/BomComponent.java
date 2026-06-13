package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(
        name = "bom_components",
        indexes = {
                @Index(name = "idx_bom_comp_bom_id", columnList = "bom_id"),
                @Index(name = "idx_bom_comp_tenant", columnList = "tenant_id"),
                @Index(name = "idx_bom_comp_active", columnList = "bom_id,is_active")
        }
)
public class BomComponent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "bom_id", nullable = false)
    private UUID bomId;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(nullable = false)
    private String name;

    private String version;
    private String purl;
    private String cpe;
    private String license;
    private String supplier;

    @Column(name = "component_type", length = 40)
    private String componentType;

    @Column(name = "bom_ref")
    private String bomRef;

    @Column(name = "group_name")
    private String groupName;

    @Column(name = "scope")
    private String scope;

    @Column(name = "swid")
    private String swid;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "hashes", columnDefinition = "jsonb")
    private String hashes;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "properties", columnDefinition = "jsonb")
    private String properties;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "external_references", columnDefinition = "jsonb")
    private String externalReferences;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private BomComponentCategory category = BomComponentCategory.UNMATCHED;

    @Enumerated(EnumType.STRING)
    @Column(name = "workflow_status", nullable = false, length = 40)
    private BomWorkflowStatus workflowStatus = BomWorkflowStatus.DISCOVERED;

    @Column(name = "is_active", nullable = false)
    private boolean active = true;

    public UUID getId() { return id; }

    public UUID getBomId() { return bomId; }
    public void setBomId(UUID bomId) { this.bomId = bomId; }

    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public String getPurl() { return purl; }
    public void setPurl(String purl) { this.purl = purl; }

    public String getCpe() { return cpe; }
    public void setCpe(String cpe) { this.cpe = cpe; }

    public String getLicense() { return license; }
    public void setLicense(String license) { this.license = license; }

    public String getSupplier() { return supplier; }
    public void setSupplier(String supplier) { this.supplier = supplier; }

    public String getComponentType() { return componentType; }
    public void setComponentType(String componentType) { this.componentType = componentType; }

    public String getBomRef() { return bomRef; }
    public void setBomRef(String bomRef) { this.bomRef = bomRef; }

    public String getGroupName() { return groupName; }
    public void setGroupName(String groupName) { this.groupName = groupName; }

    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }

    public String getSwid() { return swid; }
    public void setSwid(String swid) { this.swid = swid; }

    public String getHashes() { return hashes; }
    public void setHashes(String hashes) { this.hashes = hashes; }

    public String getProperties() { return properties; }
    public void setProperties(String properties) { this.properties = properties; }

    public String getExternalReferences() { return externalReferences; }
    public void setExternalReferences(String externalReferences) { this.externalReferences = externalReferences; }

    public BomComponentCategory getCategory() { return category; }
    public void setCategory(BomComponentCategory category) { this.category = category; }

    public BomWorkflowStatus getWorkflowStatus() { return workflowStatus; }
    public void setWorkflowStatus(BomWorkflowStatus workflowStatus) { this.workflowStatus = workflowStatus; }

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }

}
