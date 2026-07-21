package com.prototype.vulnwatch.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.security.playground.memberships")
public class PlaygroundMembershipProperties {
    private boolean enabled;
    private List<String> subjects = new ArrayList<>();
    private String role = "TENANT_ADMIN";

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public List<String> getSubjects() { return subjects; }
    public void setSubjects(List<String> subjects) { this.subjects = subjects == null ? new ArrayList<>() : subjects; }
    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
}
