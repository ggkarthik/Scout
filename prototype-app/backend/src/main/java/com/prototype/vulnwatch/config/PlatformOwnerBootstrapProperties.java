package com.prototype.vulnwatch.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.security.bootstrap.platform-owners")
public class PlatformOwnerBootstrapProperties {

    private boolean enabled;
    private List<PlatformOwnerSeed> users = new ArrayList<>();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<PlatformOwnerSeed> getUsers() {
        return users;
    }

    public void setUsers(List<PlatformOwnerSeed> users) {
        this.users = users == null ? new ArrayList<>() : users;
    }

    public static class PlatformOwnerSeed {
        private String externalSubject;
        private String email;
        private String displayName;

        public String getExternalSubject() {
            return externalSubject;
        }

        public void setExternalSubject(String externalSubject) {
            this.externalSubject = externalSubject;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getDisplayName() {
            return displayName;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }
    }
}
