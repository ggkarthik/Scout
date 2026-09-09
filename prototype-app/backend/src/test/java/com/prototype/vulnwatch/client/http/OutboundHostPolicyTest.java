package com.prototype.vulnwatch.client.http;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.InetAddress;
import java.net.URI;
import java.util.Map;
import org.junit.jupiter.api.Test;

class OutboundHostPolicyTest {

    @Test
    void acceptsOnlyApprovedHttpsHostAndPort() {
        OutboundHostPolicy policy = policyFor(Map.of("approved.example", new InetAddress[]{address("93.184.216.34")}));

        assertDoesNotThrow(() -> policy.validate("provider", URI.create("https://approved.example/resource")));
        assertThrows(IllegalArgumentException.class,
                () -> policy.validate("provider", URI.create("http://approved.example/resource")));
        assertThrows(IllegalArgumentException.class,
                () -> policy.validate("provider", URI.create("https://approved.example:8443/resource")));
        assertThrows(IllegalArgumentException.class,
                () -> policy.validate("provider", URI.create("https://other.example/resource")));
    }

    @Test
    void rejectsPrivateAddressReturnedByDns() {
        OutboundHostPolicy policy = policyFor(Map.of("approved.example", new InetAddress[]{address("127.0.0.1")}));

        assertThrows(IllegalArgumentException.class,
                () -> policy.validate("provider", URI.create("https://approved.example/resource")));
    }

    @Test
    void rejectsAnyBlockedAddressInMixedDnsAnswer() {
        OutboundHostPolicy policy = policyFor(Map.of(
                "approved.example", new InetAddress[]{address("93.184.216.34"), address("169.254.169.254")}));

        assertThrows(IllegalArgumentException.class,
                () -> policy.validate("provider", URI.create("https://approved.example/resource")));
    }

    @Test
    void rejectsIpLiteralsEvenWhenTheyArePublic() {
        OutboundHostPolicy policy = policyFor(Map.of());

        assertThrows(IllegalArgumentException.class,
                () -> policy.validate("provider", URI.create("https://93.184.216.34/resource")));
    }

    private OutboundHostPolicy policyFor(Map<String, InetAddress[]> answers) {
        return new OutboundHostPolicy("provider=approved.example", host -> answers.getOrDefault(host, new InetAddress[0]));
    }

    private InetAddress address(String value) {
        try {
            return InetAddress.getByName(value);
        } catch (java.net.UnknownHostException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
