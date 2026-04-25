package com.prototype.vulnwatch.client;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeInstancesRequest;
import software.amazon.awssdk.services.ec2.model.Instance;
import software.amazon.awssdk.services.ec2.model.Reservation;
import software.amazon.awssdk.services.ec2.paginators.DescribeInstancesIterable;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityResponse;

/**
 * AWS SDK v2 discovery client scoped to EC2 compute instances.
 */
@Service
public class AwsDiscoveryClient {

    private static final Logger LOG = LoggerFactory.getLogger(AwsDiscoveryClient.class);

    private final ApacheHttpClient.Builder httpClientBuilder;

    public AwsDiscoveryClient() {
        this.httpClientBuilder = ApacheHttpClient.builder()
                .connectionTimeout(Duration.ofMillis(5000))
                .socketTimeout(Duration.ofMillis(30000));
    }

    public List<AwsResourceRecord> fetchEc2Instances(
            AwsCredentialsProvider creds,
            List<String> regions
    ) {
        List<AwsResourceRecord> results = new ArrayList<>();
        for (String region : regions) {
            try (Ec2Client ec2 = Ec2Client.builder()
                    .region(Region.of(region))
                    .credentialsProvider(creds)
                    .httpClientBuilder(httpClientBuilder)
                    .build()) {

                DescribeInstancesIterable pages = ec2.describeInstancesPaginator(
                        DescribeInstancesRequest.builder().maxResults(1000).build());
                for (software.amazon.awssdk.services.ec2.model.DescribeInstancesResponse page : pages) {
                    for (Reservation reservation : page.reservations()) {
                        for (Instance instance : reservation.instances()) {
                            Map<String, String> tags = tagsToMap(instance.tags().stream()
                                    .map(tag -> Map.entry(tag.key(), tag.value()))
                                    .collect(Collectors.toList()));
                            String name = tags.getOrDefault("Name", instance.instanceId());
                            String az = instance.placement() != null ? instance.placement().availabilityZone() : region;
                            String derivedRegion = az != null && az.length() > 1
                                    ? az.substring(0, az.length() - 1)
                                    : region;
                            String arn = String.format("arn:aws:ec2:%s:%s:instance/%s",
                                    region, "", instance.instanceId());
                            results.add(new AwsResourceRecord(
                                    "EC2",
                                    arn,
                                    name,
                                    derivedRegion,
                                    az,
                                    "",
                                    instance.instanceTypeAsString(),
                                    instance.vpcId(),
                                    instance.subnetId(),
                                    instance.platformDetails(),
                                    instance.state() != null ? instance.state().nameAsString() : null,
                                    instance.launchTime(),
                                    tags,
                                    instance.iamInstanceProfile() == null ? null : instance.iamInstanceProfile().arn()
                            ));
                        }
                    }
                }
            } catch (SdkException e) {
                LOG.warn("AWS EC2 discovery failed for region {}: {}", region, e.getMessage());
            }
        }
        return results;
    }

    /** Test connectivity: STS GetCallerIdentity + EC2 DescribeInstances probe in configured regions. */
    public AwsConnectivityResult testConnectivity(AwsCredentialsProvider creds, List<String> regions) {
        try (StsClient sts = StsClient.builder()
                .region(Region.US_EAST_1)
                .credentialsProvider(creds)
                .httpClientBuilder(httpClientBuilder)
                .build()) {

            GetCallerIdentityResponse identity = sts.getCallerIdentity();
            String accountId = identity.account();

            List<String> reachable = new ArrayList<>();
            for (String region : regions) {
                try (Ec2Client ec2 = Ec2Client.builder()
                        .region(Region.of(region))
                        .credentialsProvider(creds)
                        .httpClientBuilder(httpClientBuilder)
                        .build()) {
                    ec2.describeInstances(DescribeInstancesRequest.builder().maxResults(5).build());
                    reachable.add(region);
                } catch (SdkException e) {
                    LOG.debug("Region {} not reachable: {}", region, e.getMessage());
                }
            }
            return new AwsConnectivityResult(true, accountId, reachable, null);
        } catch (SdkException e) {
            return new AwsConnectivityResult(false, null, Collections.emptyList(), e.getMessage());
        }
    }

    private Map<String, String> tagsToMap(List<Map.Entry<String, String>> entries) {
        return entries.stream().collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (a, b) -> a));
    }

    public record AwsResourceRecord(
            String resourceType,
            String arn,
            String name,
            String region,
            String availabilityZone,
            String accountId,
            String instanceType,
            String vpcId,
            String subnetId,
            String platformVersion,
            String state,
            Instant launchTime,
            Map<String, String> tags,
            String iamInstanceProfileArn
    ) {}

    public record AwsConnectivityResult(
            boolean success,
            String accountId,
            List<String> reachableRegions,
            String errorMessage
    ) {}
}
