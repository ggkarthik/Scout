package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.security.SensitiveTenantActionInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Value("${app.cors.allowed-origins:http://localhost:5173}")
    private String allowedOrigins;
    private final OperationalMetricsInterceptor operationalMetricsInterceptor;
    private final SensitiveTenantActionInterceptor sensitiveTenantActionInterceptor;

    public WebConfig(
            OperationalMetricsInterceptor operationalMetricsInterceptor,
            SensitiveTenantActionInterceptor sensitiveTenantActionInterceptor
    ) {
        this.operationalMetricsInterceptor = operationalMetricsInterceptor;
        this.sensitiveTenantActionInterceptor = sensitiveTenantActionInterceptor;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins(parseAllowedOrigins())
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true);
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(operationalMetricsInterceptor)
                .addPathPatterns("/api/**");
        registry.addInterceptor(sensitiveTenantActionInterceptor)
                .addPathPatterns("/api/**");
    }

    private String[] parseAllowedOrigins() {
        return java.util.Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isBlank())
                .toArray(String[]::new);
    }
}
