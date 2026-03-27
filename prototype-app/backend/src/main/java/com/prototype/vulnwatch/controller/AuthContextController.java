package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.AuthContextResponse;
import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class AuthContextController {

    private final RequestActorService requestActorService;

    public AuthContextController(RequestActorService requestActorService) {
        this.requestActorService = requestActorService;
    }

    @GetMapping({"/auth/context", "/me"})
    public AuthContextResponse get() {
        RequestActor actor = requestActorService.currentActor();
        return new AuthContextResponse(
                actor.creator(),
                actor.userId(),
                actor.userId(),
                actor.tenantId() == null ? null : actor.tenantId().toString(),
                actor.tenantName()
        );
    }
}
