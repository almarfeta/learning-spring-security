package com.example.security.demo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/v1/manager-controller")
@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
public class ManagerController {

    @GetMapping
    @PreAuthorize("hasAnyAuthority('admin:read', 'manager:read')")
    public String get() {
        return "GET:: manager controller";
    }
    @PostMapping
    @PreAuthorize("hasAnyAuthority('admin:create', 'manager:create')")
    public String post() {
        return "POST:: manager controller";
    }
    @PutMapping
    @PreAuthorize("hasAnyAuthority('admin:update', 'manager:update')")
    public String put() {
        return "PUT:: manager controller";
    }
    @DeleteMapping
    @PreAuthorize("hasAnyAuthority('admin:delete', 'manager:delete')")
    public String delete() {
        return "DELETE:: manager controller";
    }
}
