package com.example.security.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService service;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(service.register(request));
    }

    @GetMapping("/activate")
    public ResponseEntity<String> activate(@RequestParam("token") String token) {
        return ResponseEntity.ok(service.activate(token));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PutMapping("/change-name/{user_id}")
    public ResponseEntity<String> changeName(@PathVariable("user_id") Integer userId, @RequestParam("name") String firstName) {
        return ResponseEntity.ok(service.updateName(userId, firstName));
    }
}
