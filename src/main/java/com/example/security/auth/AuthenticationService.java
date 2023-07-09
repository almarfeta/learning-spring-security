package com.example.security.auth;

import com.example.security.config.JwtService;
import com.example.security.confirmationToken.ConfirmationToken;
import com.example.security.confirmationToken.ConfirmationTokenRepository;
import com.example.security.email.EmailSender;
import com.example.security.exception.BadRequestException;
import com.example.security.token.Token;
import com.example.security.token.TokenRepository;
import com.example.security.token.TokenType;
import com.example.security.user.Role;
import com.example.security.user.User;
import com.example.security.user.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final EmailSender emailSender;

    private void saveUserToken(User savedUser, String jwtToken) {
        var token = Token.builder()
                .user(savedUser)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user) {
        var validUserToken = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserToken.isEmpty()) {
            return;
        }
        validUserToken.forEach(t -> {
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validUserToken);
    }

    public String register(RegisterRequest request) {
        if (repository.findByEmail(request.getEmail()).isPresent()) {
            User user = repository.findByEmail(request.getEmail()).get();
            if (user.isDeleted()) {
                confirmationTokenRepository.delete(user.getConfirmationToken());
                repository.delete(user);
            } else {
                throw new BadRequestException("Email taken");
            }
        }

        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .activated(false)
                .build();
        var savedUser = repository.save(user);

        var activationToken = ConfirmationToken.builder()
                .token(UUID.randomUUID().toString())
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .user(savedUser)
                .build();
        confirmationTokenRepository.save(activationToken);

        String to = user.getEmail();
        String subject = "Account activation";
        String text = "<h3>Please activate your account by clicking the link below:</h3>\n" +
                "<a href=\"http://localhost:8080/api/v1/auth/activate?token=" + activationToken.getToken() + "\">Click here</a>";
        emailSender.send(to, subject, text);
        return "Account created, activation e-mail has been sent";
    }

    @Transactional
    public String activate(String token) {
        ConfirmationToken confirmationToken = confirmationTokenRepository.findByToken(token)
                .orElseThrow(() -> new BadRequestException("Token not found"));

        if (confirmationToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new BadRequestException("Token expired");
        }

        if (confirmationToken.getUser().getActivated()) {
            throw new BadRequestException("Already activated");
        }

        confirmationToken.getUser().setActivated(true);

        return "Account has been activated successfully";
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public String updateName(Integer userId, String firstName) {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof User) {
            Integer loggedInUserId = ((User) principal).getId();
            if (userId.equals(loggedInUserId)) {
                return "It updates";
            }
        }
        return "It doesn't update";
    }
}
