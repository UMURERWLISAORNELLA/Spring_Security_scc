package org.example.security_token.Controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping
    public String publicHello() {
        return "  Anyone can access this!";
    }

    @GetMapping("/user")
    public String userHello() {
        return " You are logged in successfully.";
    }

    @GetMapping("/admin")
    public String adminDashboard() {
        return " Only ADMIN role can see this.";
    }

}
