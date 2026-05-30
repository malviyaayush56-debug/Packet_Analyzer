package com.dpi.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller // Dhyan dein, yahan sirf @Controller lagana hai, @RestController nahi!
public class ViewController {

    @GetMapping("/dashboard")
    public String showDashboard() {
        // Yeh templates folder ke andar 'dashboard.html' ko dhoondhega
        return "dashboard";
    }
}
