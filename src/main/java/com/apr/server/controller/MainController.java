package com.apr.server.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;

@Controller
public class MainController {

    @RequestMapping({"/", "/index"})
    public String home() {
        return "index";
    }

    @RequestMapping({"/hello"})
    public String hello(Model model, HttpServletRequest request)
    {
        return "hello";
    }

    @GetMapping(value = "/login")
    public String login(Model model, String error, String logout) {
        if (error != null)
            model.addAttribute("error", "Your username and password is invalid.");

        if (logout != null)
            model.addAttribute("message", "You have been logged out successfully.");

        return "login";
    }

    @PreAuthorize("hasAuthority('ADMIN')")
    @RequestMapping({"/client"})
    public String user() {
        return "clients/client";
    }

    @GetMapping("/access-denied")
    public String accessDenied() {
        return "error/access-denied";
    }

}
