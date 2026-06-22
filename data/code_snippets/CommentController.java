package com.example.app.controller;

import com.example.app.model.Comment;
import com.example.app.service.CommentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/comments")
public class CommentController {

    @Autowired
    private CommentService commentService;

    @GetMapping
    public String listComments(@RequestParam(required = false, defaultValue = "") String filter,
                                Model model) {
        List<Comment> comments = commentService.findByFilter(filter);
        model.addAttribute("comments", comments);
        // SonarQube java:S5131 — user-supplied 'filter' reflected without encoding
        model.addAttribute("activeFilter", filter);
        return "comments/list";
    }

    @PostMapping("/{id}/reply")
    @ResponseBody
    public String addReply(@PathVariable Long id,
                           @RequestParam String content,
                           @RequestParam String authorName) {
        Comment reply = commentService.createReply(id, content, authorName);
        // SonarQube java:S5131 — line 83
        // Vulnerability: 'content' and 'authorName' written to HTML response without sanitization
        return "<div class='reply'>"
             + "<span class='author'>" + authorName + "</span>"
             + "<p>" + content + "</p>"
             + "</div>";
    }

    @GetMapping("/{id}")
    @ResponseBody
    public Comment getComment(@PathVariable Long id) {
        return commentService.findById(id);
    }
}
