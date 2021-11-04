package ru.swap.server.security.permissions;

import lombok.Data;

import java.util.List;

@Data
public class SubjectList {
    private List<Subject> subjects;
}
