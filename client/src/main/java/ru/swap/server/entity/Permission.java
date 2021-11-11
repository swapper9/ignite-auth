package ru.swap.server.entity;

import lombok.Data;

import java.io.Serializable;

@Data
public class Permission implements Serializable {
    private Long permissionId;
    private String permissionName;
}
