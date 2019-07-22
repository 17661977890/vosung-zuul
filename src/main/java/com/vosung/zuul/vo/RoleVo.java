package com.vosung.zuul.vo;

import lombok.Data;

import java.io.Serializable;

/**
 * 角色值对象
 * @Author 彬
 * @Date 2019/6/4
 */
@Data
public class RoleVo implements Serializable {
    private static final long serialVersionUID = 3460432806215763744L;

    private Integer id;

    private String roleCode;

    private String roleName;

}
