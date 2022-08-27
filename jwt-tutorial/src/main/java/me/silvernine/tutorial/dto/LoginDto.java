package me.silvernine.tutorial.dto;


import lombok.*;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginDto { //외부와의 통신에서 사용할 Dto

    @NotNull
    @Size(min = 3, max = 50)//validation관련 어노테이션
    private String username;

    @NotNull
    @Size(min = 3, max = 100)
    private String password;
}
