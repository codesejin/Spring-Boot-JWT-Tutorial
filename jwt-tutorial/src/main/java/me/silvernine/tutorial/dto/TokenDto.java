package me.silvernine.tutorial.dto;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenDto {//토큰 정보를 Response할때 사용

    private String token;
}