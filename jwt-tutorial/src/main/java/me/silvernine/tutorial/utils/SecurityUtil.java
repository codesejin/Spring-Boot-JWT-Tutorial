package me.silvernine.tutorial.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public class SecurityUtil {//간단한 유틸리티 메소드를 만듬(getCurrentUsername메소드를 가진 클래스)

    private static final Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

    private SecurityUtil() {}


    //getCurrentUsername메소드의 역할 : SecurityContextHolder에서 getAuthentication()객체를 꺼내와서
    //25번 라인 authentication객체를 통해서 32~40번 라인 username을 리턴해주는 간단한 유틸성 메소드
    public static Optional<String> getCurrentUsername() {
        //25번 라인 SecurityContextHolder에 Authentication객체가 저장되는 시점은
        //이전에 만들었던 jwtFilter의 doFilter메소드에서 Request가 들어오는 시점에
        //SecurityContextHolder에 setAuthentication()으로 Authentication객체가 저장되어 사용된다
        //거기서 저장된 객체가 25번라인 getAuthentication()에서 꺼내져 사용하게 됨
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            logger.debug("Security Context에 인증 정보가 없습니다.");
            return Optional.empty();
        }

        String username = null;
        if (authentication.getPrincipal() instanceof UserDetails) {
            UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
            username = springSecurityUser.getUsername();
        } else if (authentication.getPrincipal() instanceof String) {
            username = (String) authentication.getPrincipal();
        }

        return Optional.ofNullable(username);
    }
}