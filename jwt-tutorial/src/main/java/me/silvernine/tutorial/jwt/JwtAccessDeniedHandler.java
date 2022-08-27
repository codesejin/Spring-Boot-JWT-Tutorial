package me.silvernine.tutorial.jwt;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {
    //포스트맨에서 Get방식의 http://localhost:8080/api/user/silverniner가
    // forbidden된 경우에 작동된 함수
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        //필요한 권한이 없이 접근하려 할때 403
        //SC_FORBIDDEN를 컨트롤 + 클릭해서 타고 들어가서 확인해봐라
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
}