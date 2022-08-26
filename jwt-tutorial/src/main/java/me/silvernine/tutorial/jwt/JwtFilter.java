package me.silvernine.tutorial.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

//jwt를 위한 커스텀 필터를 만들기 위함
//GenericFilterBean을 extends해서
//34번라인 GenericFilterBean의 doFilter를 @Override한다
//실제 필터링 로직은 doFilter내부에 작성
//doFilter의 역할: jwt토큰의 인증정보를 현재 실행중인 Security Context에 저장하는 역할 수행
// JwtFilter는 기존에 만들었던 tokenProvider를 28번 라인 주입받는다
public class JwtFilter extends GenericFilterBean {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    public static final String AUTHORIZATION_HEADER = "Authorization";
    private TokenProvider tokenProvider;
    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        //request의 내용 작성!
        //44번라인 resolveToken을 통해 httpServletRequest에서 토큰을 받아서
        //jwt토큰을 47번라인 토큰의 유효성을 검증하는 validateToken메소드를 통과하고
        //48번라인 토큰이 정상적이면 Authentication authentication 객체를 받아와서
        //49번라인 SecurityContextHolder에 set해준다 setAuthentication
        // 여기까지 한 후 다음 진행 흐름은
        // 여태까지 만든 TokenProvider와 JwtFilter를 SecurityConfig에 적용할때 사용할
        // JwtSecurityConfig 클래스 추가
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        String jwt = resolveToken(httpServletRequest);
        String requestURI = httpServletRequest.getRequestURI();

        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
        } else {
            logger.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    //필터링을 하기 위해 토큰정보가 있어야 하므로 resolveToken메소드 추가
    //61번라인 request의 getHeader에서 토큰정보를 꺼내오는 메소드이다.
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }
}
