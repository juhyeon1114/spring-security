package security.springsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    AuthenticationManager authenticationManager;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        /**
         * 테스트용 사용자 생성
         */
        AuthenticationManagerBuilder auth = http.getSharedObject(AuthenticationManagerBuilder.class);
//        auth.userDetailsService(userDetailsService);
        auth.inMemoryAuthentication().withUser("user").password("{noop}1234").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1234").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1234").roles("ADMIN", "SYS");
        authenticationManager = auth.build();

        http.authenticationManager(authenticationManager);

        /**
         * 인가, 권한 설정
         */
//        http.securityMatcher("/shop/**"); // 인가 받아야 접근할 수 있는 경로
//
//        http.authorizeHttpRequests()
//                .requestMatchers("/shop/login", "/shop/users/**").permitAll()
//                .requestMatchers("/shop/mypage").hasRole("USER")
////                .requestMatchers("/shop/admin/pay").access("hasRole('ADMIN')")
//                .anyRequest()
//                .authenticated();

        http.authorizeHttpRequests()
                .requestMatchers("/login").permitAll()
                .requestMatchers("/user").hasRole("USER")
                .requestMatchers("/admin/pay").hasRole("ADMIN")
                .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")
                .anyRequest().authenticated();

        /**
         * Login
         */
        http.formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);
                    }
                });
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                .permitAll();

        /**
         * Logout
         */
//        http.logout()
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
//                .deleteCookies("remember-me")
//                .and()
//                .rememberMe()
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService);

        /**
         * 세션
         */
//        http.sessionManagement()
////                .sessionFixation().changeSessionId() // default. 로그인할 때 마다 새로운 세션이 생성됨.
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(true) // default: false. true == 동시로그인 차단. false == 기존 세션 만료
//                .expiredUrl("/expired");


        http.exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                });

        /**
         * CSRF
         */

//        http.csrf(); // default가 활성화임

        return http.build();
    }

}
