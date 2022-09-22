
package com.example.test.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.annotation.Resource;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.io.PrintWriter;

//@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    DataSource dataSource;
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        //在这里定制请求的授权规则

        //首页所有可以访问,其他页面的定制请求与授权
        httpSecurity.authorizeRequests().antMatchers("/**","/role/acc/**","/role/**").permitAll()
        .antMatchers("/role/**").hasAnyRole()
        .antMatchers("/main/**").hasRole("2");
        //登陆界面.loginPage("/login.html")
        //action现需要和loginProcessingUrl(）中的参数一致 .loginProcessingUrl("/user/login")
        httpSecurity.formLogin()
                .loginPage("/role/login")
                .loginProcessingUrl("/role/login/login_role")

                .usernameParameter("acc")
                .passwordParameter("password")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication auth) throws IOException, ServletException {
                        response.setContentType("application/json;charst=utf-8");
                        response.sendRedirect("main/home");
                        PrintWriter out = response.getWriter();
                        out.write("success");
                        out.flush();
                    }
                })
                .permitAll()//.and().logout().logoutUrl()
                .failureUrl("/error/500")
                .successForwardUrl("/main/");
        //httpSecurity.csrf().disable();
        //定制记住我的参数！
        httpSecurity.rememberMe().rememberMeParameter("remember").
                //     .tokenRepository(persistentTokenRepository())
                tokenValiditySeconds(60);
        //注销成功来到首页   删除cookie  清空session  退出后回到/
        httpSecurity.logout().deleteCookies("remove").invalidateHttpSession(true).logoutSuccessUrl("/");


    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //自定义认证规则
        auth.jdbcAuthentication().dataSource(dataSource)

                .usersByUsernameQuery("select rolePhone,role_Pwd,'true' as enabled from role WHERE rolePhone=?")
                .authoritiesByUsernameQuery("select roleAuth ,rolePhone from role where rolePhone=?")
                .passwordEncoder(new BCryptPasswordEncoder());

        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("admin_sdgs").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2","vip3","2");
   auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("plushuang").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2","vip3")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");

    }
}

