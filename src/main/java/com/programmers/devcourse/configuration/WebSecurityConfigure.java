package com.programmers.devcourse.configuration;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

	private final Logger logger = LoggerFactory.getLogger(WebSecurityConfigure.class);

	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers("/assets/**");
	}

	@Bean
	public AccessDecisionManager accessDecisionManager() {
		List<AccessDecisionVoter<?>> voters = new ArrayList<>();
		voters.add(new WebExpressionVoter());
		voters.add(new OddAdminVoter(new AntPathRequestMatcher("/admin")));

		return new UnanimousBased(voters);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.antMatchers("/me").hasAnyRole("USER", "ADMIN")
			.antMatchers("/admin").access("hasRole('Admin') and isFullyAuthenticated()")
			.anyRequest().permitAll()
			.accessDecisionManager(accessDecisionManager())
			.and()
			.formLogin()
			.defaultSuccessUrl("/")
			.permitAll()
			.and()
			.logout()
			.logoutRequestMatcher(new AntPathRequestMatcher("/logout")) // default
			.logoutSuccessUrl("/")
			.invalidateHttpSession(true) //dafault
			.clearAuthentication(true) // default
			.and()
			.rememberMe()
			.rememberMeParameter("remember-me")
			.tokenValiditySeconds(30) //AbstractAuthenticationProcessingFilter
			.and()
			.requiresChannel()
			.anyRequest().requiresSecure()
			.and()
			.sessionManagement()
			.sessionFixation().changeSessionId()
			.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
			.invalidSessionUrl("/")
			.maximumSessions(1)
			.maxSessionsPreventsLogin(false)
			.and()
			// .anonymous()
			// 	.principal("thisIsAnonymousUser")
			// 	.authorities("ROLE_ANONYMOUS", "ROLE_UNKNOWN")
			// 	.and()
			.and()
			.exceptionHandling()
			.accessDeniedHandler(accessDeniedHandler());
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.inMemoryAuthentication()
			.withUser("hyeb").password("{noop}hyeb123").roles("USER")
			.and()
			.withUser("admin01").password("{noop}admin123").roles("ADMIN")
			.and()
			.withUser("admin02").password("{noop}admin123").roles("ADMIN");
	}

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		return ((request, response, accessDeniedException) -> {
			var authentication = SecurityContextHolder.getContext().getAuthentication();
			var principal = authentication != null ? authentication.getPrincipal() : null;
			logger.warn("{} is denied", principal, accessDeniedException);
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.setContentType("text/plain");
			response.getWriter().write("## ACCESS DENIED ##");
			response.getWriter().flush();
			response.getWriter().close();

		});
	}
}