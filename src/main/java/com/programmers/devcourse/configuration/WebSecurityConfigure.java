package com.programmers.devcourse.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers("/assets/**");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/me").hasAnyRole("USER", "ADMIN")
				.anyRequest().permitAll()
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
				.tokenValiditySeconds(30); //AbstractAuthenticationProcessingFilter
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.inMemoryAuthentication()
			.withUser("hyeb").password("{noop}hyeb123").roles("USER")
			.and()
			.withUser("admin").password("{noop}admin123").roles("ADMIN");

	}
}