package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecuityConfig {
	
	@Value("${jwt.secretkey}")
	String mykey ;//토큰값 복호화 key 필요-github
	
	@Autowired
	BCryptPasswordEncoder encoder;
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
		System.out.println("==> SecurityConfig 실행중");
		return httpSecurity
				.httpBasic(AbstractHttpConfigurer::disable)
        	    .sessionManagement((sessionManagement) ->
	               sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)//세션사용하지 않겠다(jwt 사용할 것이므로)
	    )
        	    .addFilterBefore(new JwtTokenFilter(mykey, encoder), UsernamePasswordAuthenticationFilter.class)
				.authorizeHttpRequests(
				request-> request
	 		    .requestMatchers("/userinfo").authenticated()
            	//.requestMatchers("/adminpage").hasRole(UserRole.ADMIN.name())
            	//.requestMatchers("/userpage").hasRole(UserRole.USER.name())
            	//.requestMatchers("/userpage").hasRole(UserRole.ADMIN.name())
            	.anyRequest().permitAll()
				)
				.csrf((csrf) -> csrf.disable()) 
				//리액트에서 post방식 요청시 시큐리티는 csrf토큰을 요청헤더에서 찾음. 따라서 disable시켜야 함
				//단, get방식테스트는 disable 상관없이 통과.
				.build();
	}
}








