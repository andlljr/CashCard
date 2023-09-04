package example.cashcard;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers("/cashcards/**")
                .hasRole("OWNER")
                .and()
                .csrf().disable()
                .httpBasic();
        return http.build();
    }

    @Bean
    public UserDetailsService testOnlyUser(PasswordEncoder passwordEncoder) {
        User.UserBuilder users = User.builder();

        UserDetails sarah = users.username("sarah1")
                .password(passwordEncoder.encode("abcd123"))
                .roles("OWNER")
                .build();

        UserDetails andre = users.username("and")
                .password(passwordEncoder.encode("abc123"))
                .roles("DEPENDENCY")
                .build();

        UserDetails deleteUser = users.username("deleteMe")
                .password(passwordEncoder.encode("deleting"))
                .roles("OWNER")
                .build();

        UserDetails kumar2 = users.username("kumar2")
                .password(passwordEncoder.encode("teste"))
                .roles("OWNER")
                .build();


        return new InMemoryUserDetailsManager(sarah, andre, deleteUser, kumar2);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}