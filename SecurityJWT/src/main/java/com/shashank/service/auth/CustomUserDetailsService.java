package com.shashank.service.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.shashank.Repository.UserRepository;
import com.shashank.model.User;

import lombok.extern.slf4j.Slf4j;

@Component("customUserDetailsService")
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private UserRepository userDao;

	@Transactional(readOnly = true, propagation = Propagation.REQUIRES_NEW)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		log.info(
				"############ Inside CustomUserDetailsService#loadUserByUsername method ########");

		log.info("Username {}", username);
		
		User user = userDao.findByUsername(username);
		
		if (user == null) {
			throw new UsernameNotFoundException("No user found with username: " + username);
		}
		
		return org.springframework.security.core.userdetails.User.builder().username(user.getUsername())
				.password(user.getPassword()).roles(user.getRole()).build();
	}
}
