package io.mosip.kernel.tokenidgenerator.dto;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;


@Component("authorizedRoles")
@ConfigurationProperties(prefix = "mosip.role.keymanager")
@Getter
@Setter
public class AuthorizedRolesDTO {

	##tokenidgenerator controller
	
	private List<String> getuinpartnercode;
	

}
}