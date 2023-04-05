package pt.unl.fct.di.apdc.firstwebapp.util;

public class RegisterData {

	public String username;
	public String name;
	public String password;
	public String email;
	
	public RegisterData() {}
	
	public RegisterData(String username, String name, String password, String email) {
		this.username = username;
		this.name = name;
		this.password = password;
		this.email = email;
	}

	public boolean validRegistration() {
		// TODO Auto-generated method stub
		
		return username != null && password != null && email != null && name != null;
	}

}
