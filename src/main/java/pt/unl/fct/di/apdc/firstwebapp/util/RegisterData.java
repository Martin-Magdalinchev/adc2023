package pt.unl.fct.di.apdc.firstwebapp.util;

public class RegisterData {

    public String username;
    public String name;
    public String password;
    public String email;
    public String typeOfAccount;

    public RegisterData() {
    }

    public RegisterData(String username, String name, String password, String email, String typeOfAccount) {
        this.username = username;
        this.name = name;
        this.password = password;
        this.email = email;
        this.typeOfAccount = typeOfAccount;

    }

    public boolean validRegistration() {
        return username != null && password != null && email != null && name != null && typeOfAccount != null;
    }

}
