package pt.unl.fct.di.apdc.firstwebapp.util;

public class AdditionalDataForOthers {

    public String username;
    public String password;
    public String name;
    public String email;
    public String typeOfAccount;
    public String phone;
    public String mobilePhone;
    public String occupation;
    public String workPlace;
    public String address;
    public String nif;

    public AdditionalDataForOthers() {
    }

    public AdditionalDataForOthers(String username, String password, String name, String email, String typeOfAccount, String phone, String mobilePhone,
                           String occupation, String workPlace, String address, String nif) {

        this.username = username;
        this.password = password;
        this.name = name;
        this.email = email;
        this.typeOfAccount = typeOfAccount;
        this.phone = phone;
        this.mobilePhone = mobilePhone;
        this.occupation = occupation;
        this.workPlace = workPlace;
        this.address = address;
        this.nif = nif;
    }
}
